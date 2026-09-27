import { type Kysely, sql } from 'kysely';
import type { TenancyLogger } from '../logging.js';

/**
 * Migration 001 — rôles PostgreSQL.
 *
 * Trois rôles, chacun pour une raison mesurée en phase 0 :
 *
 *   app_runtime    rôle applicatif. NI propriétaire, NI BYPASSRLS — sans quoi
 *                  il contourne la RLS (mesuré : 2/2 lignes visibles alors
 *                  que la policy existait)
 *   app_policy     porte app_a_permission(). Une SECURITY DEFINER détenue par
 *                  le propriétaire des tables reste soumise à FORCE RLS et rend
 *                  TOUJOURS false — d'où un rôle BYPASSRLS, NOLOGIN,
 *                  propriétaire d'aucune table
 *   app_auth       schéma d'authentification, cloisonné de public
 *
 * PROPRIÉTAIRE DES OBJETS : le rôle d'administration qui exécute la migration
 * (`DB_ADMIN_USER`). Un `app_migration` était créé ici avec un mot de passe et
 * `CREATE` sur `public`, sans jamais posséder ni appliquer quoi que ce soit
 * (MESURÉ, L1-10 : 0 objet). Il n'est plus créé ; ses droits sont retirés par
 * la migration 006.
 *
 * MOTS DE PASSE : les rôles sont GLOBAUX AU CLUSTER. Réécrire le mot de passe
 * d'un rôle existant casse toute autre base du serveur qui l'utilise — les
 * suites de tests le faisaient à chaque exécution. Un rôle existant garde donc
 * son mot de passe, sauf option explicite (`realignerMotsDePasse`,
 * `DB_REALIGNER_MOTS_DE_PASSE=1` côté application).
 *
 * DÉCOUVERT À L'EXÉCUTION : les paramètres liés ne traversent PAS un bloc
 * `DO $$` — PostgreSQL le reçoit comme une chaîne littérale et refuse les
 * paramètres. D'où la vérification d'existence côté applicatif, qui permet
 * en prime de journaliser chaque création.
 */

export interface RoleCredentials {
  runtime: string;
  auth: string;
}

export interface OptionsRoles {
  /** Réécrit le mot de passe des rôles EXISTANTS. Faux par défaut. */
  realignerMotsDePasse?: boolean;
  logger?: TenancyLogger;
}

/**
 * Refuse un mot de passe qui casserait le littéral SQL.
 *
 * Exportée pour être testable directement, sans toucher aux rôles du cluster.
 */
export function assertSafePassword(role: string, password: string): void {
  if (!password || password.length < 8) {
    throw new Error(
      `Mot de passe du rôle « ${role} » trop court (minimum 8 caractères). ` +
        `Fournissez-le via la configuration, jamais en dur dans le code.`,
    );
  }
  if (password.includes("'") || password.includes('\\')) {
    throw new Error(
      `Le mot de passe du rôle « ${role} » contient une apostrophe ou un ` +
        `antislash, qui ne peuvent pas être échappés de façon sûre dans un ` +
        `CREATE ROLE. Choisissez un autre mot de passe.`,
    );
  }
}

/** Attributs de rôle vérifiables dans `pg_roles`, par mot-clé de CREATE ROLE. */
const ATTRIBUTS: Record<string, [colonne: string, valeur: boolean]> = {
  login: ['rolcanlogin', true],
  nologin: ['rolcanlogin', false],
  bypassrls: ['rolbypassrls', true],
  nobypassrls: ['rolbypassrls', false],
  nosuperuser: ['rolsuper', false],
  nocreatedb: ['rolcreatedb', false],
  nocreaterole: ['rolcreaterole', false],
};

export interface RoleVoulu {
  name: string;
  /** Absent : rôle NOLOGIN, sans mot de passe. */
  password?: string;
  /** Mots-clés de CREATE ROLE, séparés par des espaces (voir `ATTRIBUTS`). */
  options: string;
}

/** Les courses entre deux bases du même cluster, sans conséquence : même état visé. */
const COURSE = /concurrently updated|already exists|duplicate key/;

/**
 * Crée le rôle s'il manque ; sinon réaligne SES ATTRIBUTS s'ils divergent, et
 * son mot de passe SEULEMENT sur option.
 *
 * `ALTER ROLE` n'est émis que si l'état diffère : un réalignement inconditionnel
 * produisait `tuple concurrently updated` entre deux bases migrées ensemble —
 * le verrou consultatif n'y peut rien, il est propre à UNE base.
 */
export async function assurerRole(
  db: Kysely<any>,
  r: RoleVoulu,
  o: OptionsRoles = {},
): Promise<void> {
  if (r.password !== undefined) assertSafePassword(r.name, r.password);
  // Les identifiants et mots de passe ne peuvent pas être des paramètres liés
  // dans un CREATE ROLE : on interpole après validation stricte.
  const pwd = r.password !== undefined ? ` password '${r.password}'` : '';

  const actuel = await sql<Record<string, boolean>>`
    select rolcanlogin, rolbypassrls, rolsuper, rolcreatedb, rolcreaterole
    from pg_roles where rolname = ${r.name}
  `.execute(db);
  const ligne = actuel.rows[0] as Record<string, boolean> | undefined;

  try {
    if (!ligne) {
      await sql.raw(`create role ${r.name} ${r.options}${pwd}`).execute(db);
      o.logger?.log(`Rôle « ${r.name} » créé`);
      return;
    }
    const divergent = r.options
      .split(/\s+/)
      .filter(Boolean)
      .some((mot) => {
        const attendu = ATTRIBUTS[mot.toLowerCase()] as [string, boolean] | undefined;
        return attendu !== undefined && ligne[attendu[0]] !== attendu[1];
      });
    if (divergent) {
      await sql.raw(`alter role ${r.name} ${r.options}`).execute(db);
      o.logger?.warn(`Rôle « ${r.name} » : attributs réalignés (${r.options})`);
    }
    if (o.realignerMotsDePasse && pwd) {
      await sql.raw(`alter role ${r.name}${pwd}`).execute(db);
      o.logger?.warn(
        `Rôle « ${r.name} » : mot de passe RÉÉCRIT (option explicite). Il vaut pour ` +
          `TOUTES les bases du cluster.`,
      );
    } else {
      o.logger?.debug(`Rôle « ${r.name} » déjà présent — mot de passe conservé`);
    }
  } catch (e) {
    if (!COURSE.test((e as Error).message)) throw e;
    o.logger?.debug(
      `Rôle « ${r.name} » modifié en parallèle par une autre migration — ` +
        `état visé identique, sans conséquence`,
    );
  }
}

/**
 * Identifiant du verrou consultatif protégeant la création des rôles.
 *
 * Verrou de SESSION, sur UNE connexion : `pg_advisory_xact_lock` hors
 * transaction se libère à la fin de l'instruction, donc ne protégeait rien.
 */
const ROLE_LOCK_ID = 847_100_001;

export async function up(
  db: Kysely<any>,
  credentials: RoleCredentials,
  logger?: TenancyLogger,
  options: Omit<OptionsRoles, 'logger'> = {},
): Promise<void> {
  const plan: RoleVoulu[] = [
    {
      name: 'app_runtime',
      password: credentials.runtime,
      options: 'login nobypassrls nosuperuser nocreatedb nocreaterole',
    },
    {
      name: 'app_auth',
      password: credentials.auth,
      options: 'login nobypassrls nosuperuser',
    },
    { name: 'app_policy', options: 'nologin bypassrls' },
  ];
  // Valider AVANT toute écriture : un mot de passe refusé ne laisse rien derrière.
  for (const r of plan)
    if (r.password !== undefined) assertSafePassword(r.name, r.password);

  await db.connection().execute(async (conn) => {
    await sql`select pg_advisory_lock(${ROLE_LOCK_ID})`.execute(conn);
    try {
      for (const r of plan) await assurerRole(conn, r, { ...options, logger });
    } finally {
      await sql`select pg_advisory_unlock(${ROLE_LOCK_ID})`.execute(conn);
    }
  });

  // PostgreSQL 15+ a retiré CREATE au rôle PUBLIC sur le schéma public : le
  // propriétaire des tables est le rôle d'administration, qui l'a déjà.
  await sql`grant usage on schema public to app_runtime, app_policy`.execute(db);
}

export async function down(db: Kysely<any>, logger?: TenancyLogger): Promise<void> {
  // Les rôles ne sont PAS supprimés : ils peuvent porter d'autres objets, et
  // une suppression échouerait ou casserait autre chose. On retire les
  // privilèges accordés par cette migration.
  for (const role of ['app_runtime', 'app_policy']) {
    const existe = await sql<{
      n: number;
    }>`select count(*)::int as n from pg_roles where rolname = ${role}`.execute(db);
    if (existe.rows[0].n > 0) {
      await sql.raw(`revoke all on schema public from ${role}`).execute(db);
    }
  }
  logger?.warn(
    `Privilèges retirés, mais les rôles app_* sont CONSERVÉS : ils peuvent ` +
      `porter d'autres objets. Supprimez-les à la main si nécessaire ` +
      `(DROP OWNED BY <role>; DROP ROLE <role>;).`,
  );
}
