import { type Kysely, sql } from 'kysely';
import type { TenancyLogger } from '../logging.js';

/**
 * Migration 001 — rôles PostgreSQL.
 *
 * Quatre rôles, chacun pour une raison mesurée en phase 0 :
 *
 *   app_migration  propriétaire des tables, applique les migrations
 *   app_runtime    rôle applicatif. NI propriétaire, NI BYPASSRLS — sans quoi
 *                  il contourne la RLS (mesuré : 2/2 lignes visibles alors
 *                  que la policy existait)
 *   app_policy     porte app_a_permission(). Une SECURITY DEFINER détenue par
 *                  app_migration reste soumise à FORCE RLS et rend TOUJOURS
 *                  false — d'où un rôle BYPASSRLS, NOLOGIN, propriétaire
 *                  d'aucune table
 *   app_auth       schéma d'authentification, cloisonné de public
 *
 * DÉCOUVERT À L'EXÉCUTION : les paramètres liés ne traversent PAS un bloc
 * `DO $$` — PostgreSQL le reçoit comme une chaîne littérale et refuse les
 * paramètres. D'où la vérification d'existence côté applicatif, qui permet
 * en prime de journaliser chaque création.
 */

export interface RoleCredentials {
  migration: string;
  runtime: string;
  auth: string;
}

/** Refuse un mot de passe qui casserait le littéral SQL. */
function assertSafePassword(role: string, password: string): void {
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

async function roleExists(db: Kysely<any>, name: string): Promise<boolean> {
  const r = await sql<{ n: number }>`
    select count(*)::int as n from pg_roles where rolname = ${name}
  `.execute(db);
  return r.rows[0].n > 0;
}

export async function up(
  db: Kysely<any>,
  credentials: RoleCredentials,
  logger?: TenancyLogger,
): Promise<void> {
  const plan: Array<{ name: string; password?: string; options: string }> = [
    { name: 'app_migration', password: credentials.migration, options: 'login' },
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

  for (const r of plan) {
    if (r.password !== undefined) assertSafePassword(r.name, r.password);

    if (await roleExists(db, r.name)) {
      logger?.debug(`Rôle « ${r.name} » déjà présent`);
      continue;
    }
    // Les identifiants et mots de passe ne peuvent pas être des paramètres
    // liés dans un CREATE ROLE : on interpole après validation stricte.
    const pwd = r.password !== undefined ? ` password '${r.password}'` : '';
    await sql.raw(`create role ${r.name} ${r.options}${pwd}`).execute(db);
    logger?.log(`Rôle « ${r.name} » créé`);
  }

  // PostgreSQL 15+ a retiré CREATE au rôle PUBLIC sur le schéma public.
  // Sans ce GRANT, la première table échoue sur
  // « permission denied for schema public » (mesuré phase 0).
  await sql`grant usage on schema public to app_runtime, app_migration, app_policy`
    .execute(db);
  await sql`grant create on schema public to app_migration`.execute(db);
  await sql`
    alter default privileges for role app_migration in schema public
    grant select, insert, update, delete on tables to app_runtime
  `.execute(db);
}

export async function down(db: Kysely<any>, logger?: TenancyLogger): Promise<void> {
  // Les rôles ne sont PAS supprimés : ils peuvent porter d'autres objets, et
  // une suppression échouerait ou casserait autre chose. On retire les
  // privilèges accordés par cette migration.
  for (const role of ['app_runtime', 'app_policy', 'app_migration']) {
    if (await roleExists(db, role)) {
      await sql.raw(`revoke all on schema public from ${role}`).execute(db);
    }
  }
  logger?.warn(
    `Privilèges retirés, mais les rôles app_* sont CONSERVÉS : ils peuvent ` +
      `porter d'autres objets. Supprimez-les à la main si nécessaire ` +
      `(DROP OWNED BY <role>; DROP ROLE <role>;).`,
  );
}
