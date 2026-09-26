import { type Kysely, sql } from 'kysely';
import { MSG, type TenancyLogger } from '../logging.js';

/**
 * Harnais de migration : désactiver FORCE RLS, faire le travail, le rétablir.
 *
 * MESURÉ (sonde T3.1, PostgreSQL 17) :
 *
 *   A. Un INSERT bloqué par RLS LÈVE une exception
 *      (`new row violates row-level security policy`) — contrairement à
 *      SELECT/UPDATE, qui rendent 0 ligne en silence. L'échec est donc
 *      bruyant pour les insertions.
 *
 *   C. En transaction, un échec rétablit FORCE automatiquement : le ROLLBACK
 *      annule aussi le ALTER TABLE.
 *
 *   D. HORS transaction, FORCE reste DÉSACTIVÉ après un échec. La table est
 *      exposée à son propriétaire jusqu'au prochain ALTER, sans aucun signal.
 *
 * D'où la règle imposée ici : **toujours en transaction**. Ce n'est pas une
 * bonne pratique, c'est la seule façon de garantir le rétablissement.
 */

export interface RlsGuardOptions {
  /** Tables dont FORCE doit être temporairement levé. */
  tables: string[];
  logger?: TenancyLogger;
}

/**
 * Exécute `work` avec FORCE RLS temporairement désactivé sur les tables
 * demandées, **dans une transaction**, et rétablit FORCE dans tous les cas.
 *
 * @throws si `db` est déjà une transaction — le rétablissement ne serait alors
 *         plus garanti par le ROLLBACK de CETTE fonction.
 */
export async function withRlsDisabled<T>(
  db: Kysely<any>,
  opts: RlsGuardOptions,
  work: (trx: Kysely<any>) => Promise<T>,
): Promise<T> {
  const { tables, logger } = opts;
  if (tables.length === 0) {
    return db.transaction().execute((trx) => work(trx));
  }

  logger?.debug(
    `FORCE RLS levé temporairement sur ${tables.length} table(s) : ${tables.join(', ')}`,
  );

  return db.transaction().execute(async (trx) => {
    for (const t of tables) {
      await sql`alter table ${sql.ref(t)} no force row level security`.execute(trx);
    }
    try {
      const result = await work(trx);
      for (const t of tables) {
        await sql`alter table ${sql.ref(t)} force row level security`.execute(trx);
      }
      logger?.debug(`FORCE RLS rétabli sur ${tables.length} table(s)`);
      return result;
    } catch (e) {
      // Le ROLLBACK annule aussi les ALTER TABLE : FORCE est rétabli par la
      // base elle-même. On le dit explicitement pour que personne n'aille
      // vérifier à la main dans l'urgence.
      logger?.warn(
        `Migration interrompue : ${(e as Error).message}. ` +
          `FORCE RLS sera rétabli par le ROLLBACK sur : ${tables.join(', ')}. ` +
          `Aucune action manuelle requise.`,
      );
      throw e;
    }
  });
}

/**
 * Vérifie qu'aucune table n'a été laissée sans FORCE.
 *
 * À appeler au démarrage de l'application : c'est le filet qui attrape une
 * migration interrompue hors transaction — le cas D de la sonde, celui qui ne
 * produit aucun signal par lui-même.
 */
export async function assertForceEnabled(
  db: Kysely<any>,
  logger?: TenancyLogger,
): Promise<string[]> {
  const rows = await sql<{ relname: string }>`
    select c.relname
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    join pg_attribute a on a.attrelid = c.oid and a.attname = 'tenant_id'
    where n.nspname = 'public'
      and c.relkind = 'r'
      and not (c.relrowsecurity and c.relforcerowsecurity)
  `.execute(db);

  const exposed = rows.rows.map((r) => r.relname);
  if (exposed.length > 0) {
    logger?.error(MSG.forceLeftDisabled(exposed));
  }
  return exposed;
}

/**
 * Vérifie que toute table sous RLS a au moins une policy.
 *
 * Une table avec RLS activée et zéro policy est **vide pour tout le monde**,
 * sans erreur — le défaut le plus difficile à diagnostiquer de la phase 0.
 */
export async function assertPoliciesPresent(
  db: Kysely<any>,
  logger?: TenancyLogger,
): Promise<string[]> {
  const rows = await sql<{ relname: string }>`
    select c.relname
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and c.relkind = 'r'
      and c.relrowsecurity
      and not exists (select 1 from pg_policy p where p.polrelid = c.oid)
  `.execute(db);

  const silent = rows.rows.map((r) => r.relname);
  for (const t of silent) logger?.error(MSG.rlsWithoutPolicy(t));
  return silent;
}

/**
 * Vérifie que le rôle courant ne contourne pas la RLS.
 *
 * `BYPASSRLS` ou `SUPERUSER` sur le rôle applicatif réduit toute l'isolation à
 * néant — et rien ne le signale à l'exécution.
 */
export async function assertRoleIsSafe(
  db: Kysely<any>,
  logger?: TenancyLogger,
): Promise<boolean> {
  const r = await sql<{
    rolname: string;
    rolbypassrls: boolean;
    rolsuper: boolean;
  }>`
    select rolname, rolbypassrls, rolsuper
    from pg_roles where rolname = current_user
  `.execute(db);

  const row = r.rows[0];
  // Voir `guards.ts` : `rows[0]` est typé non-nullable alors qu'une requête
  // peut ne rien rendre. Le garde protège un cas réel que le type nie.
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (!row) return false;

  const problems: string[] = [];
  if (row.rolbypassrls) problems.push('a BYPASSRLS');
  if (row.rolsuper) problems.push('est SUPERUSER');

  if (problems.length > 0) {
    logger?.error(MSG.unsafeRole(row.rolname, problems.join(' et ')));
    return false;
  }
  return true;
}
