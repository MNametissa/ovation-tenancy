import { type Kysely, sql } from 'kysely';
import { MSG, type TenancyLogger } from '../logging.js';

/**
 * Les six règles RLS, en garde-fous exécutables.
 *
 * Chacune vient d'une mesure de la phase 0, et chacune échoue SILENCIEUSEMENT
 * si elle est violée — c'est ce qui rend ces vérifications indispensables.
 *
 * À appeler au démarrage de l'application, et en intégration continue.
 */

export interface RlsAudit {
  /** Tables avec tenant_id sans RLS ou sans FORCE. */
  missingForce: string[];
  /** Tables sous RLS sans aucune policy : vides pour tout le monde. */
  withoutPolicy: string[];
  /** Tables sous RLS sans policy PERMISSIVE : vides malgré leurs restrictives. */
  withoutPermissive: string[];
  /** Policies restrictives « for all » sans WITH CHECK. */
  missingWithCheck: Array<{ table: string; policy: string }>;
  /** Contraintes d'unicité globales sur une table tenant. */
  globalUniques: Array<{ table: string; constraint: string }>;
  /** Le rôle courant contourne-t-il la RLS ? */
  unsafeRole: string | null;
  /** true si aucune anomalie. */
  ok: boolean;
}

/** Règle 2 — FORCE obligatoire : sans lui, le propriétaire contourne. */
async function checkForce(db: Kysely<any>): Promise<string[]> {
  const r = await sql<{ relname: string }>`
    select c.relname
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    join pg_attribute a on a.attrelid = c.oid and a.attname = 'tenant_id'
    where n.nspname = 'public' and c.relkind = 'r'
      and not (c.relrowsecurity and c.relforcerowsecurity)
  `.execute(db);
  return r.rows.map((x) => x.relname);
}

/**
 * Toute table sous RLS doit avoir au moins une policy.
 *
 * Interroger `pg_class`, JAMAIS `pg_policies` : une table sans policy n'y
 * produit aucune ligne, donc elle y est invisible. C'est la cause de
 * CVE-2025-48757 (170 applications vulnérables sur 1 645).
 */
async function checkAnyPolicy(db: Kysely<any>): Promise<string[]> {
  const r = await sql<{ relname: string }>`
    select c.relname
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity
      and not exists (select 1 from pg_policy p where p.polrelid = c.oid)
  `.execute(db);
  return r.rows.map((x) => x.relname);
}

/**
 * Règle 3 — une PERMISSIVE de base est obligatoire.
 *
 * Une RESTRICTIVE restreint, elle n'accorde rien : sans permissive, la formule
 * est (aucune permissive = FAUX) AND restrictives → toujours faux. Résultat :
 * 0 ligne partout, sans le moindre message d'erreur.
 */
async function checkPermissive(db: Kysely<any>): Promise<string[]> {
  const r = await sql<{ relname: string }>`
    select c.relname
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity
      and exists (select 1 from pg_policy p where p.polrelid = c.oid)
      and not exists (
        select 1 from pg_policy p where p.polrelid = c.oid and p.polpermissive
      )
  `.execute(db);
  return r.rows.map((x) => x.relname);
}

/**
 * WITH CHECK explicite sur les restrictives « for all ».
 *
 * Sans lui, PostgreSQL retombe sur USING pour les écritures : une restrictive
 * correcte en lecture bloque des INSERT légitimes.
 */
async function checkWithCheck(
  db: Kysely<any>,
): Promise<Array<{ table: string; policy: string }>> {
  const r = await sql<{ relname: string; polname: string }>`
    select c.relname, p.polname
    from pg_policy p join pg_class c on c.oid = p.polrelid
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and not p.polpermissive
      and p.polcmd = '*'
      and p.polwithcheck is null
  `.execute(db);
  return r.rows.map((x) => ({ table: x.relname, policy: x.polname }));
}

/**
 * Règle 5 — unicité TOUJOURS scopée au tenant.
 *
 * Les contraintes d'unicité contournent la RLS par conception. Un UNIQUE
 * global sur une table tenant est donc un ORACLE D'EXISTENCE inter-tenant :
 * l'erreur de duplication révèle qu'une ligne existe ailleurs.
 */
async function checkGlobalUniques(
  db: Kysely<any>,
): Promise<Array<{ table: string; constraint: string }>> {
  const r = await sql<{ relname: string; conname: string }>`
    select c.relname, con.conname
    from pg_constraint con
    join pg_class c on c.oid = con.conrelid
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and con.contype = 'u'
      -- la table porte tenant_id …
      and exists (
        select 1 from pg_attribute a
        where a.attrelid = c.oid and a.attname = 'tenant_id' and a.attnum > 0
      )
      -- … mais la contrainte ne l'inclut pas
      and not exists (
        select 1 from pg_attribute a
        where a.attrelid = c.oid and a.attname = 'tenant_id'
          and a.attnum = any(con.conkey)
      )
  `.execute(db);
  return r.rows.map((x) => ({ table: x.relname, constraint: x.conname }));
}

/** Règle 1 — le rôle applicatif ne doit contourner ni policies ni RLS. */
async function checkRole(db: Kysely<any>): Promise<string | null> {
  const r = await sql<{ rolname: string; rolbypassrls: boolean; rolsuper: boolean }>`
    select rolname, rolbypassrls, rolsuper from pg_roles where rolname = current_user
  `.execute(db);
  const row = r.rows[0];
  // Kysely type `rows[0]` comme non-nullable, mais une requête PEUT ne rien
  // rendre — `current_user` absent de `pg_roles` après un DROP ROLE concurrent.
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (!row) return null;
  const why: string[] = [];
  if (row.rolbypassrls) why.push('a BYPASSRLS');
  if (row.rolsuper) why.push('est SUPERUSER');
  return why.length ? `${row.rolname} ${why.join(' et ')}` : null;
}

/**
 * Audit complet de la configuration RLS.
 *
 * Journalise chaque anomalie avec son action corrective — un rapport qu'on ne
 * sait pas traiter finit ignoré.
 */
export async function auditRls(
  db: Kysely<any>,
  logger?: TenancyLogger,
): Promise<RlsAudit> {
  const [
    missingForce,
    withoutPolicy,
    withoutPermissive,
    missingWithCheck,
    globalUniques,
    unsafeRole,
  ] = await Promise.all([
    checkForce(db),
    checkAnyPolicy(db),
    checkPermissive(db),
    checkWithCheck(db),
    checkGlobalUniques(db),
    checkRole(db),
  ]);

  for (const t of missingForce) logger?.error(MSG.missingForce(t));
  for (const t of withoutPolicy) logger?.error(MSG.rlsWithoutPolicy(t));

  for (const t of withoutPermissive) {
    logger?.error(
      `La table « ${t} » n'a que des policies RESTRICTIVE : elle est VIDE ` +
        `pour tous les rôles, silencieusement. Une restrictive restreint, ` +
        `elle n'accorde rien. Ajoutez : CREATE POLICY base ON ${t} FOR ALL ` +
        `TO app_runtime USING (true) WITH CHECK (true);`,
    );
  }

  for (const { table, policy } of missingWithCheck) {
    logger?.error(
      `La policy « ${policy} » sur « ${table} » est RESTRICTIVE sans ` +
        `WITH CHECK : PostgreSQL retombe sur USING pour les écritures et ` +
        `bloquera des INSERT légitimes. Ajoutez une clause WITH CHECK ` +
        `identique à USING.`,
    );
  }

  for (const { table, constraint } of globalUniques) {
    logger?.error(
      `La contrainte « ${constraint} » sur « ${table} » est unique SANS ` +
        `tenant_id. Les contraintes contournent la RLS : l'erreur de ` +
        `duplication révélerait l'existence d'une ligne chez un AUTRE tenant. ` +
        `Remplacez par UNIQUE (tenant_id, …).`,
    );
  }

  if (unsafeRole) {
    logger?.error(
      MSG.unsafeRole(
        unsafeRole.split(' ')[0],
        unsafeRole.split(' ').slice(1).join(' '),
      ),
    );
  }

  const ok =
    missingForce.length === 0 &&
    withoutPolicy.length === 0 &&
    withoutPermissive.length === 0 &&
    missingWithCheck.length === 0 &&
    globalUniques.length === 0 &&
    unsafeRole === null;

  if (ok) logger?.log('Audit RLS : les six règles sont respectées');

  return {
    missingForce,
    withoutPolicy,
    withoutPermissive,
    missingWithCheck,
    globalUniques,
    unsafeRole,
    ok,
  };
}

/**
 * Variante bloquante, pour l'intégration continue et le démarrage.
 *
 * @throws si une anomalie est détectée, avec le détail dans le message.
 */
export async function assertRlsIsSound(
  db: Kysely<any>,
  logger?: TenancyLogger,
): Promise<void> {
  const a = await auditRls(db, logger);
  if (a.ok) return;

  const problems: string[] = [];
  if (a.missingForce.length) problems.push(`sans FORCE : ${a.missingForce.join(', ')}`);
  if (a.withoutPolicy.length)
    problems.push(`sans policy : ${a.withoutPolicy.join(', ')}`);
  if (a.withoutPermissive.length)
    problems.push(`sans permissive : ${a.withoutPermissive.join(', ')}`);
  if (a.missingWithCheck.length)
    problems.push(
      `sans WITH CHECK : ${a.missingWithCheck.map((x) => `${x.table}.${x.policy}`).join(', ')}`,
    );
  if (a.globalUniques.length)
    problems.push(
      `unicité globale : ${a.globalUniques.map((x) => `${x.table}.${x.constraint}`).join(', ')}`,
    );
  if (a.unsafeRole) problems.push(`rôle non bridé : ${a.unsafeRole}`);

  throw new Error(
    `Configuration RLS incorrecte — l'isolation entre tenants n'est PAS ` +
      `garantie. ${problems.join(' ; ')}. Détail et correctifs dans les ` +
      `messages d'erreur ci-dessus.`,
  );
}
