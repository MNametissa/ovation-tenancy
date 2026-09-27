import { type Kysely, sql } from 'kysely';

/**
 * Migration 006 — moindre privilège (lot L1 du plan des correctifs).
 *
 * 1. `app_runtime` avait TOUS les droits sur `utilisateur`, `permission` et
 *    `tenant` (migration 002). Vérifié par grep avant révocation : aucun code
 *    sous `app_runtime` n'écrit dans `utilisateur` (création, revendication et
 *    acceptation passent par des SECURITY DEFINER détenues par `app_policy`),
 *    ne supprime de permission (le puits marque obsolète), ni ne crée ou
 *    supprime de tenant (`tenant:create` tourne en administrateur).
 *    `UPDATE tenant` reste : modification de l'organisation, et le
 *    `FOR UPDATE` du trigger du dernier propriétaire.
 * 2. Un tenant pouvait créer un rôle à `tenant_id` NUL — donc visible de toutes
 *    les organisations — parce que le WITH CHECK de `role` acceptait le nul.
 *    Désormais : on n'écrit que dans son tenant, et `systeme ⇔ tenant_id nul`.
 * 3. `app_migration` ne possédait rien (mesuré) : ses droits sont retirés. Le
 *    rôle, global au cluster, n'est pas supprimé ici — d'autres bases peuvent
 *    encore y faire référence (`DROP ROLE app_migration` à la main ensuite).
 * 4. `auditRls` vérifie que les migrations attendues sont appliquées, sous le
 *    rôle applicatif : il doit pouvoir LIRE la table de suivi.
 */
const TENANT_COURANT = `(select nullif(current_setting('app.tenant', true), '')::uuid)`;

export async function up(db: Kysely<any>): Promise<void> {
  await sql`revoke insert, update, delete on utilisateur from app_runtime`.execute(db);
  await sql`revoke delete on permission from app_runtime`.execute(db);
  await sql`revoke insert, delete on tenant from app_runtime`.execute(db);

  await sql`drop policy if exists tenant_isolation on role`.execute(db);
  await sql
    .raw(
      `create policy tenant_isolation on role as restrictive
       using      (tenant_id is null or tenant_id = ${TENANT_COURANT})
       with check (tenant_id = ${TENANT_COURANT})`,
    )
    .execute(db);
  await sql`alter table role drop constraint if exists role_systeme_sans_tenant`.execute(
    db,
  );
  await sql`alter table role add constraint role_systeme_tenant_nul
            check (systeme = (tenant_id is null))`.execute(db);

  const migration = await sql<{
    n: number;
  }>`select count(*)::int as n from pg_roles where rolname = 'app_migration'`.execute(
    db,
  );
  if (migration.rows[0].n > 0) {
    await sql`revoke all on schema public from app_migration`.execute(db);
    await sql`revoke all on all tables in schema public from app_migration`.execute(db);
    await sql`revoke all on all functions in schema public from app_migration`.execute(
      db,
    );
    await sql`alter default privileges for role app_migration in schema public
              revoke all on tables from app_runtime`.execute(db);
  }

  await sql`grant select on tenancy_migrations to app_runtime`.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`revoke select on tenancy_migrations from app_runtime`.execute(db);
  await sql`alter table role drop constraint if exists role_systeme_tenant_nul`.execute(
    db,
  );
  await sql`alter table role add constraint role_systeme_sans_tenant
            check (not systeme or tenant_id is null)`.execute(db);
  await sql`drop policy if exists tenant_isolation on role`.execute(db);
  await sql
    .raw(
      `create policy tenant_isolation on role as restrictive
       using      (tenant_id is null or tenant_id = ${TENANT_COURANT})
       with check (tenant_id is null or tenant_id = ${TENANT_COURANT})`,
    )
    .execute(db);
  await sql`grant insert, delete on tenant to app_runtime`.execute(db);
  await sql`grant delete on permission to app_runtime`.execute(db);
  await sql`grant insert, update, delete on utilisateur to app_runtime`.execute(db);
}
