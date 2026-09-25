import { type Kysely, sql } from 'kysely';

/**
 * Migration 004 — Row Level Security.
 *
 * TROIS PIÈGES MESURÉS EN PHASE 0, chacun silencieux :
 *
 *   1. Une policy RESTRICTIVE seule BLOQUE TOUT. Elle restreint, elle n'accorde
 *      rien : sans PERMISSIVE de base, la formule est
 *      (aucune permissive = FAUX) AND restrictives → toujours faux.
 *      Résultat : 0 ligne partout, sans le moindre message d'erreur.
 *
 *   2. Sans WITH CHECK explicite, PostgreSQL retombe sur USING pour les
 *      écritures. Une restrictive correcte en lecture bloque alors des INSERT
 *      légitimes.
 *
 *   3. FORCE est indispensable : sans lui le propriétaire contourne la RLS
 *      (mesuré : 2/2 lignes visibles alors que la policy existait).
 *
 * Et le `(SELECT ...)` n'est pas une optimisation : il force un InitPlan, donc
 * UNE évaluation par requête au lieu d'une par ligne. Mesuré : 575,8 ms contre
 * 71,2 ms sur 10 000 lignes — facteur 8,1.
 */

/** Tables du socle portant `tenant_id`. */
const TENANT_TABLES = ['tenant', 'role', 'appartenance', 'journal_audit'] as const;

export async function up(db: Kysely<any>): Promise<void> {
  for (const t of TENANT_TABLES) {
    await sql`alter table ${sql.ref(t)} enable row level security`.execute(db);
    await sql`alter table ${sql.ref(t)} force row level security`.execute(db);
  }

  // ── 1. PERMISSIVE de base, une par table ───────────────────────────────
  // Sans elle : 0 ligne partout, silencieusement.
  for (const t of TENANT_TABLES) {
    await sql`drop policy if exists base on ${sql.ref(t)}`.execute(db);
    await sql`
      create policy base on ${sql.ref(t)}
      for all to app_runtime using (true) with check (true)
    `.execute(db);
  }

  // ── 2. Isolation tenant, RESTRICTIVE, avec WITH CHECK ──────────────────
  const tenantScoped = ['role', 'appartenance', 'journal_audit'] as const;
  for (const t of tenantScoped) {
    await sql`drop policy if exists tenant_isolation on ${sql.ref(t)}`.execute(db);
  }

  // `role` : un rôle système (tenant_id NULL) est visible de tous.
  await sql`
    create policy tenant_isolation on role as restrictive
    using      (tenant_id is null
                or tenant_id = (select nullif(current_setting('app.tenant', true), '')::uuid))
    with check (tenant_id is null
                or tenant_id = (select nullif(current_setting('app.tenant', true), '')::uuid))
  `.execute(db);

  await sql`
    create policy tenant_isolation on appartenance as restrictive
    using      (tenant_id = (select nullif(current_setting('app.tenant', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant', true), '')::uuid))
  `.execute(db);

  await sql`
    create policy tenant_isolation on journal_audit as restrictive
    using      (tenant_id = (select nullif(current_setting('app.tenant', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant', true), '')::uuid))
  `.execute(db);

  // `tenant` : la clé du tenant est `id`, pas `tenant_id`.
  await sql`drop policy if exists tenant_isolation on tenant`.execute(db);
  await sql`
    create policy tenant_isolation on tenant as restrictive
    using      (id = (select nullif(current_setting('app.tenant', true), '')::uuid))
    with check (id = (select nullif(current_setting('app.tenant', true), '')::uuid))
  `.execute(db);

  // ── 3. Lecture du journal conditionnée à une permission ────────────────
  await sql`drop policy if exists audit_lecture on journal_audit`.execute(db);
  await sql`
    create policy audit_lecture on journal_audit as restrictive for select
    using ((select app_a_permission('audit.read')))
  `.execute(db);

  // `permission` et `utilisateur` sont globales : pas de RLS, mais lecture
  // seule pour le rôle applicatif — le catalogue décrit ce que le CODE sait
  // faire respecter, il n'appartient à personne.
  await sql`grant select on permission, utilisateur to app_runtime`.execute(db);
  await sql`grant select on role_permission to app_runtime`.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  for (const t of TENANT_TABLES) {
    await sql`drop policy if exists base on ${sql.ref(t)}`.execute(db);
    await sql`drop policy if exists tenant_isolation on ${sql.ref(t)}`.execute(db);
    await sql`alter table ${sql.ref(t)} no force row level security`.execute(db);
    await sql`alter table ${sql.ref(t)} disable row level security`.execute(db);
  }
  await sql`drop policy if exists audit_lecture on journal_audit`.execute(db);
}
