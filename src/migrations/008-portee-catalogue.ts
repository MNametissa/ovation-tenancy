import { type Kysely, sql } from 'kysely';

/** Portée par appartenance, indépendante de la permission globale du garde. */
export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    create or replace function app_a_permission_portee(p_code text, p_ressource uuid)
    returns boolean language sql stable security definer
    set search_path = public, pg_temp
    as $$
      select exists (
        select 1 from appartenance a
        join role_permission rp on rp.role_id = a.role_id
        join permission p on p.id = rp.permission_id
        where a.utilisateur_id = nullif(current_setting('app.user', true), '')::uuid
          and a.tenant_id = nullif(current_setting('app.tenant', true), '')::uuid
          and p.code = p_code and p.obsolete_le is null
          and (a.portee_ressource_id is null or a.portee_ressource_id = p_ressource)
      );
    $$`.execute(db);
  await sql`alter function app_a_permission_portee(text, uuid) owner to app_policy`.execute(
    db,
  );
  await sql`revoke all on function app_a_permission_portee(text, uuid) from public`.execute(
    db,
  );
  await sql`grant execute on function app_a_permission_portee(text, uuid) to app_runtime`.execute(
    db,
  );
  // Les ressources où l'acteur détient la permission PAR PORTÉE (liste vide
  // si aucune). Rendue en tableau pour être évaluée UNE fois par requête.
  await sql`
    create or replace function app_portees_permission(p_code text)
    returns uuid[] language sql stable security definer
    set search_path = public, pg_temp
    as $$
      select coalesce(array_agg(distinct a.portee_ressource_id), '{}')
      from appartenance a
      join role_permission rp on rp.role_id = a.role_id
      join permission p on p.id = rp.permission_id
      where a.utilisateur_id = nullif(current_setting('app.user', true), '')::uuid
        and a.tenant_id = nullif(current_setting('app.tenant', true), '')::uuid
        and p.code = p_code and p.obsolete_le is null
        and a.portee_ressource_id is not null;
    $$`.execute(db);
  await sql`alter function app_portees_permission(text) owner to app_policy`.execute(
    db,
  );
  await sql`revoke all on function app_portees_permission(text) from public`.execute(
    db,
  );
  await sql`grant execute on function app_portees_permission(text) to app_runtime`.execute(
    db,
  );
  // Chaque fonction entre `(select …)` : évaluée une fois (InitPlan), et non à
  // chaque ligne — MESURÉ en L7, un appel par ligne coûte ~8 µs, soit des
  // secondes sur un journal d'un million de lignes, même pour un titulaire
  // sans portée.
  //
  // Revue croisée : la version par ligne masquait aussi au titulaire à portée
  // SES PROPRES consultations (`audit.*`, sans ressource), que le service
  // relit pour dédoublonner — chaque rafraîchissement ajoutait une entrée.
  // Il voit donc ses consultations du journal, et rien d'autre hors portée.
  await sql`drop policy audit_lecture on journal_audit`.execute(db);
  await sql`create policy audit_lecture on journal_audit as restrictive for select
    using (
      (select app_a_permission_portee('audit.read', null))
      or ressource_id = any ((select app_portees_permission('audit.read'))::uuid[])
      or (
        acteur_id = nullif(current_setting('app.user', true), '')::uuid
        and action like 'audit.%'
      )
    )`.execute(db);
  await sql`revoke insert, update, delete on permission from app_runtime`.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`drop policy audit_lecture on journal_audit`.execute(db);
  await sql`create policy audit_lecture on journal_audit as restrictive for select
    using ((select app_a_permission('audit.read')))`.execute(db);
  await sql`drop function app_portees_permission(text)`.execute(db);
  await sql`drop function app_a_permission_portee(text, uuid)`.execute(db);
  await sql`grant insert, update on permission to app_runtime`.execute(db);
}
