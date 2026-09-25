import { type Kysely, sql } from 'kysely';

/**
 * Migration 003 — fonctions et triggers.
 *
 * `app_a_permission` est le cœur des policies : elle dit si l'utilisateur
 * courant détient une permission dans le tenant courant.
 *
 * MESURÉ (phase 0) — trois pièges, chacun silencieux :
 *
 *   1. `SECURITY DEFINER` détenue par le propriétaire des tables reste soumise
 *      à FORCE RLS : elle ne voit rien et rend TOUJOURS false. D'où
 *      `app_policy`, rôle BYPASSRLS propriétaire d'aucune table.
 *
 *   2. BYPASSRLS contourne les POLICIES, pas les PRIVILÈGES. Le GRANT SELECT
 *      reste nécessaire — et strictement limité aux trois tables lues.
 *
 *   3. `search_path` figé obligatoire : sans lui, un SECURITY DEFINER est une
 *      porte dérobée.
 */

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    create or replace function app_a_permission(p_code text) returns boolean
    language sql stable security definer
    set search_path = public, pg_temp
    as $$
      select exists (
        select 1
        from appartenance a
        join role_permission rp on rp.role_id = a.role_id
        join permission p       on p.id = rp.permission_id
        where a.utilisateur_id = nullif(current_setting('app.user', true), '')::uuid
          and a.tenant_id      = nullif(current_setting('app.tenant', true), '')::uuid
          and p.code = p_code
          and p.obsolete_le is null
      );
    $$
  `.execute(db);

  await sql`alter function app_a_permission(text) owner to app_policy`.execute(db);
  await sql`revoke all on function app_a_permission(text) from public`.execute(db);
  await sql`grant execute on function app_a_permission(text) to app_runtime, app_migration`
    .execute(db);
  await sql`grant select on appartenance, role_permission, permission to app_policy`
    .execute(db);

  /**
   * Trigger de portée requise.
   *
   * Un CHECK ne peut pas lire une autre table : l'invariant « ce rôle exige une
   * portée » vit dans `role.portee_requise`, donc il faut un trigger.
   *
   * Le second contrôle ferme une faille discrète : sans lui, un tenant pourrait
   * attribuer un rôle appartenant à un AUTRE tenant.
   */
  await sql`
    create or replace function verifie_portee_requise() returns trigger
    language plpgsql as $$
    declare
      v_requise boolean;
      v_role_tenant uuid;
      v_code text;
    begin
      select portee_requise, tenant_id, code
        into v_requise, v_role_tenant, v_code
      from role where id = new.role_id;

      if v_requise and new.portee_ressource_id is null then
        raise exception
          'Le rôle « % » exige une portée sur une ressource. '
          'Renseignez portee_ressource_id, ou retirez portee_requise du rôle.',
          coalesce(v_code, new.role_id::text)
          using errcode = 'check_violation';
      end if;

      if v_role_tenant is not null and v_role_tenant <> new.tenant_id then
        raise exception
          'Le rôle « % » appartient à un autre tenant. '
          'Un rôle propre à un tenant ne peut être attribué que dans celui-ci.',
          coalesce(v_code, new.role_id::text)
          using errcode = 'check_violation';
      end if;

      return new;
    end $$
  `.execute(db);

  await sql`drop trigger if exists appartenance_portee on appartenance`.execute(db);
  await sql`
    create trigger appartenance_portee
      before insert or update on appartenance
      for each row execute function verifie_portee_requise()
  `.execute(db);

  /**
   * Chaînage du journal d'audit.
   *
   * Ce que le chaînage prouve : la suppression ponctuelle et l'altération
   * accidentelle. Ce qu'il NE prouve PAS : il ne protège pas d'un opérateur qui
   * recalculerait toute la chaîne. À présenter comme tel, sans survente.
   */
  await sql`
    create or replace function chaine_audit() returns trigger
    language plpgsql as $$
    declare v_prec bytea;
    begin
      select empreinte into v_prec
      from journal_audit
      where tenant_id = new.tenant_id
      order by id desc limit 1;

      new.empreinte_precedente := v_prec;
      new.empreinte := digest(
        coalesce(encode(v_prec, 'hex'), '') || new.horodatage::text || new.action ||
        new.cible_type || coalesce(new.cible_id::text, '') ||
        coalesce(new.acteur_id::text, 'system'),
        'sha256'
      );
      return new;
    end $$
  `.execute(db);

  await sql`drop trigger if exists journal_chainage on journal_audit`.execute(db);
  await sql`
    create trigger journal_chainage
      before insert on journal_audit
      for each row execute function chaine_audit()
  `.execute(db);

  // Immuabilité au niveau base : la révocation de privilège ET la règle.
  // La première empêche, la seconde neutralise même si un privilège était
  // accordé par erreur.
  await sql`revoke update, delete on journal_audit from app_runtime`.execute(db);
  await sql`create or replace rule journal_no_update as
            on update to journal_audit do instead nothing`.execute(db);
  await sql`create or replace rule journal_no_delete as
            on delete to journal_audit do instead nothing`.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`drop trigger if exists journal_chainage on journal_audit`.execute(db);
  await sql`drop trigger if exists appartenance_portee on appartenance`.execute(db);
  await sql`drop function if exists chaine_audit() cascade`.execute(db);
  await sql`drop function if exists verifie_portee_requise() cascade`.execute(db);
  await sql`drop function if exists app_a_permission(text) cascade`.execute(db);
}
