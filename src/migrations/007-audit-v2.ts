import { type Kysely, sql } from 'kysely';
import * as m005 from './005-audit-chaine.js';

/**
 * Chaîne d'audit, version 2 (lot L1-7).
 *
 * 1. ENCODAGE CANONIQUE. La v1 concaténait les champs sans séparateur : un
 *    motif `erreur{"a": 1}` sans « avant » et un motif `erreur` avec
 *    `avant = {"a":1}` donnaient la MÊME empreinte (mesuré). La v2 hache
 *    `jsonb_build_array(...)::text` : chaque champ est un élément typé, un nul
 *    est `null`, et une chaîne ne peut plus déborder sur sa voisine.
 * 2. `tenant_id` et la VERSION de la formule entrent dans l'empreinte ; la
 *    version est stockée dans `version_empreinte`, imposée par le trigger.
 * 3. Le trigger impose `horodatage := clock_timestamp()` : l'appelant ne choisit
 *    plus la date de ce qu'il écrit.
 * 4. `audit_chaine_tete` tient À PART le nombre d'entrées et le dernier maillon
 *    de chaque tenant : `verifyChain` y compare la chaîne, et une queue tronquée
 *    — ou une chaîne entièrement supprimée — est détectée. Le trigger enchaîne
 *    sur ce dernier maillon connu : il ne cherche plus la dernière ligne du
 *    tenant (`order by id desc limit 1`, 405 ms mesurés sans index).
 * 5. L'existant est RECALCULÉ en v2 (voir `recalculer`).
 *
 * PERFORMANCE (audit du 2026-09-27) :
 *  - `app_empreinte_audit` n'a plus de `SET search_path` : il empêchait
 *    l'inlining (27 µs par ligne). Elle n'est pas SECURITY DEFINER ; tous ses
 *    noms sont QUALIFIÉS, aucune résolution ne dépend du chemin de l'appelant ;
 *  - index `(tenant_id, id)` (liste du journal, recalcul), `(acteur_id, id)`
 *    (clé étrangère vers `utilisateur`, filtre par acteur) et
 *    `(tenant_id, ressource_id, id)` (filtre par évènement).
 *
 * EXPLOITATION : sur un gros journal, cette migration réécrit chaque ligne sous
 * verrou exclusif (règle d'immuabilité levée) — la prévoir dans une FENÊTRE DE
 * MAINTENANCE, puis lancer `VACUUM (ANALYZE) journal_audit` : la réécriture
 * double la taille de la table jusqu'au VACUUM.
 *
 * Limite inchangée, à dire sans survente : un opérateur qui recalculerait toute
 * la chaîne ET la tête reste indétectable de l'intérieur de la base.
 *
 * NB : pas d'apostrophe dans les commentaires SQL ci-dessous.
 */
const TENANT_COURANT = `(select nullif(current_setting('app.tenant', true), '')::uuid)`;

export async function up(db: Kysely<any>): Promise<void> {
  // Valeur par défaut portée par le CATALOGUE (PostgreSQL 11+) : pas de
  // réécriture de la table, et chaque ligne existante se lit déjà en v2.
  await sql`alter table journal_audit
            add column if not exists version_empreinte smallint not null default 2`.execute(
    db,
  );
  await sql`create index if not exists journal_tenant_id_idx
            on journal_audit (tenant_id, id)`.execute(db);
  await sql`create index if not exists journal_acteur_idx
            on journal_audit (acteur_id, id)`.execute(db);
  await sql`create index if not exists journal_tenant_ressource_idx
            on journal_audit (tenant_id, ressource_id, id)`.execute(db);

  await tete(db);

  await sql`
    create or replace function app_empreinte_audit(p_prec bytea, j journal_audit)
    returns bytea language sql stable
    as $$
      select public.digest(pg_catalog.jsonb_build_array(
        j.version_empreinte,
        pg_catalog.encode(p_prec, 'hex'),
        j.tenant_id,
        pg_catalog.to_char(pg_catalog.timezone('UTC', j.horodatage),
                           'YYYY-MM-DD"T"HH24:MI:SS.US'),
        j.action, j.cible_type, j.cible_id,
        j.acteur_id, j.acteur_role, j.ressource_id,
        j.motif, j.avant, j.apres
      )::text, 'sha256')
    $$
  `.execute(db);

  await recalculer(db);

  await sql`
    create or replace function chaine_audit() returns trigger
    language plpgsql security definer set search_path = public, pg_temp
    as $$
    declare v_prec bytea;
    begin
      -- Serialise les ecritures dun meme tenant jusqua la fin de la transaction.
      perform pg_advisory_xact_lock(hashtext('journal_audit:' || new.tenant_id::text));
      new.horodatage := clock_timestamp();
      new.version_empreinte := 2;
      -- Id repris verrou tenu : l ordre des id EST l ordre du chainage.
      new.id := nextval(pg_get_serial_sequence('journal_audit', 'id'));
      select t.derniere_empreinte into v_prec
      from audit_chaine_tete t where t.tenant_id = new.tenant_id;
      new.empreinte_precedente := v_prec;
      new.empreinte := app_empreinte_audit(v_prec, new);
      insert into audit_chaine_tete as t (tenant_id, nombre, dernier_id, derniere_empreinte)
      values (new.tenant_id, 1, new.id, new.empreinte)
      on conflict (tenant_id) do update
        set nombre = t.nombre + 1,
            dernier_id = excluded.dernier_id,
            derniere_empreinte = excluded.derniere_empreinte;
      return new;
    end $$
  `.execute(db);

  await sql`alter function app_empreinte_audit(bytea, journal_audit) owner to app_policy`.execute(
    db,
  );
  await sql`alter function chaine_audit() owner to app_policy`.execute(db);
  await sql`revoke all on function app_empreinte_audit(bytea, journal_audit) from public`.execute(
    db,
  );
  await sql`grant execute on function app_empreinte_audit(bytea, journal_audit)
            to app_runtime`.execute(db);
}

/** Tête de chaîne par tenant : lue par `verifyChain`, écrite par le seul trigger. */
async function tete(db: Kysely<any>): Promise<void> {
  await sql`
    create table if not exists audit_chaine_tete (
      tenant_id          uuid primary key references tenant(id) on delete cascade,
      nombre             bigint not null,
      dernier_id         bigint not null,
      derniere_empreinte bytea not null
    )
  `.execute(db);
  await sql`alter table audit_chaine_tete enable row level security`.execute(db);
  await sql`alter table audit_chaine_tete force row level security`.execute(db);
  await sql`drop policy if exists base on audit_chaine_tete`.execute(db);
  await sql`create policy base on audit_chaine_tete for all to app_runtime
            using (true) with check (true)`.execute(db);
  await sql`drop policy if exists tenant_isolation on audit_chaine_tete`.execute(db);
  await sql
    .raw(
      `create policy tenant_isolation on audit_chaine_tete as restrictive
       using (tenant_id = ${TENANT_COURANT}) with check (tenant_id = ${TENANT_COURANT})`,
    )
    .execute(db);
  await sql`grant select on audit_chaine_tete to app_runtime`.execute(db);
  await sql`grant select, insert, update on audit_chaine_tete to app_policy`.execute(
    db,
  );
}

/**
 * Recalcule toute la chaîne en v2, puis pose la tête de chaque tenant.
 *
 * La chaîne est RÉCURSIVE — chaque empreinte dépend de la précédente
 * RECALCULÉE —, donc un `lag()` ne suffit pas. Une seule requête récursive
 * avance tous les tenants de front, maillon par maillon, par l'index
 * `(tenant_id, id)` ; puis UN `UPDATE` ensembliste réécrit les lignes. MESURÉ
 * (300 000 lignes) : la boucle ligne à ligne précédente prenait 23,6 s.
 *
 * FORCE est levé le temps du recalcul : sous un propriétaire non superuser, la
 * RLS rendrait la table vide et le recalcul ne toucherait rien, en silence.
 * La règle d'immuabilité aussi : c'est la seule réécriture légitime du journal.
 * Le tout tient dans la transaction de la migration.
 */
async function recalculer(db: Kysely<any>): Promise<void> {
  await sql`alter table journal_audit no force row level security`.execute(db);
  await sql`alter table journal_audit disable rule journal_no_update`.execute(db);
  await sql`
    with recursive chaine (tenant_id, id, prec, empreinte) as (
      select j.tenant_id, j.id, null::bytea, app_empreinte_audit(null, j)
      from journal_audit j
      where j.id in (select min(x.id) from journal_audit x group by x.tenant_id)
      union all
      select (s.r).tenant_id, (s.r).id, c.empreinte, app_empreinte_audit(c.empreinte, s.r)
      from chaine c
      cross join lateral (
        select j as r from journal_audit j
        where j.tenant_id = c.tenant_id and j.id > c.id
        order by j.id limit 1
      ) as s
    )
    update journal_audit j
       set version_empreinte = 2, empreinte_precedente = c.prec, empreinte = c.empreinte
      from chaine c
     where j.id = c.id
  `.execute(db);
  await sql`
    insert into audit_chaine_tete (tenant_id, nombre, dernier_id, derniere_empreinte)
    select distinct on (tenant_id) tenant_id, count(*) over (partition by tenant_id), id, empreinte
    from journal_audit order by tenant_id, id desc
    on conflict (tenant_id) do nothing
  `.execute(db);
  await sql`alter table journal_audit enable rule journal_no_update`.execute(db);
  await sql`alter table journal_audit force row level security`.execute(db);
}

/** Retour à la forme 005 : formule v1, pas de tête. Les empreintes v2 ne se vérifient plus. */
export async function down(db: Kysely<any>): Promise<void> {
  await m005.up(db);
  await sql`drop table if exists audit_chaine_tete`.execute(db);
  for (const index of [
    'journal_tenant_id_idx',
    'journal_acteur_idx',
    'journal_tenant_ressource_idx',
  ]) {
    await sql`drop index if exists ${sql.id(index)}`.execute(db);
  }
  await sql`alter table journal_audit drop column if exists version_empreinte`.execute(
    db,
  );
}
