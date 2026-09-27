import { type Kysely, sql } from 'kysely';

/**
 * La chaîne d'audit, réparée.
 *
 * 1. SECURITY DEFINER, détenue par `app_policy` (BYPASSRLS). Le trigger relit la
 *    dernière empreinte du tenant, sous la policy `audit_lecture` qui exige
 *    `audit.read`. MESURÉ (sonde SQL, phase 4-bis) : un acteur sans `audit.read`
 *    ne la voyait pas, et chaque entrée repartait d'un maillon vide — la chaîne
 *    n'enchaînait rien pour la quasi-totalité des mutations.
 * 2. Verrou consultatif par tenant : deux insertions concurrentes lisaient la
 *    même « dernière » empreinte, et la chaîne fourchait.
 * 3. UNE formule, `app_empreinte_audit`, pour le trigger ET pour `verifyChain` —
 *    elle couvre désormais rôle, ressource, motif, avant et après. Avant, un
 *    motif réécrit en base passait la vérification.
 *
 * 4. L'horodatage entre dans l'empreinte en UTC, format fixe : `horodatage::text`
 *    dépendait du paramètre `TimeZone` de la session, et une vérification lancée
 *    depuis un autre fuseau concluait à une falsification (trouvé en revue).
 *
 * NB : pas d'apostrophe dans le SQL ci-dessous (littéral de template).
 */
export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    create or replace function app_empreinte_audit(p_prec bytea, j journal_audit)
    returns bytea language sql stable set search_path = public, pg_temp
    as $$
      select digest(
        coalesce(encode(p_prec, 'hex'), '') ||
        to_char(j.horodatage at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') || j.action ||
        j.cible_type || coalesce(j.cible_id::text, '') ||
        coalesce(j.acteur_id::text, 'system') || j.acteur_role ||
        coalesce(j.ressource_id::text, '') || coalesce(j.motif, '') ||
        coalesce(j.avant::text, '') || coalesce(j.apres::text, ''),
        'sha256')
    $$
  `.execute(db);

  await sql`
    create or replace function chaine_audit() returns trigger
    language plpgsql security definer set search_path = public, pg_temp
    as $$
    declare v_prec bytea;
    begin
      -- Serialise les ecritures dun meme tenant jusqua la fin de la transaction.
      perform pg_advisory_xact_lock(hashtext('journal_audit:' || new.tenant_id::text));
      -- L id d identite est attribue AVANT ce trigger, donc avant le verrou :
      -- deux ecritures concurrentes se chainaient dans l ordre du verrou mais
      -- se numerotaient dans l ordre d arrivee (MESURE : 20 ecritures, chaine
      -- rompue). On le reprend ici, verrou tenu : l ordre des id EST l ordre
      -- du chainage, que verifyChain parcourt.
      new.id := nextval(pg_get_serial_sequence('journal_audit', 'id'));
      select empreinte into v_prec from journal_audit
      where tenant_id = new.tenant_id order by id desc limit 1;
      new.empreinte_precedente := v_prec;
      new.empreinte := app_empreinte_audit(v_prec, new);
      return new;
    end $$
  `.execute(db);

  await sql`grant select on journal_audit to app_policy`.execute(db);
  // Le trigger (détenu par app_policy) renumérote l'entrée : il consomme la séquence.
  await sql`grant usage on sequence journal_audit_id_seq to app_policy`.execute(db);
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

/** Retour à la forme 003 : trigger à droits de l'appelant, formule courte. */
export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    create or replace function chaine_audit() returns trigger
    language plpgsql security invoker as $$
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
  await sql`drop function if exists app_empreinte_audit(bytea, journal_audit)`.execute(
    db,
  );
}
