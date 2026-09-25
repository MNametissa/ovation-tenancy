import { type Kysely, sql } from 'kysely';

/**
 * Migration 002 — tables du socle multitenant.
 *
 * Toutes portent `tenant_id` sauf `permission` (catalogue global : il décrit
 * ce que le CODE sait faire respecter) et `utilisateur` (identité globale,
 * une personne peut appartenir à plusieurs tenants).
 *
 * Invariants posés ici plutôt qu'en applicatif :
 *   - unicité TOUJOURS scopée au tenant (un UNIQUE global serait un oracle
 *     d'existence inter-tenant : les contraintes contournent la RLS) ;
 *   - `UNIQUE NULLS NOT DISTINCT` pour les rôles système (sans lui, deux
 *     rôles de même code passeraient, NULL ≠ NULL en SQL standard) ;
 *   - motif obligatoire sur les états défavorables.
 */

export async function up(db: Kysely<any>): Promise<void> {
  await sql`create extension if not exists citext`.execute(db);
  await sql`create extension if not exists pgcrypto`.execute(db);

  await sql`
    create table if not exists tenant (
      id             uuid primary key default gen_random_uuid(),
      slug           citext not null unique,
      nom            text not null,
      raison_sociale text,
      rccm           text,
      pays           char(2) not null,
      statut         text not null default 'actif'
                     check (statut in ('actif','suspendu','archive')),
      creee_le       timestamptz not null default now()
    )
  `.execute(db);

  await sql`
    create table if not exists utilisateur (
      id          uuid primary key default gen_random_uuid(),
      auth_sub    text not null unique,
      email       citext not null unique,
      nom_affiche text,
      creee_le    timestamptz not null default now()
    )
  `.execute(db);

  // Catalogue global, alimenté par auto-découverte. Jamais édité à la main.
  await sql`
    create table if not exists permission (
      id          uuid primary key default gen_random_uuid(),
      code        text not null unique,
      libelle     text not null default '',
      description text,
      domaine     text not null default 'general',
      source      text not null default 'convention',
      obsolete_le timestamptz,
      creee_le    timestamptz not null default now()
    )
  `.execute(db);

  await sql`
    create table if not exists role (
      id             uuid primary key default gen_random_uuid(),
      tenant_id      uuid references tenant(id) on delete cascade,
      code           text not null,
      libelle        text not null,
      description    text,
      systeme        boolean not null default false,
      portee_requise boolean not null default false,
      creee_le       timestamptz not null default now(),
      constraint role_code_unique unique nulls not distinct (tenant_id, code),
      constraint role_systeme_sans_tenant check (not systeme or tenant_id is null)
    )
  `.execute(db);

  await sql`
    create table if not exists role_permission (
      role_id       uuid not null references role(id) on delete cascade,
      permission_id uuid not null references permission(id) on delete restrict,
      primary key (role_id, permission_id)
    )
  `.execute(db);

  // La table portant la portée est déclarée par l'hôte (scopedResource).
  // Ici, `appartenance.portee_ressource_id` reste sans clé étrangère : la
  // bibliothèque ne connaît pas le métier de son consommateur.
  await sql`
    create table if not exists appartenance (
      id                   uuid primary key default gen_random_uuid(),
      tenant_id            uuid not null references tenant(id) on delete cascade,
      utilisateur_id       uuid not null references utilisateur(id) on delete cascade,
      role_id              uuid not null references role(id) on delete restrict,
      portee_ressource_id  uuid,
      creee_le             timestamptz not null default now(),
      constraint appartenance_unique unique nulls not distinct
        (tenant_id, utilisateur_id, role_id, portee_ressource_id)
    )
  `.execute(db);

  await sql`
    create table if not exists journal_audit (
      id                   bigint generated always as identity primary key,
      tenant_id            uuid not null references tenant(id) on delete restrict,
      ressource_id         uuid,
      horodatage           timestamptz not null default now(),
      acteur_id            uuid references utilisateur(id) on delete restrict,
      acteur_role          text not null,
      action               text not null,
      cible_type           text not null,
      cible_id             uuid,
      avant                jsonb,
      apres                jsonb,
      motif                text,
      empreinte_precedente bytea,
      empreinte            bytea not null
    )
  `.execute(db);

  // Index exigés par les policies : sans eux, chaque requête sous RLS
  // dégénère (mesuré phase 0).
  await sql`create index if not exists appartenance_user_tenant_idx
            on appartenance (utilisateur_id, tenant_id)`.execute(db);
  await sql`create index if not exists appartenance_user_portee_idx
            on appartenance (utilisateur_id, portee_ressource_id)
            where portee_ressource_id is not null`.execute(db);
  await sql`create index if not exists appartenance_tenant_role_idx
            on appartenance (tenant_id, role_id)`.execute(db);
  await sql`create index if not exists role_permission_idx
            on role_permission (role_id, permission_id)`.execute(db);
  await sql`create index if not exists permission_domaine_idx
            on permission (domaine) where obsolete_le is null`.execute(db);
  await sql`create index if not exists journal_tenant_date_idx
            on journal_audit (tenant_id, horodatage desc)`.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  for (const t of [
    'journal_audit',
    'appartenance',
    'role_permission',
    'role',
    'permission',
    'utilisateur',
    'tenant',
  ]) {
    await sql`drop table if exists ${sql.ref(t)} cascade`.execute(db);
  }
}
