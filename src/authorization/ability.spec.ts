/**
 * T3.9 — autorisation applicative CASL, contre PostgreSQL réel.
 *
 * Le test central : un juré ne peut pas lire les notes d'un autre, refusé par
 * CASL **et** par la RLS. Deux barrières indépendantes, vérifiées séparément.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { runMigrations } from '../migrations/runner.js';
import { RoleService } from '../roles/role-service.js';
import {
  buildAbility,
  loadAbilityContext,
  assertCan,
  ForbiddenError,
} from './ability.js';

const { Pool, Client } = pg;
const DB = 'tenancy_casl_test';

const CREDENTIALS = {
  migration: 'test_migration_pwd',
  runtime: 'test_runtime_pwd',
  auth: 'test_auth_pwd',
};

const T_A = '11111111-1111-1111-1111-111111111111';
const T_B = '22222222-2222-2222-2222-222222222222';
const U_ORGA = 'aaaaaaaa-0000-0000-0000-000000000001';
const U_JURE1 = 'aaaaaaaa-0000-0000-0000-000000000002';
const U_JURE2 = 'aaaaaaaa-0000-0000-0000-000000000003';
const EV_1 = 'e1111111-0000-0000-0000-000000000001';
const EV_2 = 'e1111111-0000-0000-0000-000000000002';

function mkDb(database: string, user: string, password: string, max = 2) {
  return new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new Pool({ host: '127.0.0.1', port: 55432, database, user, password, max }),
    }),
  });
}

let admin: Kysely<any>;

beforeAll(async () => {
  const c = new Client({
    host: '127.0.0.1', port: 55432, database: 'postgres',
    user: 'postgres', password: 'probe',
  });
  await c.connect();
  await c.query(`drop database if exists ${DB}`);
  await c.query(`create database ${DB}`);
  await c.end();

  admin = mkDb(DB, 'postgres', 'probe', 3);
  await runMigrations(admin, { credentials: CREDENTIALS, verify: false });
});

afterAll(async () => {
  await admin.destroy();
  const c = new Client({
    host: '127.0.0.1', port: 55432, database: 'postgres',
    user: 'postgres', password: 'probe',
  });
  await c.connect();
  await c.query(`drop database if exists ${DB}`);
  await c.end();
});

beforeEach(async () => {
  const tables = ['appartenance', 'role_permission', 'role', 'tenant', 'utilisateur'];
  for (const t of tables) {
    await sql.raw(`alter table ${t} no force row level security`).execute(admin);
  }
  await sql`delete from appartenance`.execute(admin);
  await sql`delete from role_permission`.execute(admin);
  await sql`delete from role`.execute(admin);
  await sql`delete from tenant`.execute(admin);
  await sql`delete from utilisateur`.execute(admin);
  await sql`delete from permission`.execute(admin);

  await sql`insert into permission (code, libelle, domaine) values
    ('event.read.all', 'Lire tous les évènements', 'evenement'),
    ('event.update', 'Modifier un évènement', 'evenement'),
    ('event.publish', 'Publier', 'evenement'),
    ('score.read.own', 'Lire ses notes', 'jury'),
    ('score.read.all', 'Lire toutes les notes', 'jury'),
    ('score.create', 'Noter', 'jury'),
    ('audit.read', 'Lire le journal', 'audit')`.execute(admin);

  await sql`insert into tenant (id, slug, nom, pays) values
    (${T_A}, 'a', 'Tenant A', 'CM'), (${T_B}, 'b', 'Tenant B', 'CM')`.execute(admin);
  await sql`insert into utilisateur (id, auth_sub, email) values
    (${U_ORGA}, 'sub-orga', 'orga@test.cm'),
    (${U_JURE1}, 'sub-j1', 'j1@test.cm'),
    (${U_JURE2}, 'sub-j2', 'j2@test.cm')`.execute(admin);

  const roles = new RoleService(admin);
  await roles.ensureSystemRoles();

  const orgaRole = await sql<{ id: string }>`
    select id from role where code = 'organisateur'`.execute(admin);
  const jureRole = await sql<{ id: string }>`
    select id from role where code = 'jure'`.execute(admin);

  await sql`insert into role_permission (role_id, permission_id)
    select ${orgaRole.rows[0].id}, id from permission
    where code in ('event.read.all','event.update','event.publish','score.read.all')
    on conflict do nothing`.execute(admin);
  await sql`insert into role_permission (role_id, permission_id)
    select ${jureRole.rows[0].id}, id from permission
    where code in ('score.read.own','score.create')
    on conflict do nothing`.execute(admin);

  // Organisateur sur EV_1. Deux jurés sur EV_1 — le cas que l'isolation
  // tenant seule ne couvre pas.
  await sql`insert into appartenance (tenant_id, utilisateur_id, role_id, portee_ressource_id)
    values (${T_A}, ${U_ORGA}, ${orgaRole.rows[0].id}, ${EV_1}),
           (${T_A}, ${U_JURE1}, ${jureRole.rows[0].id}, ${EV_1}),
           (${T_A}, ${U_JURE2}, ${jureRole.rows[0].id}, ${EV_1})`.execute(admin);

  for (const t of tables) {
    await sql.raw(`alter table ${t} force row level security`).execute(admin);
  }
});

describe('T3.9 — construction des règles', () => {
  it('dérive can(action, resource) depuis une permission', () => {
    const a = buildAbility({
      tenantId: T_A, userId: U_ORGA,
      permissions: ['event.publish'], scopedResourceIds: [],
    });
    expect(a.can('publish', 'event')).toBe(true);
    expect(a.can('delete', 'event')).toBe(false);
  });

  it('« .all » lève toute condition', () => {
    const a = buildAbility({
      tenantId: T_A, userId: U_ORGA,
      permissions: ['score.read.all'], scopedResourceIds: [EV_1],
    });
    expect(a.can('read', 'score')).toBe(true);
  });

  it('« .own » restreint au propriétaire', () => {
    const a = buildAbility({
      tenantId: T_A, userId: U_JURE1,
      permissions: ['score.read.own'], scopedResourceIds: [EV_1],
    });
    const sienne = { ownerId: U_JURE1, __caslSubjectType__: 'score' };
    const autre = { ownerId: U_JURE2, __caslSubjectType__: 'score' };
    expect(a.can('read', sienne as never)).toBe(true);
    expect(a.can('read', autre as never)).toBe(false);
  });

  it('une permission simple est limitée à la portée', () => {
    const a = buildAbility({
      tenantId: T_A, userId: U_ORGA,
      permissions: ['event.update'], scopedResourceIds: [EV_1],
    });
    expect(a.can('update', { id: EV_1, __caslSubjectType__: 'event' } as never)).toBe(true);
    expect(a.can('update', { id: EV_2, __caslSubjectType__: 'event' } as never)).toBe(false);
  });

  it('sans portée, la permission vaut partout dans le tenant', () => {
    const a = buildAbility({
      tenantId: T_A, userId: U_ORGA,
      permissions: ['event.update'], scopedResourceIds: [],
    });
    expect(a.can('update', { id: EV_2, __caslSubjectType__: 'event' } as never)).toBe(true);
  });

  it('aucune permission : tout est refusé', () => {
    const a = buildAbility({
      tenantId: T_A, userId: U_JURE1, permissions: [], scopedResourceIds: [],
    });
    expect(a.can('read', 'event')).toBe(false);
    expect(a.can('publish', 'event')).toBe(false);
  });

  it('ignore une permission malformée sans planter', () => {
    const a = buildAbility({
      tenantId: T_A, userId: U_ORGA,
      permissions: ['sansaction', '', 'event.'], scopedResourceIds: [],
    });
    expect(a.rules.length).toBe(0);
  });
});

describe('T3.9 — chargement depuis la base', () => {
  it("charge les permissions et la portée d'un juré", async () => {
    const ctx = await loadAbilityContext(admin, T_A, U_JURE1);
    expect(ctx.permissions.sort()).toEqual(['score.create', 'score.read.own']);
    expect(ctx.scopedResourceIds).toEqual([EV_1]);
  });

  it("charge celles d'un organisateur", async () => {
    const ctx = await loadAbilityContext(admin, T_A, U_ORGA);
    expect(ctx.permissions).toContain('event.publish');
    expect(ctx.permissions).toContain('score.read.all');
  });

  it('rend vide dans un AUTRE tenant', async () => {
    const ctx = await loadAbilityContext(admin, T_B, U_ORGA);
    expect(ctx.permissions).toHaveLength(0);
    const a = buildAbility(ctx);
    expect(a.can('publish', 'event')).toBe(false);
  });

  it('ignore les permissions obsolètes', async () => {
    await sql`update permission set obsolete_le = now() where code = 'event.publish'`
      .execute(admin);
    const ctx = await loadAbilityContext(admin, T_A, U_ORGA);
    expect(ctx.permissions).not.toContain('event.publish');
    await sql`update permission set obsolete_le = null where code = 'event.publish'`
      .execute(admin);
  });

  it('RÉVOCATION IMMÉDIATE : sans cache ni jeton', async () => {
    const before = buildAbility(await loadAbilityContext(admin, T_A, U_ORGA));
    // Interrogé sur un TYPE sans instance, CASL rend true dès qu'une règle
    // existe — il ne peut pas évaluer une condition sans objet. La vérification
    // utile porte donc toujours sur une INSTANCE.
    expect(before.can('publish', { id: EV_1, __caslSubjectType__: 'event' } as never)).toBe(true);
    expect(before.can('publish', { id: EV_2, __caslSubjectType__: 'event' } as never)).toBe(false);

    await sql`alter table appartenance no force row level security`.execute(admin);
    await sql`delete from appartenance where utilisateur_id = ${U_ORGA}`.execute(admin);
    await sql`alter table appartenance force row level security`.execute(admin);

    const after = buildAbility(await loadAbilityContext(admin, T_A, U_ORGA));
    expect(after.can('publish', { id: EV_1, __caslSubjectType__: 'event' } as never)).toBe(false);
  });
});

describe('T3.9 — assertCan et messages de refus', () => {
  it('passe quand l’action est permise', async () => {
    const a = buildAbility(await loadAbilityContext(admin, T_A, U_ORGA));
    expect(() => assertCan(a, 'publish', 'event', { id: EV_1 })).not.toThrow();
  });

  it('distingue « aucune permission » de « hors portée »', async () => {
    const a = buildAbility(await loadAbilityContext(admin, T_A, U_JURE1));

    // Aucune permission du tout sur `event`
    try {
      assertCan(a, 'publish', 'event');
      throw new Error('aurait dû échouer');
    } catch (e) {
      expect(e).toBeInstanceOf(ForbiddenError);
      expect((e as ForbiddenError).reason).toContain('aucune permission');
    }

    // Permission existante, mais pas sur cette ressource
    try {
      assertCan(a, 'read', 'score', { ownerId: U_JURE2 });
      throw new Error('aurait dû échouer');
    } catch (e) {
      expect(e).toBeInstanceOf(ForbiddenError);
      expect((e as ForbiddenError).reason).toContain('la permission existe');
    }
  });

  it('le message dit quoi vérifier', async () => {
    const a = buildAbility(await loadAbilityContext(admin, T_A, U_JURE1));
    try {
      assertCan(a, 'publish', 'event');
    } catch (e) {
      expect((e as Error).message).toContain('refusée');
      expect((e as Error).message).toContain('Vérifiez les permissions du rôle');
    }
  });
});

describe('T3.9 — LE test : deux barrières indépendantes', () => {
  it('un juré ne lit pas les notes d’un autre — refusé par CASL', async () => {
    const a = buildAbility(await loadAbilityContext(admin, T_A, U_JURE1));

    // Sa note : autorisée.
    expect(() =>
      assertCan(a, 'read', 'score', { ownerId: U_JURE1 }),
    ).not.toThrow();

    // Celle du juré 2, MÊME tenant, MÊME évènement : refusée.
    expect(() =>
      assertCan(a, 'read', 'score', { ownerId: U_JURE2 }),
    ).toThrow(ForbiddenError);
  });

  it('… et refusé par la RLS, indépendamment de CASL', async () => {
    // Table de notes minimale, avec la policy de visibilité du métier.
    await sql`drop table if exists note_jury cascade`.execute(admin);
    await sql`create table note_jury (
      id uuid primary key default gen_random_uuid(),
      tenant_id uuid not null,
      jure_id uuid not null,
      total numeric(6,2)
    )`.execute(admin);
    await sql`alter table note_jury owner to app_migration`.execute(admin);
    await sql`insert into note_jury (tenant_id, jure_id, total) values
      (${T_A}, ${U_JURE1}, 15.50), (${T_A}, ${U_JURE2}, 18.00)`.execute(admin);

    await sql`alter table note_jury enable row level security`.execute(admin);
    await sql`alter table note_jury force row level security`.execute(admin);
    await sql`grant select on note_jury to app_runtime`.execute(admin);
    await sql`create policy base on note_jury for all to app_runtime
              using (true) with check (true)`.execute(admin);
    await sql`create policy tenant_iso on note_jury as restrictive
              using (tenant_id = (select nullif(current_setting('app.tenant', true),'')::uuid))`
      .execute(admin);
    await sql`create policy own_only on note_jury as restrictive for select
              using (jure_id = (select nullif(current_setting('app.user', true),'')::uuid))`
      .execute(admin);

    const runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime, 1);
    try {
      const rows = await runtime.transaction().execute(async (trx) => {
        await sql`select set_config('app.tenant', ${T_A}, true)`.execute(trx);
        await sql`select set_config('app.user', ${U_JURE1}, true)`.execute(trx);
        return trx.selectFrom('note_jury').select(['jure_id', 'total']).execute();
      });

      // La base elle-même ne rend qu'une ligne : celle du juré 1.
      expect(rows).toHaveLength(1);
      expect(rows[0].jure_id).toBe(U_JURE1);
      expect(Number(rows[0].total)).toBe(15.5);
    } finally {
      await runtime.destroy();
      await sql`drop table if exists note_jury cascade`.execute(admin);
    }
  });

  it('CASL oublié : la RLS rattrape quand même', async () => {
    // Le cas qui justifie les deux barrières — un garde oublié sur une route.
    await sql`drop table if exists note_jury cascade`.execute(admin);
    await sql`create table note_jury (
      id uuid primary key default gen_random_uuid(),
      tenant_id uuid not null, jure_id uuid not null, total numeric(6,2)
    )`.execute(admin);
    await sql`alter table note_jury owner to app_migration`.execute(admin);
    await sql`insert into note_jury (tenant_id, jure_id, total) values
      (${T_A}, ${U_JURE1}, 15.50), (${T_A}, ${U_JURE2}, 18.00)`.execute(admin);
    await sql`alter table note_jury enable row level security`.execute(admin);
    await sql`alter table note_jury force row level security`.execute(admin);
    await sql`grant select on note_jury to app_runtime`.execute(admin);
    await sql`create policy base on note_jury for all to app_runtime
              using (true) with check (true)`.execute(admin);
    await sql`create policy own_only on note_jury as restrictive for select
              using (jure_id = (select nullif(current_setting('app.user', true),'')::uuid))`
      .execute(admin);

    const runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime, 1);
    try {
      // AUCUNE vérification CASL ici : on interroge directement.
      const rows = await runtime.transaction().execute(async (trx) => {
        await sql`select set_config('app.tenant', ${T_A}, true)`.execute(trx);
        await sql`select set_config('app.user', ${U_JURE1}, true)`.execute(trx);
        return trx.selectFrom('note_jury').selectAll().execute();
      });
      expect(rows).toHaveLength(1); // la fuite n'a pas lieu
    } finally {
      await runtime.destroy();
      await sql`drop table if exists note_jury cascade`.execute(admin);
    }
  });
});
