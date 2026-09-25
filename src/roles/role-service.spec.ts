/**
 * Tests des rôles configurables et de `app_a_permission`, contre PostgreSQL
 * réel.
 *
 * Deux tâches vérifiées ici :
 *   T3.5 — la fonction de permission rend le bon verdict, et ne peut pas être
 *          détournée ;
 *   T3.6 — un rôle créé par un tenant se comporte comme un rôle système, sans
 *          modification de code ni de policy.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { runMigrations } from '../migrations/runner.js';
import { RoleService, SYSTEM_ROLES } from './role-service.js';

const { Pool, Client } = pg;
const DB = 'tenancy_roles_test';

const CREDENTIALS = {
  migration: 'test_migration_pwd',
  runtime: 'test_runtime_pwd',
  auth: 'test_auth_pwd',
};

const T_A = '11111111-1111-1111-1111-111111111111';
const T_B = '22222222-2222-2222-2222-222222222222';
const U_1 = 'aaaaaaaa-0000-0000-0000-000000000001';
const U_2 = 'aaaaaaaa-0000-0000-0000-000000000002';
const EV_1 = 'e1111111-0000-0000-0000-000000000001';

function mkDb(database: string, user: string, password: string, max = 2) {
  return new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new Pool({ host: '127.0.0.1', port: 55432, database, user, password, max }),
    }),
  });
}

let admin: Kysely<any>;
let runtime: Kysely<any>;
let roles: RoleService;

/** Exécute avec le contexte posé, comme le fera l'intercepteur. */
async function asUser<T>(
  tenantId: string,
  userId: string,
  fn: (trx: Kysely<any>) => Promise<T>,
): Promise<T> {
  return runtime.transaction().execute(async (trx) => {
    await sql`select set_config('app.tenant', ${tenantId}, true)`.execute(trx);
    await sql`select set_config('app.user', ${userId}, true)`.execute(trx);
    return fn(trx);
  });
}

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
  runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime, 2);
  roles = new RoleService(admin);
});

afterAll(async () => {
  await runtime.destroy();
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
  for (const t of ['appartenance', 'role_permission', 'role', 'tenant', 'utilisateur']) {
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
    ('score.read.all', 'Lire toutes les notes', 'jury'),
    ('score.read.own', 'Lire ses notes', 'jury'),
    ('audit.read', 'Lire le journal', 'audit')`.execute(admin);

  await sql`insert into tenant (id, slug, nom, pays) values
    (${T_A}, 'a', 'Tenant A', 'CM'), (${T_B}, 'b', 'Tenant B', 'CM')`.execute(admin);
  await sql`insert into utilisateur (id, auth_sub, email) values
    (${U_1}, 'sub-1', 'u1@test.cm'), (${U_2}, 'sub-2', 'u2@test.cm')`.execute(admin);

  await roles.ensureSystemRoles();

  for (const t of ['appartenance', 'role_permission', 'role', 'tenant', 'utilisateur']) {
    await sql.raw(`alter table ${t} force row level security`).execute(admin);
  }
});

describe('T3.6 — rôles système', () => {
  it('installe les sept rôles livrés', async () => {
    const r = await sql<{ n: number }>`
      select count(*)::int as n from role where systeme and tenant_id is null
    `.execute(admin);
    expect(r.rows[0].n).toBe(SYSTEM_ROLES.length);
  });

  it('est idempotent : un second appel ne duplique rien', async () => {
    const created = await roles.ensureSystemRoles();
    expect(created).toHaveLength(0);
  });

  it('les rôles à portée requise sont marqués', async () => {
    const r = await sql<{ code: string }>`
      select code from role where portee_requise and systeme order by code
    `.execute(admin);
    expect(r.rows.map((x) => x.code)).toEqual(['jure', 'organisateur']);
  });

  it('refuse de supprimer un rôle système, et explique pourquoi', async () => {
    await expect(roles.deleteTenantRole(T_A, 'jure')).rejects.toThrow(
      /rôle système .* ne peut pas être supprimé/,
    );
    await expect(roles.deleteTenantRole(T_A, 'jure')).rejects.toThrow(
      /modifier ses permissions|créer un rôle propre/,
    );
  });
});

describe('T3.6 — rôles propres au tenant', () => {
  it('un rôle « coach » se comporte comme un rôle système', async () => {
    const coach = await roles.createTenantRole(T_A, {
      code: 'coach',
      libelle: 'Coach',
      porteeRequise: true,
      permissions: ['score.read.own'],
    });

    expect(coach.systeme).toBe(false);
    expect(coach.porteeRequise).toBe(true);

    // Le trigger de portée s'applique SANS modification de code.
    await sql`alter table appartenance no force row level security`.execute(admin);
    await expect(
      sql`insert into appartenance (tenant_id, utilisateur_id, role_id)
          values (${T_A}, ${U_1}, ${coach.id})`.execute(admin),
    ).rejects.toThrow(/exige une portée/);
    await sql`alter table appartenance force row level security`.execute(admin);
  });

  it('refuse un code en collision avec un rôle système', async () => {
    await expect(
      roles.createTenantRole(T_A, { code: 'jure', libelle: 'X', permissions: [] }),
    ).rejects.toThrow(/rôle système porte déjà le code/);
  });

  it('un rôle du tenant A est invisible du tenant B', async () => {
    await roles.createTenantRole(T_A, {
      code: 'coach', libelle: 'Coach', permissions: [],
    });
    const forB = await roles.listRoles(T_B);
    expect(forB.map((r) => r.code)).not.toContain('coach');
    const forA = await roles.listRoles(T_A);
    expect(forA.map((r) => r.code)).toContain('coach');
  });

  it('refuse une permission inconnue du catalogue, et dit pourquoi', async () => {
    await expect(
      roles.createTenantRole(T_A, {
        code: 'bidon', libelle: 'Bidon', permissions: ['inventee.permission'],
      }),
    ).rejects.toThrow(/inconnue\(s\) du catalogue/);
    await expect(
      roles.createTenantRole(T_A, {
        code: 'bidon2', libelle: 'Bidon', permissions: ['inventee.permission'],
      }),
    ).rejects.toThrow(/ne protège rien/);
  });

  it('refuse de supprimer un rôle attribué, et dit combien', async () => {
    const coach = await roles.createTenantRole(T_A, {
      code: 'coach', libelle: 'Coach', permissions: [],
    });
    await sql`alter table appartenance no force row level security`.execute(admin);
    await sql`insert into appartenance (tenant_id, utilisateur_id, role_id)
              values (${T_A}, ${U_1}, ${coach.id})`.execute(admin);
    await sql`alter table appartenance force row level security`.execute(admin);

    await expect(roles.deleteTenantRole(T_A, 'coach')).rejects.toThrow(
      /attribué à 1 membre/,
    );
  });

  it('supprime un rôle non attribué', async () => {
    await roles.createTenantRole(T_A, {
      code: 'temporaire', libelle: 'Temp', permissions: [],
    });
    await expect(roles.deleteTenantRole(T_A, 'temporaire')).resolves.toBeUndefined();
  });
});

describe('T3.5 — app_a_permission', () => {
  beforeEach(async () => {
    await sql`alter table appartenance no force row level security`.execute(admin);
    const orga = await sql<{ id: string }>`
      select id from role where code = 'organisateur'
    `.execute(admin);
    const jure = await sql<{ id: string }>`select id from role where code = 'jure'`
      .execute(admin);

    await sql`insert into role_permission (role_id, permission_id)
      select ${orga.rows[0].id}, id from permission
      where code in ('event.read.all','score.read.all')
      on conflict do nothing`.execute(admin);
    await sql`insert into role_permission (role_id, permission_id)
      select ${jure.rows[0].id}, id from permission where code = 'score.read.own'
      on conflict do nothing`.execute(admin);

    // U_1 organisateur du tenant A, U_2 juré sur l'évènement EV_1.
    // `organisateur` exige une portée — le trigger le refuserait sans.
    await sql`insert into appartenance (tenant_id, utilisateur_id, role_id, portee_ressource_id)
              values (${T_A}, ${U_1}, ${orga.rows[0].id}, ${EV_1})`.execute(admin);
    await sql`insert into appartenance (tenant_id, utilisateur_id, role_id, portee_ressource_id)
              values (${T_A}, ${U_2}, ${jure.rows[0].id}, ${EV_1})`.execute(admin);
    await sql`alter table appartenance force row level security`.execute(admin);
  });

  it('rend true pour une permission détenue', async () => {
    const r = await asUser(T_A, U_1, (trx) =>
      sql<{ ok: boolean }>`select app_a_permission('event.read.all') as ok`.execute(trx),
    );
    expect(r.rows[0].ok).toBe(true);
  });

  it('rend false pour une permission non détenue', async () => {
    const r = await asUser(T_A, U_2, (trx) =>
      sql<{ ok: boolean }>`select app_a_permission('event.read.all') as ok`.execute(trx),
    );
    expect(r.rows[0].ok).toBe(false);
  });

  it('rend false dans un AUTRE tenant, même utilisateur', async () => {
    // L'appartenance est scopée au tenant : changer de tenant retire les
    // permissions, sans changer d'utilisateur.
    const r = await asUser(T_B, U_1, (trx) =>
      sql<{ ok: boolean }>`select app_a_permission('event.read.all') as ok`.execute(trx),
    );
    expect(r.rows[0].ok).toBe(false);
  });

  it('rend false sans contexte utilisateur', async () => {
    const r = await runtime.transaction().execute(async (trx) => {
      await sql`select set_config('app.tenant', ${T_A}, true)`.execute(trx);
      return sql<{ ok: boolean }>`select app_a_permission('event.read.all') as ok`
        .execute(trx);
    });
    expect(r.rows[0].ok).toBe(false);
  });

  it('ignore une permission marquée obsolète', async () => {
    await sql`update permission set obsolete_le = now() where code = 'event.read.all'`
      .execute(admin);
    const r = await asUser(T_A, U_1, (trx) =>
      sql<{ ok: boolean }>`select app_a_permission('event.read.all') as ok`.execute(trx),
    );
    expect(r.rows[0].ok).toBe(false);
    await sql`update permission set obsolete_le = null where code = 'event.read.all'`
      .execute(admin);
  });

  it('RÉVOCATION IMMÉDIATE : retirer l’appartenance retire la permission', async () => {
    const before = await asUser(T_A, U_1, (trx) =>
      sql<{ ok: boolean }>`select app_a_permission('event.read.all') as ok`.execute(trx),
    );
    expect(before.rows[0].ok).toBe(true);

    await sql`alter table appartenance no force row level security`.execute(admin);
    await sql`delete from appartenance where utilisateur_id = ${U_1}`.execute(admin);
    await sql`alter table appartenance force row level security`.execute(admin);

    // La requête SUIVANTE voit déjà la révocation : pas de cache, pas de jeton.
    const after = await asUser(T_A, U_1, (trx) =>
      sql<{ ok: boolean }>`select app_a_permission('event.read.all') as ok`.execute(trx),
    );
    expect(after.rows[0].ok).toBe(false);
  });

  it('ne peut pas être détournée par le search_path', async () => {
    // Un SECURITY DEFINER sans search_path figé est une porte dérobée : on
    // pourrait créer une table « permission » dans un schéma prioritaire.
    const r = await sql<{ config: string[] }>`
      select proconfig as config from pg_proc where proname = 'app_a_permission'
    `.execute(admin);
    expect(r.rows[0].config.join(',')).toContain('search_path=public, pg_temp');
  });
});
