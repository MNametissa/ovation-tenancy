/**
 * Lot L1 (plan des correctifs du 2026-09-27) — rôles, mots de passe et droits.
 *
 * Chaque test MESURE en base : un privilège lu dans le catalogue, une écriture
 * tentée sous le vrai rôle, une empreinte de mot de passe relue dans
 * `pg_authid`. Base dédiée, migrée une fois.
 */
import { describe, it, expect, beforeAll, afterAll, jest } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { PoolDeTest } from '../fixtures/pool-test.js';
import { runMigrations, MIGRATIONS } from './runner.js';
import { TEST_CREDENTIALS } from '../test-globals.js';

const DB = 'tenancy_durcissement_test';
const T_A = '11111111-0000-0000-0000-00000000000a';
const T_B = '11111111-0000-0000-0000-00000000000b';

function mkDb(user = 'postgres', password = 'probe') {
  return new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new PoolDeTest({
        host: '127.0.0.1',
        port: 55432,
        database: DB,
        user,
        password,
        max: 3,
      }),
    }),
  });
}

async function superuser(requete: string): Promise<void> {
  const c = new pg.Client({
    host: '127.0.0.1',
    port: 55432,
    database: 'postgres',
    user: 'postgres',
    password: 'probe',
  });
  await c.connect();
  try {
    await c.query(requete);
  } finally {
    await c.end();
  }
}

let admin: Kysely<any>;
let runtime: Kysely<any>;

beforeAll(async () => {
  await superuser(`drop database if exists ${DB} with (force)`);
  await superuser(`create database ${DB}`);
  admin = mkDb();
  await runMigrations(admin, { credentials: TEST_CREDENTIALS });
  runtime = mkDb('app_runtime', TEST_CREDENTIALS.runtime);
  await sql`insert into tenant (id, slug, nom)
            values (${T_A}, 'a', 'A'), (${T_B}, 'b', 'B')`.execute(admin);
});

afterAll(async () => {
  await runtime.destroy();
  await admin.destroy();
  await superuser(`drop database if exists ${DB} with (force)`);
});

/** Transaction sous app_runtime, tenant courant posé comme le fait l'intercepteur. */
function sousTenant<T>(tenant: string, fn: (trx: Kysely<any>) => Promise<T>) {
  return runtime.transaction().execute(async (trx) => {
    await sql`select set_config('app.tenant', ${tenant}, true)`.execute(trx);
    return fn(trx);
  });
}

const empreinte = async (role: string) =>
  (
    await sql<{
      p: string;
    }>`select rolpassword as p from pg_authid where rolname = ${role}`.execute(admin)
  ).rows[0].p;

describe('L1-8 — mot de passe d’un rôle EXISTANT', () => {
  // Les rôles sont GLOBAUX AU CLUSTER : réécrire un mot de passe casse les
  // autres bases du serveur. SCRAM sale chaque empreinte : poser la MÊME
  // valeur change quand même `rolpassword`, ce qui rend l'écriture visible
  // sans perturber les suites parallèles.
  it('une migration ne réécrit PAS le mot de passe d’un rôle existant', async () => {
    const avant = await empreinte('app_runtime');
    const avantAuth = await empreinte('app_auth');
    // Rejoue la seule migration 001, sur des rôles déjà présents.
    await sql`delete from tenancy_migrations where name = '001-roles'`.execute(admin);
    await runMigrations(admin, { credentials: TEST_CREDENTIALS, verify: false });
    expect(await empreinte('app_runtime')).toBe(avant);
    expect(await empreinte('app_auth')).toBe(avantAuth);
  });

  it.each([false, true])(
    'transmet la rotation explicite, 001 déjà appliquée : %s',
    async (deja) => {
      // Les rôles partagés ne sont jamais réécrits par les tests : on observe
      // la délégation au pilote, dont la rotation est testée sur un rôle jetable.
      if (!deja)
        await sql`delete from tenancy_migrations where name = '001-roles'`.execute(
          admin,
        );
      const pilote = jest.spyOn(MIGRATIONS[0], 'up').mockResolvedValue(undefined);
      try {
        await runMigrations(admin, {
          credentials: TEST_CREDENTIALS,
          verify: false,
          realignerMotsDePasse: true,
        });
        expect(pilote).toHaveBeenCalledWith(
          expect.anything(),
          TEST_CREDENTIALS,
          undefined,
          { realignerMotsDePasse: true },
        );
      } finally {
        pilote.mockRestore();
      }
    },
  );
});

describe('L1-4 — droits d’app_runtime sur le catalogue global', () => {
  const droit = async (table: string, privilege: string) =>
    (
      await sql<{
        ok: boolean;
      }>`select has_table_privilege('app_runtime', ${table}, ${privilege}) as ok`.execute(
        admin,
      )
    ).rows[0].ok;

  it.each([
    ['utilisateur', 'INSERT'],
    ['utilisateur', 'UPDATE'],
    ['utilisateur', 'DELETE'],
    ['permission', 'DELETE'],
    ['permission', 'INSERT'],
    ['permission', 'UPDATE'],
    ['tenant', 'INSERT'],
    ['tenant', 'DELETE'],
  ])('%s : %s révoqué', async (table, privilege) => {
    expect(await droit(table, privilege)).toBe(false);
  });

  it.each([
    ['utilisateur', 'SELECT'],
    ['permission', 'SELECT'],
    ['tenant', 'SELECT'],
    ['tenant', 'UPDATE'],
  ])('%s : %s conservé (utilisé par le code)', async (table, privilege) => {
    expect(await droit(table, privilege)).toBe(true);
  });

  it('une création de tenant sous app_runtime est REFUSÉE', async () => {
    await expect(
      sousTenant(T_A, (trx) =>
        sql`insert into tenant (slug, nom) values ('x', 'X')`.execute(trx),
      ),
    ).rejects.toThrow(/permission denied/);
  });
});

describe('L1-5 — rôle à tenant_id nul', () => {
  it('un tenant ne crée PAS de rôle sans tenant (WITH CHECK)', async () => {
    await expect(
      sousTenant(T_A, (trx) =>
        sql`insert into role (tenant_id, code, libelle) values (null, 'global', 'G')`.execute(
          trx,
        ),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it('un tenant crée toujours un rôle À LUI', async () => {
    await sousTenant(T_A, (trx) =>
      sql`insert into role (tenant_id, code, libelle) values (${T_A}, 'propre', 'P')`.execute(
        trx,
      ),
    );
  });

  it('un tenant ne crée PAS de rôle pour un autre tenant', async () => {
    await expect(
      sousTenant(T_A, (trx) =>
        sql`insert into role (tenant_id, code, libelle) values (${T_B}, 'autre', 'O')`.execute(
          trx,
        ),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it('les rôles système restent visibles de tous', async () => {
    await sql`insert into role (tenant_id, code, libelle, systeme)
              values (null, 'sys_visible', 'S', true)`.execute(admin);
    const r = await sousTenant(T_B, (trx) =>
      sql<{
        n: number;
      }>`select count(*)::int as n from role where code = 'sys_visible'`.execute(trx),
    );
    expect(r.rows[0].n).toBe(1);
  });

  it('CHECK : tenant_id nul ⇔ système — même pour le propriétaire', async () => {
    await expect(
      sql`insert into role (tenant_id, code, libelle, systeme)
          values (null, 'faux_global', 'F', false)`.execute(admin),
    ).rejects.toThrow(/role_systeme_tenant_nul/);
    await expect(
      sql`insert into role (tenant_id, code, libelle, systeme)
          values (${T_A}, 'faux_systeme', 'F', true)`.execute(admin),
    ).rejects.toThrow(/role_systeme/);
  });
});

describe('L1-10 — app_migration ne détient RIEN dans la base', () => {
  // Décision : le propriétaire des objets est le rôle d'administration qui
  // exécute `migrate`. `app_migration` n'était ni propriétaire ni utilisé :
  // un mot de passe et des droits sans usage, retirés.
  it('ni droit sur le schéma, ni sur les fonctions, ni privilège par défaut', async () => {
    const r = await sql<{
      existe: boolean;
      create: boolean;
      exec: boolean;
      defauts: number;
    }>`
      select exists (select 1 from pg_roles where rolname = 'app_migration') as existe,
             coalesce((select has_schema_privilege(oid, 'public', 'CREATE')
                       from pg_roles where rolname = 'app_migration'), false) as create,
             coalesce((select has_function_privilege(oid, 'app_a_permission(text)', 'EXECUTE')
                       from pg_roles where rolname = 'app_migration'), false) as exec,
             (select count(*)::int from pg_default_acl d join pg_roles r on r.oid = d.defaclrole
              where r.rolname = 'app_migration') as defauts
    `.execute(admin);
    const { create, exec, defauts } = r.rows[0];
    expect({ create, exec, defauts }).toEqual({
      create: false,
      exec: false,
      defauts: 0,
    });
  });

  it('ne possède aucun objet', async () => {
    const r = await sql<{ n: number }>`
      select count(*)::int as n from pg_class c join pg_roles r on r.oid = c.relowner
      where r.rolname = 'app_migration'
    `.execute(admin);
    expect(r.rows[0].n).toBe(0);
  });
});
