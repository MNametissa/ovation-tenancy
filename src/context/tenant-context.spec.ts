/**
 * Tests du contexte de tenant, contre PostgreSQL réel.
 *
 * Le test central est celui de la RÉUTILISATION DE CONNEXION : c'est le seul
 * moyen d'attraper une fuite de variable de session, et elle n'apparaît
 * jamais en test séquentiel naïf.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Test } from '@nestjs/testing';
import { ClsModule, ClsService } from 'nestjs-cls';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { runMigrations } from '../migrations/runner.js';
import { CLS_TENANT, CLS_USER } from './tenant-context.js';
import { MSG, type TenancyLogger } from '../logging.js';

const { Pool, Client } = pg;
const DB = 'tenancy_ctx_test';

const CREDENTIALS = {
  migration: 'test_migration_pwd',
  runtime: 'test_runtime_pwd',
  auth: 'test_auth_pwd',
};

const T_A = '11111111-1111-1111-1111-111111111111';
const T_B = '22222222-2222-2222-2222-222222222222';
const U_1 = 'aaaaaaaa-0000-0000-0000-000000000001';

function mkDb(database: string, user: string, password: string, max = 1) {
  return new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new Pool({ host: '127.0.0.1', port: 55432, database, user, password, max }),
    }),
  });
}

function mkLogger() {
  const warns: string[] = [];
  const errors: string[] = [];
  const debugs: string[] = [];
  const logger: TenancyLogger = {
    error: (m) => errors.push(m),
    warn: (m) => warns.push(m),
    log: () => {},
    debug: (m) => debugs.push(m),
  };
  return { logger, warns, errors, debugs };
}

let admin: Kysely<any>;
let runtime: Kysely<any>;

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

  // Deux tenants et un utilisateur, insérés en levant FORCE.
  await sql`alter table tenant no force row level security`.execute(admin);
  await sql`alter table appartenance no force row level security`.execute(admin);
  await sql`insert into tenant (id, slug, nom, pays) values
    (${T_A}, 'a', 'Tenant A', 'CM'), (${T_B}, 'b', 'Tenant B', 'CM')`.execute(admin);
  await sql`insert into utilisateur (id, auth_sub, email) values
    (${U_1}, 'sub-1', 'u1@test.cm')`.execute(admin);
  await sql`alter table tenant force row level security`.execute(admin);
  await sql`alter table appartenance force row level security`.execute(admin);

  // Pool à UNE connexion : garantit la réutilisation, donc révèle les fuites.
  runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime, 1);
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

/** Pose le contexte à la main, comme le fera l'intercepteur. */
async function withScope<T>(
  tenantId: string | null,
  userId: string | null,
  fn: (trx: Kysely<any>) => Promise<T>,
): Promise<T> {
  return runtime.transaction().execute(async (trx) => {
    if (tenantId) await sql`select set_config('app.tenant', ${tenantId}, true)`.execute(trx);
    if (userId) await sql`select set_config('app.user', ${userId}, true)`.execute(trx);
    return fn(trx);
  });
}

describe('contexte de tenant — isolation', () => {
  it('avec contexte : ne voit que son tenant', async () => {
    const rows = await withScope(T_A, U_1, (trx) =>
      trx.selectFrom('tenant').select(['id']).execute(),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(T_A);
  });

  it('LE test : aucune fuite entre requêtes sur la MÊME connexion', async () => {
    // Pool max=1 : la connexion est forcément réutilisée. C'est le seul
    // montage qui révèle une variable de session résiduelle.
    for (let i = 0; i < 20; i++) {
      const tenant = i % 2 === 0 ? T_A : T_B;
      const rows = await withScope(tenant, U_1, (trx) =>
        trx.selectFrom('tenant').select(['id']).execute(),
      );
      expect(rows).toHaveLength(1);
      expect(rows[0].id).toBe(tenant);
    }
  });

  it('sans contexte : 0 ligne, PAS une exception', async () => {
    const rows = await runtime.selectFrom('tenant').select(['id']).execute();
    expect(rows).toHaveLength(0);
  });

  it('le contexte expire au COMMIT', async () => {
    await withScope(T_A, U_1, async () => {});
    const residu = await sql<{ v: string }>`
      select coalesce(current_setting('app.tenant', true), '') as v
    `.execute(runtime);
    expect(residu.rows[0].v).toBe('');
  });

  it('transaction SANS contexte : échec fermé', async () => {
    const rows = await runtime
      .transaction()
      .execute((trx) => trx.selectFrom('tenant').select(['id']).execute());
    expect(rows).toHaveLength(0);
  });

  it('le contexte tient sur plusieurs requêtes de la même transaction', async () => {
    const out = await withScope(T_A, U_1, async (trx) => {
      const a = await trx.selectFrom('tenant').select(['id']).execute();
      const b = await trx.selectFrom('tenant').select(['id']).execute();
      return [a.length, b.length];
    });
    expect(out).toEqual([1, 1]);
  });
});

describe('messages destinés au développeur', () => {
  it('chaque message dit CE QUI manque et COMMENT corriger', () => {
    // La règle : ce qui s'est passé, pourquoi, et l'action corrective.
    const cases: Array<[string, string[]]> = [
      [MSG.noTransaction('listTenants'), ['AUCUNE ligne', '@Transactional']],
      [MSG.noTenantContext('listTenants'), ['AUCUNE ligne', 'TenantContext.run']],
      [MSG.noUserContext('listScores'), ['INTRA-tenant', 'app.user']],
      [MSG.rlsWithoutPolicy('note'), ['vide pour tous', 'permissive']],
      [MSG.missingForce('note'), ['CONTOURNE', 'ALTER TABLE']],
      [MSG.unsafeRole('app', 'a BYPASSRLS'), ['contourne', 'NOBYPASSRLS']],
      [MSG.forceLeftDisabled(['a', 'b']), ['exposées', 'ALTER TABLE']],
      [MSG.migrationOutsideTransaction(), ['exposées', 'withRlsDisabled']],
    ];
    for (const [message, musts] of cases) {
      for (const m of musts) {
        expect(message).toContain(m);
      }
      // Un message qui n'indique pas quoi faire finit ignoré.
      expect(message.length).toBeGreaterThan(80);
    }
  });

  it('les messages nomment l’opération concernée', () => {
    expect(MSG.noTenantContext('publierEvenement')).toContain('publierEvenement');
    expect(MSG.noTransaction('publierEvenement')).toContain('publierEvenement');
  });
});

describe('CLS — propagation du contexte', () => {
  it('le contexte survit aux appels asynchrones imbriqués', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [ClsModule.forRoot({ global: true, middleware: { mount: false } })],
    }).compile();
    const cls = moduleRef.get(ClsService);

    const seen: Array<string | undefined> = [];
    await cls.run(async () => {
      cls.set(CLS_TENANT, T_A);
      cls.set(CLS_USER, U_1);
      seen.push(cls.get(CLS_TENANT));
      await new Promise((r) => setTimeout(r, 5));
      seen.push(cls.get(CLS_TENANT)); // après une attente
      await Promise.all([
        (async () => seen.push(cls.get(CLS_TENANT)))(),
        (async () => seen.push(cls.get(CLS_USER)))(),
      ]);
    });

    expect(seen).toEqual([T_A, T_A, T_A, U_1]);
    await moduleRef.close();
  });

  it('deux contextes concurrents ne se mélangent pas', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [ClsModule.forRoot({ global: true, middleware: { mount: false } })],
    }).compile();
    const cls = moduleRef.get(ClsService);

    const [a, b] = await Promise.all([
      cls.run(async () => {
        cls.set(CLS_TENANT, T_A);
        await new Promise((r) => setTimeout(r, 10));
        return cls.get(CLS_TENANT);
      }),
      cls.run(async () => {
        cls.set(CLS_TENANT, T_B);
        await new Promise((r) => setTimeout(r, 5));
        return cls.get(CLS_TENANT);
      }),
    ]);

    expect(a).toBe(T_A);
    expect(b).toBe(T_B);
    await moduleRef.close();
  });

  it('hors contexte CLS, la lecture ne plante pas', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [ClsModule.forRoot({ global: true, middleware: { mount: false } })],
    }).compile();
    const cls = moduleRef.get(ClsService);
    expect(cls.isActive()).toBe(false);
    await moduleRef.close();
  });
});
