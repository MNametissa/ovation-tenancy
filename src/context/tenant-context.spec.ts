/**
 * Tests du contexte de tenant, contre PostgreSQL réel.
 *
 * Le test central est celui de la RÉUTILISATION DE CONNEXION : c'est le seul
 * moyen d'attraper une fuite de variable de session, et elle n'apparaît
 * jamais en test séquentiel naïf.
 */
import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
} from '@jest/globals';
import { Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { ClsModule, ClsService } from 'nestjs-cls';
import { ClsPluginTransactional } from '@nestjs-cls/transactional';
import { TransactionalAdapterKysely } from '@nestjs-cls/transactional-adapter-kysely';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { PoolDeTest } from '../fixtures/pool-test.js';
import { runMigrations } from '../migrations/runner.js';
import { CLS_TENANT, CLS_USER, TenantContext } from './tenant-context.js';
import { MSG, TENANCY_LOGGER, type TenancyLogger } from '../logging.js';

/** Jeton du Kysely fourni à l'adaptateur transactionnel. */
const KYSELY = Symbol('KYSELY');

/**
 * Module exportant le Kysely, pour le plugin transactionnel.
 *
 * `useFactory` et non `useValue` : `runtime` n'est assigné qu'en `beforeAll`,
 * donc la valeur doit être lue au moment de l'instanciation.
 */
@Module({
  providers: [{ provide: KYSELY, useFactory: () => runtime }],
  exports: [KYSELY],
})
class DbModule {}

const { Client } = pg;
const DB = 'tenancy_ctx_test';

const CREDENTIALS = {
  runtime: 'test_runtime_pwd',
  auth: 'test_auth_pwd',
};

const T_A = '11111111-1111-1111-1111-111111111111';
const T_B = '22222222-2222-2222-2222-222222222222';
const U_1 = 'aaaaaaaa-0000-0000-0000-000000000001';

function mkDb(database: string, user: string, password: string, max = 1) {
  return new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new PoolDeTest({
        host: '127.0.0.1',
        port: 55432,
        database,
        user,
        password,
        max,
      }),
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
    host: '127.0.0.1',
    port: 55432,
    database: 'postgres',
    user: 'postgres',
    password: 'probe',
  });
  await c.connect();
  await c.query(`drop database if exists ${DB} with (force)`);
  await c.query(`create database ${DB}`);
  await c.end();

  admin = mkDb(DB, 'postgres', 'probe', 3);
  await runMigrations(admin, { credentials: CREDENTIALS, verify: false });

  // Deux tenants et un utilisateur, insérés en levant FORCE.
  await sql`alter table tenant no force row level security`.execute(admin);
  await sql`alter table appartenance no force row level security`.execute(admin);
  await sql`insert into tenant (id, slug, nom) values
    (${T_A}, 'a', 'Tenant A'), (${T_B}, 'b', 'Tenant B')`.execute(admin);
  await sql`insert into utilisateur (id, auth_sub, email) values
    (${U_1}, 'sub-1', 'u1@test.cm')`.execute(admin);
  await sql`alter table tenant force row level security`.execute(admin);
  await sql`alter table appartenance force row level security`.execute(admin);

  // Pool à UNE connexion : garantit la réutilisation, donc révèle les fuites.
  runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime, 1);
});

// Timeout explicite : cette suite monte des modules NestJS complets, et le
// `drop database` final attend la fermeture des pools. MESURÉ : seule elle
// passe en 8,9 s, mais sous le parallélisme des 8 suites le crochet dépassait
// les 5 s par défaut de Jest — 134 tests verts et une suite « failed to run ».
afterAll(async () => {
  await runtime.destroy();
  await admin.destroy();
  const c = new Client({
    host: '127.0.0.1',
    port: 55432,
    database: 'postgres',
    user: 'postgres',
    password: 'probe',
  });
  await c.connect();
  await c.query(`drop database if exists ${DB} with (force)`);
  await c.end();
}, 30_000);

/** Pose le contexte à la main, comme le fera l'intercepteur. */
async function withScope<T>(
  tenantId: string | null,
  userId: string | null,
  fn: (trx: Kysely<any>) => Promise<T>,
): Promise<T> {
  return runtime.transaction().execute(async (trx) => {
    if (tenantId)
      await sql`select set_config('app.tenant', ${tenantId}, true)`.execute(trx);
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

/**
 * La CLASSE TenantContext, montée comme une application le fera.
 *
 * Les tests ci-dessus prouvent le comportement de PostgreSQL et du CLS, mais
 * en posant `set_config` à la main. Ils ne touchaient donc jamais le code que
 * l'application appelle réellement — `applyToTransaction`, `withContext`,
 * `assertInTransaction`. Une garantie mesurée sur la base n'est pas une
 * garantie mesurée sur le code qui l'utilise.
 */
describe('TenantContext — la classe', () => {
  let moduleRef: Awaited<
    ReturnType<ReturnType<typeof Test.createTestingModule>['compile']>
  >;
  let ctx: TenantContext;
  let logs: ReturnType<typeof mkLogger>;

  beforeEach(async () => {
    logs = mkLogger();
    moduleRef = await Test.createTestingModule({
      imports: [
        ClsModule.forRoot({
          global: true,
          middleware: { mount: false },
          plugins: [
            new ClsPluginTransactional({
              // Le plugin est un module isolé : le jeton doit lui être fourni
              // par son propre `imports`, pas depuis le module de test.
              imports: [DbModule],
              adapter: new TransactionalAdapterKysely({ kyselyInstanceToken: KYSELY }),
            }),
          ],
        }),
      ],
      providers: [{ provide: TENANCY_LOGGER, useValue: logs.logger }, TenantContext],
    }).compile();
    await moduleRef.init();
    ctx = moduleRef.get(TenantContext);
  });

  afterEach(async () => {
    await moduleRef.close();
  });

  it('withContext pose le contexte : le tenant se voit lui-même', async () => {
    const rows = await ctx.run({ tenantId: T_A, userId: U_1 }, () =>
      ctx.withContext((trx) => trx.selectFrom('tenant').select(['id']).execute()),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(T_A);
  });

  it('withContext isole : deux tenants successifs, même connexion', async () => {
    for (const t of [T_A, T_B, T_A, T_B]) {
      const rows = await ctx.run({ tenantId: t, userId: U_1 }, () =>
        ctx.withContext((trx) => trx.selectFrom('tenant').select(['id']).execute()),
      );
      expect(rows.map((r: any) => r.id)).toEqual([t]);
    }
  });

  it('run expose tenantId et userId ; hors run ils sont undefined', async () => {
    expect(ctx.tenantId).toBeUndefined();
    expect(ctx.userId).toBeUndefined();

    await ctx.run({ tenantId: T_A, userId: U_1 }, async () => {
      expect(ctx.tenantId).toBe(T_A);
      expect(ctx.userId).toBe(U_1);
    });

    // Le contexte ne survit pas à la sortie du run.
    expect(ctx.tenantId).toBeUndefined();
  });

  it('run sans userId : tenantId posé, userId absent', async () => {
    await ctx.run({ tenantId: T_A }, async () => {
      expect(ctx.tenantId).toBe(T_A);
      expect(ctx.userId).toBeUndefined();
    });
  });

  it('SANS tenant : 0 ligne, et le développeur est AVERTI avec l’action', async () => {
    // L'échec fermé protège la donnée ; l'avertissement évite la chasse au
    // bug. Les deux sont exigés.
    const rows = await ctx.withContext((trx) =>
      trx.selectFrom('tenant').select(['id']).execute(),
    );
    expect(rows).toHaveLength(0);
    expect(logs.warns.some((w) => w.includes('TenantContext.run'))).toBe(true);
    expect(logs.warns.some((w) => w.includes('AUCUNE ligne'))).toBe(true);
  });

  it('tenant SANS utilisateur : contexte posé, mais averti sur app.user', async () => {
    const rows = await ctx.run({ tenantId: T_A }, () =>
      ctx.withContext((trx) => trx.selectFrom('tenant').select(['id']).execute()),
    );
    // Le tenant est bien posé : la lecture fonctionne.
    expect(rows).toHaveLength(1);
    // Mais l'isolation intra-tenant ne s'appliquera pas, et ça doit se savoir.
    expect(logs.warns.some((w) => w.includes('app.user'))).toBe(true);
  });

  it('applyToTransaction nomme l’opération dans l’avertissement', async () => {
    await runtime.transaction().execute(async (trx) => {
      await ctx.applyToTransaction(trx, 'publierEvenement');
    });
    expect(logs.warns.some((w) => w.includes('publierEvenement'))).toBe(true);
  });

  it('applyToTransaction trace le contexte posé en debug, tronqué', async () => {
    await ctx.run({ tenantId: T_A, userId: U_1 }, () =>
      ctx.withContext(async () => {}),
    );
    const d = logs.debugs.find((m) => m.includes('Contexte posé'));
    expect(d).toBeDefined();
    // L'identifiant est tronqué : un log ne doit pas porter l'UUID entier.
    expect(d).toContain(T_A.slice(0, 8));
    expect(d).not.toContain(T_A);
  });

  it('assertInTransaction avertit hors transaction, se taît dedans', async () => {
    ctx.assertInTransaction('listTenants');
    expect(logs.warns.some((w) => w.includes('@Transactional'))).toBe(true);

    const avant = logs.warns.length;
    await ctx.run({ tenantId: T_A, userId: U_1 }, () =>
      ctx.withContext(async () => {
        ctx.assertInTransaction('listTenants');
      }),
    );
    expect(logs.warns.length).toBe(avant);
  });

  it('RÉGRESSION : isTransactionActive est une MÉTHODE, pas un accesseur', () => {
    // Le défaut trouvé : `if (!this.txHost.isTransactionActive)` teste la
    // fonction elle-même — toujours vraie — donc le garde n'avertissait
    // jamais. Un garde muet donne l'illusion d'une protection.
    //
    // On verrouille la forme, pas seulement le comportement : si une
    // bibliothèque future en faisait un accesseur booléen, ce test le dirait
    // avant que le garde ne redevienne muet en silence.
    const th: any = (ctx as any).txHost;
    expect(typeof th.isTransactionActive).toBe('function');
    expect(th.isTransactionActive()).toBe(false);
  });

  it('withContext propage l’erreur ET annule la transaction', async () => {
    await expect(
      ctx.run({ tenantId: T_A, userId: U_1 }, () =>
        ctx.withContext(async () => {
          throw new Error('échec métier');
        }),
      ),
    ).rejects.toThrow('échec métier');

    // La connexion reste utilisable : pas de transaction restée ouverte.
    const rows = await ctx.run({ tenantId: T_A, userId: U_1 }, () =>
      ctx.withContext((trx) => trx.selectFrom('tenant').select(['id']).execute()),
    );
    expect(rows).toHaveLength(1);
  });

  it('le contexte ne fuit pas APRÈS withContext, sur la même connexion', async () => {
    await ctx.run({ tenantId: T_A, userId: U_1 }, () =>
      ctx.withContext(async () => {}),
    );
    const residu = await sql<{ v: string }>`
      select coalesce(current_setting('app.tenant', true), '') as v
    `.execute(runtime);
    expect(residu.rows[0].v).toBe('');
  });

  it('deux run concurrents ne se mélangent pas jusqu’au SQL', async () => {
    // Le vrai régime d'un serveur. Pool max=1 : les transactions sont
    // sérialisées, mais chaque run doit retrouver SON tenant.
    const [a, b] = await Promise.all([
      ctx.run({ tenantId: T_A, userId: U_1 }, () =>
        ctx.withContext((trx) => trx.selectFrom('tenant').select(['id']).execute()),
      ),
      ctx.run({ tenantId: T_B, userId: U_1 }, () =>
        ctx.withContext((trx) => trx.selectFrom('tenant').select(['id']).execute()),
      ),
    ]);
    expect(a.map((r: any) => r.id)).toEqual([T_A]);
    expect(b.map((r: any) => r.id)).toEqual([T_B]);
  });
});
