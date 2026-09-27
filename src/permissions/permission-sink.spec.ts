/**
 * L6-3 — démarrage CONCURRENT de plusieurs instances.
 *
 * Chaque instance synchronise le catalogue au démarrage : elle lit les codes
 * connus, puis insère ceux qui manquent. Deux instances qui démarrent ensemble
 * lisent le même état, et la seconde insertion heurtait l'index unique de
 * `permission.code` (23505) : le démarrage de l'instance échouait.
 */
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { PoolDeTest } from '../fixtures/pool-test.js';
import { runMigrations } from '../migrations/runner.js';
import { PermissionSink } from './permission-sink.js';

const { Client } = pg;
const DB = 'tenancy_sink_concurrent_test';
const CREDENTIALS = { runtime: 'test_runtime_pwd', auth: 'test_auth_pwd' };

function mkDb(user: string, password: string, max = 2) {
  return new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new PoolDeTest({
        host: '127.0.0.1',
        port: 55432,
        database: DB,
        user,
        password,
        max,
      }),
    }),
  });
}

async function postgres<T>(f: (c: pg.Client) => Promise<T>): Promise<T> {
  const c = new Client({
    host: '127.0.0.1',
    port: 55432,
    database: 'postgres',
    user: 'postgres',
    password: 'probe',
  });
  await c.connect();
  try {
    return await f(c);
  } finally {
    await c.end();
  }
}

let admin: Kysely<any> | undefined;

beforeAll(async () => {
  await postgres(async (c) => {
    await c.query(`drop database if exists ${DB} with (force)`);
    await c.query(`create database ${DB}`);
  });
  admin = mkDb('postgres', 'probe', 3);
  await runMigrations(admin, { credentials: CREDENTIALS, verify: false });
  // Le consommateur choisit une connexion de publication distincte du métier.
  await sql`grant usage on schema public to app_auth`.execute(admin);
  await sql`grant select, insert, update on permission to app_auth`.execute(admin);
  await sql`grant select on role_permission to app_auth`.execute(admin);
}, 60_000);

afterAll(async () => {
  await admin?.destroy();
  await postgres((c) => c.query(`drop database if exists ${DB} with (force)`));
});

describe('L6-3 — synchronisation idempotente sous démarrage concurrent', () => {
  it('six instances qui synchronisent ensemble le même catalogue réussissent toutes', async () => {
    // Un pool PAR instance, sous le rôle de l'application : de vraies sessions
    // distinctes, qui lisent toutes « rien de connu » avant d'insérer.
    const instances = Array.from({ length: 6 }, () =>
      mkDb('app_auth', CREDENTIALS.auth, 1),
    );
    const catalogue = {
      permissions: Array.from({ length: 60 }, (_, i) => ({
        key: `concurrent.p${String(i).padStart(2, '0')}`,
      })),
    };
    try {
      const bilans = await Promise.allSettled(
        instances.map((db) => new PermissionSink(db).sync(catalogue)),
      );
      const echecs = bilans.flatMap((b) =>
        b.status === 'rejected' ? [String((b.reason as Error).message)] : [],
      );
      expect(echecs).toEqual([]);

      // Chaque code n'est compté « ajouté » que par l'instance qui l'a inséré.
      const ajoutes = bilans.flatMap((b) =>
        b.status === 'fulfilled' ? b.value.added : [],
      );
      expect([...ajoutes].sort()).toEqual(catalogue.permissions.map((p) => p.key));
    } finally {
      await Promise.all(instances.map((db) => db.destroy()));
    }

    const n = await sql<{ n: number }>`
      select count(*)::int as n from permission where code like 'concurrent.%'
    `.execute(admin!);
    expect(n.rows[0].n).toBe(60);
  });
});
