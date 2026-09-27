/** Harnais commun aux tests du journal et du catalogue ; une base par suite. */
import { beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { PoolDeTest } from './pool-test.js';
import { runMigrations } from '../migrations/runner.js';
import type { TenancyLogger } from '../logging.js';
const { Client } = pg;
export let DB: string;

export const CREDENTIALS = {
  runtime: 'test_runtime_pwd',
  auth: 'test_auth_pwd',
};

export const T_A = '11111111-1111-1111-1111-111111111111';
export const U_1 = 'aaaaaaaa-0000-0000-0000-000000000001';

export function mkDb(database: string, user: string, password: string, max = 2) {
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

export function mkLogger() {
  const warns: string[] = [];
  const errors: string[] = [];
  const logs: string[] = [];
  const logger: TenancyLogger = {
    error: (m) => errors.push(m),
    warn: (m) => warns.push(m),
    log: (m) => logs.push(m),
    debug: () => {},
  };
  return { logger, warns, errors, logs };
}

export let admin: Kysely<any>;
export let runtime: Kysely<any>;

export function installerBancAudit(nom: string): void {
  DB = nom;
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
    runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime, 2);
  });

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
  });

  beforeEach(async () => {
    for (const t of [
      'journal_audit',
      'appartenance',
      'role_permission',
      'role',
      'tenant',
      'utilisateur',
    ]) {
      await sql.raw(`alter table ${t} no force row level security`).execute(admin);
    }
    // journal_audit porte des règles DO INSTEAD NOTHING : on les lève le temps
    // du nettoyage, puis on les repose. C'est justement ce que les tests
    // d'immuabilité vérifieront ensuite.
    await sql`drop rule if exists journal_no_delete on journal_audit`.execute(admin);
    await sql`delete from journal_audit`.execute(admin);
    await sql`create rule journal_no_delete as on delete to journal_audit do instead nothing`.execute(
      admin,
    );

    await sql`delete from appartenance`.execute(admin);
    await sql`delete from role_permission`.execute(admin);
    await sql`delete from role`.execute(admin);
    await sql`delete from tenant`.execute(admin);
    await sql`delete from utilisateur`.execute(admin);
    await sql`delete from permission`.execute(admin);

    await sql`insert into tenant (id, slug, nom)
            values (${T_A}, 'a', 'Tenant A')`.execute(admin);
    await sql`insert into utilisateur (id, auth_sub, email)
            values (${U_1}, 'sub-1', 'u1@test.cm')`.execute(admin);

    for (const t of [
      'journal_audit',
      'appartenance',
      'role_permission',
      'role',
      'tenant',
      'utilisateur',
    ]) {
      await sql.raw(`alter table ${t} force row level security`).execute(admin);
    }
  });
}
