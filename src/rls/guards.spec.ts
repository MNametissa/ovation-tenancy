/**
 * Tests des six garde-fous RLS.
 *
 * Chaque test CRÉE DÉLIBÉRÉMENT l'anomalie, puis vérifie qu'elle est détectée
 * et que le message dit comment corriger. C'est la règle : un mécanisme de
 * sécurité doit avoir un test qui retire le contrôle.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { auditRls, assertRlsIsSound } from './guards.js';
import { runMigrations } from '../migrations/runner.js';
import type { TenancyLogger } from '../logging.js';

const { Pool, Client } = pg;
const DB = 'tenancy_rls_test';

const CREDENTIALS = {
  migration: 'test_migration_pwd',
  runtime: 'test_runtime_pwd',
  auth: 'test_auth_pwd',
};

function mkDb(database: string, user = 'postgres', password = 'probe') {
  return new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new Pool({
        host: '127.0.0.1',
        port: 55432,
        database,
        user,
        password,
        max: 3,
      }),
    }),
  });
}

function mkLogger() {
  const errors: string[] = [];
  const logs: string[] = [];
  const logger: TenancyLogger = {
    error: (m) => errors.push(m),
    warn: () => {},
    log: (m) => logs.push(m),
    debug: () => {},
  };
  return { logger, errors, logs };
}

let db: Kysely<any>;

beforeAll(async () => {
  const admin = new Client({
    host: '127.0.0.1',
    port: 55432,
    database: 'postgres',
    user: 'postgres',
    password: 'probe',
  });
  await admin.connect();
  await admin.query(`drop database if exists ${DB}`);
  await admin.query(`create database ${DB}`);
  await admin.end();
  db = mkDb(DB);
});

afterAll(async () => {
  await db.destroy();
  const admin = new Client({
    host: '127.0.0.1',
    port: 55432,
    database: 'postgres',
    user: 'postgres',
    password: 'probe',
  });
  await admin.connect();
  await admin.query(`drop database if exists ${DB}`);
  await admin.end();
});

beforeEach(async () => {
  await sql`drop schema public cascade`.execute(db).catch(() => {});
  await sql`create schema public`.execute(db);
  await sql`drop table if exists tenancy_migrations`.execute(db).catch(() => {});
  await runMigrations(db, { credentials: CREDENTIALS, verify: false });
});

describe('auditRls — configuration saine', () => {
  it('ne signale rien après migration, sauf le rôle superuser du test', async () => {
    const { logger, errors } = mkLogger();
    const a = await auditRls(db, logger);

    expect(a.missingForce).toHaveLength(0);
    expect(a.withoutPolicy).toHaveLength(0);
    expect(a.withoutPermissive).toHaveLength(0);
    expect(a.missingWithCheck).toHaveLength(0);
    expect(a.globalUniques).toHaveLength(0);
    // Le test tourne en `postgres` : le rôle EST superuser, c'est attendu.
    expect(a.unsafeRole).toContain('SUPERUSER');
    expect(errors.some((e) => e.includes('NOBYPASSRLS'))).toBe(true);
  });

  it('avec le rôle applicatif bridé, tout est sain', async () => {
    const runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime);
    try {
      const { logger, logs } = mkLogger();
      const a = await auditRls(runtime, logger);
      expect(a.ok).toBe(true);
      expect(logs.some((l) => l.includes('six règles sont respectées'))).toBe(true);
    } finally {
      await runtime.destroy();
    }
  });
});

describe('auditRls — chaque anomalie créée délibérément', () => {
  it('détecte une table sans FORCE, et dit comment corriger', async () => {
    await sql`alter table appartenance no force row level security`.execute(db);
    const { logger, errors } = mkLogger();
    const a = await auditRls(db, logger);

    expect(a.missingForce).toContain('appartenance');
    const msg = errors.find((e) => e.includes('appartenance'))!;
    expect(msg).toContain('CONTOURNE');
    expect(msg).toContain('FORCE ROW LEVEL SECURITY'); // la commande exacte
  });

  it('détecte une table sous RLS sans aucune policy', async () => {
    await sql`drop policy base on appartenance`.execute(db);
    await sql`drop policy tenant_isolation on appartenance`.execute(db);
    const { logger, errors } = mkLogger();
    const a = await auditRls(db, logger);

    expect(a.withoutPolicy).toContain('appartenance');
    expect(errors.some((e) => e.includes('vide pour tous les rôles'))).toBe(true);
  });

  it('LE piège : restrictives SANS permissive de base', async () => {
    // Le défaut le plus difficile à diagnostiquer de la phase 0 : la table
    // est vide pour tout le monde, sans aucune erreur.
    await sql`drop policy base on appartenance`.execute(db);
    const { logger, errors } = mkLogger();
    const a = await auditRls(db, logger);

    expect(a.withoutPermissive).toContain('appartenance');
    const msg = errors.find((e) => e.includes('que des policies RESTRICTIVE'))!;
    expect(msg).toContain('VIDE');
    expect(msg).toContain('CREATE POLICY base'); // la commande exacte
  });

  it('détecte une restrictive sans WITH CHECK', async () => {
    await sql`drop policy tenant_isolation on appartenance`.execute(db);
    await sql`
      create policy tenant_isolation on appartenance as restrictive
      using (tenant_id = (select nullif(current_setting('app.tenant', true), '')::uuid))
    `.execute(db);

    const { logger, errors } = mkLogger();
    const a = await auditRls(db, logger);

    expect(a.missingWithCheck).toContainEqual({
      table: 'appartenance',
      policy: 'tenant_isolation',
    });
    expect(errors.some((e) => e.includes('WITH CHECK'))).toBe(true);
    expect(errors.some((e) => e.includes('INSERT légitimes'))).toBe(true);
  });

  it("détecte une unicité globale — l'oracle d'existence inter-tenant", async () => {
    await sql`alter table appartenance add column ref text`.execute(db);
    await sql`alter table appartenance add constraint ref_global unique (ref)`.execute(
      db,
    );

    const { logger, errors } = mkLogger();
    const a = await auditRls(db, logger);

    expect(a.globalUniques).toContainEqual({
      table: 'appartenance',
      constraint: 'ref_global',
    });
    const msg = errors.find((e) => e.includes('ref_global'))!;
    expect(msg).toContain('contournent la RLS');
    expect(msg).toContain('UNIQUE (tenant_id'); // la correction exacte
  });

  it('accepte une unicité correctement scopée', async () => {
    await sql`alter table appartenance add column ref text`.execute(db);
    await sql`alter table appartenance add constraint ref_scoped unique (tenant_id, ref)`.execute(
      db,
    );
    const a = await auditRls(db);
    expect(a.globalUniques.map((x) => x.constraint)).not.toContain('ref_scoped');
  });
});

describe('assertRlsIsSound', () => {
  it('passe sur une configuration saine', async () => {
    const runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime);
    try {
      await expect(assertRlsIsSound(runtime)).resolves.toBeUndefined();
    } finally {
      await runtime.destroy();
    }
  });

  it('lève une exception détaillée sur anomalie', async () => {
    await sql`alter table appartenance no force row level security`.execute(db);
    const runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime);
    try {
      await expect(assertRlsIsSound(runtime)).rejects.toThrow(
        /isolation entre tenants n'est PAS garantie/,
      );
      await expect(assertRlsIsSound(runtime)).rejects.toThrow(/appartenance/);
    } finally {
      await runtime.destroy();
    }
  });

  it('cumule plusieurs anomalies dans un seul message', async () => {
    await sql`alter table appartenance no force row level security`.execute(db);
    await sql`drop policy base on role`.execute(db);
    const runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime);
    try {
      let message = '';
      await assertRlsIsSound(runtime).catch((e) => {
        message = (e as Error).message;
      });
      expect(message).toContain('sans FORCE');
      expect(message).toContain('sans permissive');
    } finally {
      await runtime.destroy();
    }
  });

  /**
   * `auditRls` détectait déjà ces deux anomalies, mais `assertRlsIsSound` — la
   * fonction appelée au DÉMARRAGE — ne les avait jamais rencontrées. Un défaut
   * détecté par l'audit mais absent du message de démarrage ne bloque rien.
   */
  it('NOMME la policy fautive quand un WITH CHECK manque', async () => {
    await sql`drop policy tenant_isolation on appartenance`.execute(db);
    await sql`
      create policy tenant_isolation on appartenance as restrictive
      using (tenant_id = (select nullif(current_setting('app.tenant', true), '')::uuid))
    `.execute(db);

    const runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime);
    try {
      let message = '';
      await assertRlsIsSound(runtime).catch((e) => {
        message = (e as Error).message;
      });
      expect(message).toContain('sans WITH CHECK');
      // table.policy : sans le nom, il faut chercher laquelle.
      expect(message).toContain('appartenance.tenant_isolation');
    } finally {
      await runtime.destroy();
    }
  });

  it('NOMME la contrainte quand une unicité est globale', async () => {
    // Une UNIQUE globale est un oracle d'existence : elle révèle qu'une valeur
    // existe chez un AUTRE tenant. C'est une fuite, pas une gêne.
    await sql`alter table appartenance add column ref text`.execute(db);
    await sql`alter table appartenance add constraint ref_global unique (ref)`.execute(
      db,
    );

    const runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime);
    try {
      let message = '';
      await assertRlsIsSound(runtime).catch((e) => {
        message = (e as Error).message;
      });
      expect(message).toContain('unicité globale');
      expect(message).toContain('appartenance.ref_global');
    } finally {
      await runtime.destroy();
    }
  });

  it('signale un rôle non bridé — BYPASSRLS contourne tout', async () => {
    // Le superuser du test EST non bridé : c'est le cas le plus courant en
    // développement, et le plus dangereux si on le garde en production.
    let message = '';
    await assertRlsIsSound(db).catch((e) => {
      message = (e as Error).message;
    });
    expect(message).toContain('rôle non bridé');
  });
});
