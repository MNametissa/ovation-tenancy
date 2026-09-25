/**
 * Tests du harnais de migration, contre une VRAIE base PostgreSQL.
 *
 * Ces garanties ne se testent pas en mémoire : elles portent sur le
 * comportement de PostgreSQL face à FORCE ROW LEVEL SECURITY, mesuré et non
 * supposé.
 *
 * Prérequis : `cd probes/phase0 && docker compose up -d pg`
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import {
  withRlsDisabled,
  assertForceEnabled,
  assertPoliciesPresent,
  assertRoleIsSafe,
} from './rls-guard.js';
import type { TenancyLogger } from '../logging.js';

const { Pool } = pg;

function mkDb(user: string, password: string) {
  return new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new Pool({
        host: '127.0.0.1',
        port: 55432,
        database: 'ovation_probe',
        user,
        password,
        max: 3,
      }),
    }),
  });
}

/** Logger de test : capture les messages par niveau. */
function mkLogger() {
  const errors: string[] = [];
  const warns: string[] = [];
  const logs: string[] = [];
  const debugs: string[] = [];
  const logger: TenancyLogger = {
    error: (m) => errors.push(m),
    warn: (m) => warns.push(m),
    log: (m) => logs.push(m),
    debug: (m) => debugs.push(m),
  };
  return { logger, errors, warns, logs, debugs };
}

const T_A = '11111111-1111-1111-1111-111111111111';
let admin: Kysely<any>;
let migration: Kysely<any>;

beforeAll(async () => {
  admin = mkDb('postgres', 'probe');
  migration = mkDb('app_migration', 'migration');
});

afterAll(async () => {
  await sql`drop table if exists guard_t cascade`.execute(admin).catch(() => {});
  await admin.destroy();
  await migration.destroy();
});

beforeEach(async () => {
  await sql`drop table if exists guard_t cascade`.execute(admin);
  await sql`create table guard_t (id serial primary key, tenant_id uuid not null, v text)`
    .execute(admin);
  await sql`alter table guard_t owner to app_migration`.execute(admin);
  await sql`alter table guard_t enable row level security`.execute(admin);
  await sql`alter table guard_t force row level security`.execute(admin);
  await sql`create policy base on guard_t for all to app_migration using (true) with check (true)`
    .execute(admin);
  await sql`create policy iso on guard_t as restrictive
            using (tenant_id = (select nullif(current_setting('app.tenant', true),'')::uuid))
            with check (tenant_id = (select nullif(current_setting('app.tenant', true),'')::uuid))`
    .execute(admin);
  await sql`grant select, insert, update, delete on guard_t to app_migration`.execute(admin);
});

describe('withRlsDisabled', () => {
  it('permet une insertion de migration', async () => {
    const { logger } = mkLogger();
    await withRlsDisabled(admin, { tables: ['guard_t'], logger }, async (trx) => {
      await sql`insert into guard_t (tenant_id, v) values (${T_A}, 'x')`.execute(trx);
    });
    const n = await sql<{ n: number }>`select count(*)::int as n from guard_t`.execute(admin);
    expect(n.rows[0].n).toBe(1);
  });

  it('rétablit FORCE après succès', async () => {
    await withRlsDisabled(admin, { tables: ['guard_t'] }, async (trx) => {
      await sql`insert into guard_t (tenant_id, v) values (${T_A}, 'x')`.execute(trx);
    });
    const r = await sql<{ f: boolean }>`
      select relforcerowsecurity as f from pg_class where relname='guard_t'`.execute(admin);
    expect(r.rows[0].f).toBe(true);
  });

  it('LE test : rétablit FORCE après un ÉCHEC', async () => {
    // Mesuré en sonde : le ROLLBACK annule aussi le ALTER TABLE.
    // C'est ce qui rend le harnais sûr, et pourquoi il impose la transaction.
    const { logger, warns } = mkLogger();
    await expect(
      withRlsDisabled(admin, { tables: ['guard_t'], logger }, async () => {
        throw new Error('panne simulée');
      }),
    ).rejects.toThrow('panne simulée');

    const r = await sql<{ f: boolean }>`
      select relforcerowsecurity as f from pg_class where relname='guard_t'`.execute(admin);
    expect(r.rows[0].f).toBe(true);

    // Et le développeur est PRÉVENU, avec la raison et l'absence d'action requise.
    expect(warns).toHaveLength(1);
    expect(warns[0]).toContain('panne simulée');
    expect(warns[0]).toContain('Aucune action manuelle requise');
  });

  it("n'écrit rien si le travail échoue", async () => {
    await expect(
      withRlsDisabled(admin, { tables: ['guard_t'] }, async (trx) => {
        await sql`insert into guard_t (tenant_id, v) values (${T_A}, 'y')`.execute(trx);
        throw new Error('après insertion');
      }),
    ).rejects.toThrow();
    const n = await sql<{ n: number }>`select count(*)::int as n from guard_t`.execute(admin);
    expect(n.rows[0].n).toBe(0);
  });

  it('liste de tables vide : simple transaction', async () => {
    const out = await withRlsDisabled(admin, { tables: [] }, async () => 42);
    expect(out).toBe(42);
  });

  it('journalise en debug, pas plus haut, quand tout va bien', async () => {
    const { logger, errors, warns, debugs } = mkLogger();
    await withRlsDisabled(admin, { tables: ['guard_t'], logger }, async () => {});
    expect(errors).toHaveLength(0);
    expect(warns).toHaveLength(0);
    expect(debugs.length).toBeGreaterThanOrEqual(2); // levé puis rétabli
  });
});

describe('assertForceEnabled', () => {
  it('ne signale rien quand tout est en ordre', async () => {
    const { logger, errors } = mkLogger();
    const exposed = await assertForceEnabled(admin, logger);
    expect(exposed).not.toContain('guard_t');
    expect(errors).toHaveLength(0);
  });

  it('détecte une table laissée sans FORCE, et le dit', async () => {
    // Reproduit le cas D : migration interrompue HORS transaction.
    await sql`alter table guard_t no force row level security`.execute(admin);
    const { logger, errors } = mkLogger();
    const exposed = await assertForceEnabled(admin, logger);

    expect(exposed).toContain('guard_t');
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('guard_t');
    expect(errors[0]).toContain('exposées');
    expect(errors[0]).toContain('ALTER TABLE'); // dit COMMENT corriger

    await sql`alter table guard_t force row level security`.execute(admin);
  });
});

describe('assertPoliciesPresent', () => {
  it('détecte une table sous RLS sans policy', async () => {
    await sql`drop policy base on guard_t`.execute(admin);
    await sql`drop policy iso on guard_t`.execute(admin);

    const { logger, errors } = mkLogger();
    const silent = await assertPoliciesPresent(admin, logger);

    expect(silent).toContain('guard_t');
    expect(errors[0]).toContain('vide pour tous les rôles');
    expect(errors[0]).toContain('permissive'); // dit quoi faire
  });

  it('ne signale rien quand les policies existent', async () => {
    const { logger, errors } = mkLogger();
    const silent = await assertPoliciesPresent(admin, logger);
    expect(silent).not.toContain('guard_t');
    expect(errors).toHaveLength(0);
  });
});

describe('assertRoleIsSafe', () => {
  it('refuse un rôle SUPERUSER, et explique pourquoi', async () => {
    const { logger, errors } = mkLogger();
    const safe = await assertRoleIsSafe(admin, logger); // postgres = superuser
    expect(safe).toBe(false);
    expect(errors[0]).toContain('SUPERUSER');
    expect(errors[0]).toContain('contourne');
    expect(errors[0]).toContain('NOBYPASSRLS'); // dit quoi faire
  });

  it('accepte un rôle applicatif bridé', async () => {
    // Rôle dédié à CE test : les rôles sont globaux au cluster, et
    // `app_runtime` voit son mot de passe réaligné par les migrations des
    // autres suites. Un test ne doit pas dépendre de l'état laissé par un
    // autre.
    const NAME = 'guard_spec_runtime';
    const PWD = 'guard_spec_pwd_2026';
    await sql.raw(`drop role if exists ${NAME}`).execute(admin).catch(() => {});
    await sql
      .raw(`create role ${NAME} login password '${PWD}' nobypassrls nosuperuser`)
      .execute(admin);
    await sql.raw(`grant usage on schema public to ${NAME}`).execute(admin);

    const runtime = mkDb(NAME, PWD);
    try {
      const { logger, errors } = mkLogger();
      const safe = await assertRoleIsSafe(runtime, logger);
      expect(safe).toBe(true);
      expect(errors).toHaveLength(0);
    } finally {
      await runtime.destroy();
      await sql.raw(`drop role if exists ${NAME}`).execute(admin).catch(() => {});
    }
  });
});
