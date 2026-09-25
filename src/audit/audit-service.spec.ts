/**
 * Tests du journal d'audit et du puits de permissions, contre PostgreSQL réel.
 *
 * T3.7 — une permission disparue est marquée obsolète, jamais supprimée.
 * T3.8 — le journal est immuable, et la chaîne détecte une altération.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { runMigrations } from '../migrations/runner.js';
import { AuditService } from './audit-service.js';
import { PermissionSink } from '../permissions/permission-sink.js';
import { RoleService } from '../roles/role-service.js';
import type { TenancyLogger } from '../logging.js';

const { Pool, Client } = pg;
const DB = 'tenancy_audit_test';

const CREDENTIALS = {
  migration: 'test_migration_pwd',
  runtime: 'test_runtime_pwd',
  auth: 'test_auth_pwd',
};

const T_A = '11111111-1111-1111-1111-111111111111';
const U_1 = 'aaaaaaaa-0000-0000-0000-000000000001';

function mkDb(database: string, user: string, password: string, max = 2) {
  return new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new Pool({ host: '127.0.0.1', port: 55432, database, user, password, max }),
    }),
  });
}

function mkLogger() {
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
  runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime, 2);
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
  for (const t of ['journal_audit', 'appartenance', 'role_permission', 'role',
                   'tenant', 'utilisateur']) {
    await sql.raw(`alter table ${t} no force row level security`).execute(admin);
  }
  // journal_audit porte des règles DO INSTEAD NOTHING : on les lève le temps
  // du nettoyage, puis on les repose. C'est justement ce que les tests
  // d'immuabilité vérifieront ensuite.
  await sql`drop rule if exists journal_no_delete on journal_audit`.execute(admin);
  await sql`delete from journal_audit`.execute(admin);
  await sql`create rule journal_no_delete as on delete to journal_audit do instead nothing`
    .execute(admin);

  await sql`delete from appartenance`.execute(admin);
  await sql`delete from role_permission`.execute(admin);
  await sql`delete from role`.execute(admin);
  await sql`delete from tenant`.execute(admin);
  await sql`delete from utilisateur`.execute(admin);
  await sql`delete from permission`.execute(admin);

  await sql`insert into tenant (id, slug, nom, pays)
            values (${T_A}, 'a', 'Tenant A', 'CM')`.execute(admin);
  await sql`insert into utilisateur (id, auth_sub, email)
            values (${U_1}, 'sub-1', 'u1@test.cm')`.execute(admin);

  for (const t of ['journal_audit', 'appartenance', 'role_permission', 'role',
                   'tenant', 'utilisateur']) {
    await sql.raw(`alter table ${t} force row level security`).execute(admin);
  }
});

describe('T3.8 — journal d’audit', () => {
  it('enregistre une entrée avec son empreinte', async () => {
    const audit = new AuditService(admin);
    await audit.record({
      tenantId: T_A, acteurId: U_1, acteurRole: 'organisateur',
      action: 'event.create', cibleType: 'evenement',
    });
    // `max()` n'existe pas pour bytea : on lit l'empreinte directement.
    const r = await sql<{ n: number; h: Buffer }>`
      select count(*) over ()::int as n, empreinte as h from journal_audit limit 1
    `.execute(admin);
    expect(r.rows[0].n).toBe(1);
    expect(r.rows[0].h).toBeTruthy();
    expect(r.rows[0].h.length).toBe(32); // SHA-256
  });

  it('EXIGE un motif sur une action destructrice, et dit pourquoi', async () => {
    const audit = new AuditService(admin);
    await expect(
      audit.record({
        tenantId: T_A, acteurRole: 'organisateur',
        action: 'participant.disqualify', cibleType: 'participant',
      }),
    ).rejects.toThrow(/exige un motif/);
    await expect(
      audit.record({
        tenantId: T_A, acteurRole: 'organisateur',
        action: 'participant.disqualify', cibleType: 'participant',
      }),
    ).rejects.toThrow(/POURQUOI/);
  });

  it('accepte une action destructrice AVEC motif', async () => {
    const audit = new AuditService(admin);
    await expect(
      audit.record({
        tenantId: T_A, acteurRole: 'organisateur',
        action: 'participant.disqualify', cibleType: 'participant',
        motif: 'Règlement article 7 : inscription hors délai',
      }),
    ).resolves.toBeUndefined();
  });

  it('IMMUABLE : un UPDATE ne modifie rien', async () => {
    const audit = new AuditService(admin);
    await audit.record({
      tenantId: T_A, acteurRole: 'organisateur',
      action: 'event.create', cibleType: 'evenement',
    });

    // La règle DO INSTEAD NOTHING absorbe l'UPDATE sans erreur : rien ne change.
    await sql`update journal_audit set action = 'falsifie'`.execute(admin);
    const r = await sql<{ action: string }>`select action from journal_audit`
      .execute(admin);
    expect(r.rows[0].action).toBe('event.create');
  });

  it('IMMUABLE : un DELETE ne supprime rien', async () => {
    const audit = new AuditService(admin);
    await audit.record({
      tenantId: T_A, acteurRole: 'organisateur',
      action: 'event.create', cibleType: 'evenement',
    });
    await sql`delete from journal_audit`.execute(admin);
    const r = await sql<{ n: number }>`select count(*)::int as n from journal_audit`
      .execute(admin);
    expect(r.rows[0].n).toBe(1);
  });

  it('le rôle applicatif n’a NI update NI delete au niveau des privilèges', async () => {
    // Deux barrières indépendantes : privilèges ET règles.
    const r = await sql<{ priv: string }>`
      select privilege_type as priv
      from information_schema.table_privileges
      where grantee = 'app_runtime' and table_name = 'journal_audit'
      order by privilege_type
    `.execute(admin);
    const privs = r.rows.map((x) => x.priv);
    expect(privs).toContain('SELECT');
    expect(privs).toContain('INSERT');
    expect(privs).not.toContain('UPDATE');
    expect(privs).not.toContain('DELETE');
  });

  it('la chaîne est valide sur une suite d’entrées', async () => {
    const audit = new AuditService(admin);
    for (let i = 0; i < 5; i++) {
      await audit.record({
        tenantId: T_A, acteurId: U_1, acteurRole: 'organisateur',
        action: `event.step${i}`, cibleType: 'evenement',
      });
    }
    const v = await audit.verifyChain(T_A);
    expect(v.valid).toBe(true);
    expect(v.checked).toBe(5);
  });

  it('DÉTECTE une entrée supprimée hors application', async () => {
    const audit = new AuditService(admin);
    for (let i = 0; i < 4; i++) {
      await audit.record({
        tenantId: T_A, acteurId: U_1, acteurRole: 'organisateur',
        action: `event.step${i}`, cibleType: 'evenement',
      });
    }

    // Suppression « par la bande » : on lève la règle, comme le ferait un
    // opérateur ayant accès à la base.
    await sql`drop rule journal_no_delete on journal_audit`.execute(admin);
    await sql`delete from journal_audit where action = 'event.step1'`.execute(admin);
    await sql`create rule journal_no_delete as on delete to journal_audit do instead nothing`
      .execute(admin);

    const { logger, errors } = mkLogger();
    const v = await new AuditService(admin, logger).verifyChain(T_A);

    expect(v.valid).toBe(false);
    expect(v.brokenAt).toBeDefined();
    expect(errors[0]).toContain('ROMPUE');
    expect(errors[0]).toContain('supprimée ou');
    expect(errors[0]).toContain('Conservez une copie'); // dit quoi faire
  });

  it('chaîne vide : valide', async () => {
    const v = await new AuditService(admin).verifyChain(T_A);
    expect(v.valid).toBe(true);
    expect(v.checked).toBe(0);
  });
});

describe('T3.7 — puits de permissions', () => {
  it('insère les permissions découvertes', async () => {
    const sink = new PermissionSink(admin);
    const r = await sink.sync({
      permissions: [
        { key: 'event.create', resource: 'event', action: 'create' },
        { key: 'event.delete', resource: 'event', action: 'delete' },
      ],
    });
    expect(r.added.sort()).toEqual(['event.create', 'event.delete']);
    expect(r.obsoleted).toHaveLength(0);
  });

  it('MARQUE OBSOLÈTE une permission disparue, sans la supprimer', async () => {
    const sink = new PermissionSink(admin);
    await sink.sync({ permissions: [{ key: 'event.create' }, { key: 'event.legacy' }] });

    const { logger, logs } = mkLogger();
    const r = await new PermissionSink(admin, logger).sync({
      permissions: [{ key: 'event.create' }],
    });

    expect(r.obsoleted).toEqual(['event.legacy']);
    // Toujours présente en base — un rôle pourrait y référer.
    const still = await sql<{ n: number; obs: Date | null }>`
      select count(*)::int as n, max(obsolete_le) as obs
      from permission where code = 'event.legacy'
    `.execute(admin);
    expect(still.rows[0].n).toBe(1);
    expect(still.rows[0].obs).not.toBeNull();
    expect(logs.some((l) => l.includes('obsolète'))).toBe(true);
  });

  it('AVERTIT si une permission obsolète est encore attribuée', async () => {
    const sink = new PermissionSink(admin);
    await sink.sync({ permissions: [{ key: 'event.legacy' }] });

    await sql`alter table role no force row level security`.execute(admin);
    await sql`alter table role_permission no force row level security`.execute(admin);
    const roles = new RoleService(admin);
    await roles.createTenantRole(T_A, {
      code: 'legacy_role', libelle: 'Legacy', permissions: ['event.legacy'],
    });
    await sql`alter table role force row level security`.execute(admin);
    await sql`alter table role_permission force row level security`.execute(admin);

    const { logger, warns } = mkLogger();
    const r = await new PermissionSink(admin, logger).sync({ permissions: [] });

    expect(r.stillReferenced).toEqual([{ code: 'event.legacy', roles: 1 }]);
    expect(warns[0]).toContain('disparu du code');
    expect(warns[0]).toContain('PAS');
    expect(warns[0]).toContain('Retirez-la de ces rôles'); // dit quoi faire
  });

  it('RÉVEILLE une permission obsolète qui réapparaît', async () => {
    const sink = new PermissionSink(admin);
    await sink.sync({ permissions: [{ key: 'event.maybe' }] });
    await sink.sync({ permissions: [] }); // disparue

    const { logger, logs } = mkLogger();
    const r = await new PermissionSink(admin, logger).sync({
      permissions: [{ key: 'event.maybe' }],
    });

    expect(r.revived).toEqual(['event.maybe']);
    expect(r.added).toHaveLength(0); // réveillée, pas dupliquée
    expect(logs.some((l) => l.includes('réapparue'))).toBe(true);

    const n = await sql<{ n: number }>`
      select count(*)::int as n from permission where code = 'event.maybe'
    `.execute(admin);
    expect(n.rows[0].n).toBe(1); // une seule ligne, pas deux
  });

  it('listObsoleteInUse donne le ménage à faire', async () => {
    const sink = new PermissionSink(admin);
    await sink.sync({ permissions: [{ key: 'event.old' }] });

    await sql`alter table role no force row level security`.execute(admin);
    await sql`alter table role_permission no force row level security`.execute(admin);
    await new RoleService(admin).createTenantRole(T_A, {
      code: 'r1', libelle: 'R1', permissions: ['event.old'],
    });
    await sql`alter table role force row level security`.execute(admin);
    await sql`alter table role_permission force row level security`.execute(admin);

    await sink.sync({ permissions: [] });
    const todo = await sink.listObsoleteInUse();
    expect(todo).toEqual([{ code: 'event.old', roles: ['r1'] }]);
  });
});
