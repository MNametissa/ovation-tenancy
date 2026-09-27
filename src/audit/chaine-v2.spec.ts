/**
 * Chaîne d'audit v2 (lot L1-7) : encodage canonique, tenant couvert,
 * horodatage imposé, queue tronquée détectée, existant recalculé.
 */
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { AuditService } from './audit-service.js';
import { runMigrations } from '../migrations/runner.js';
import { TEST_CREDENTIALS } from '../test-globals.js';

const DB = 'tenancy_chaine_v2_test';
const T_A = '22222222-0000-0000-0000-00000000000a';
const T_B = '22222222-0000-0000-0000-00000000000b';

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

beforeAll(async () => {
  await superuser(`drop database if exists ${DB} with (force)`);
  await superuser(`create database ${DB}`);
  admin = new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new pg.Pool({
        host: '127.0.0.1',
        port: 55432,
        database: DB,
        user: 'postgres',
        password: 'probe',
        max: 3,
      }),
    }),
  });
  await runMigrations(admin, { credentials: TEST_CREDENTIALS, verify: false });
  await sql`insert into tenant (id, slug, nom, pays)
            values (${T_A}, 'a', 'A', 'CM'), (${T_B}, 'b', 'B', 'CM')`.execute(admin);
});

afterAll(async () => {
  await admin.destroy();
  await superuser(`drop database if exists ${DB} with (force)`);
});

/** Empreinte d'une ligne fabriquée, par LA formule de la base. */
async function empreinte(ligne: Record<string, unknown>): Promise<string> {
  const base = {
    id: 1,
    tenant_id: T_A,
    horodatage: '2026-09-27T10:00:00Z',
    acteur_role: 'r',
    action: 'x.y',
    cible_type: 'c',
    empreinte: '\\x00',
  };
  const r = await sql<{ e: Buffer }>`
    select app_empreinte_audit(null,
      jsonb_populate_record(null::journal_audit, ${JSON.stringify({ ...base, ...ligne })}::jsonb)) as e
  `.execute(admin);
  return r.rows[0].e.toString('hex');
}

async function ecrire(tenant: string, action: string): Promise<void> {
  await new AuditService(admin).record({
    tenantId: tenant,
    acteurRole: 'r',
    action,
    cibleType: 'c',
  });
}

async function supprimer(condition: string): Promise<void> {
  await sql`alter table journal_audit disable rule journal_no_delete`.execute(admin);
  await sql.raw(`delete from journal_audit where ${condition}`).execute(admin);
  await sql`alter table journal_audit enable rule journal_no_delete`.execute(admin);
}

describe('L1-7 — empreinte canonique', () => {
  it('collision mesurée en v1 : motif et « avant » ne se confondent plus', async () => {
    const a = await empreinte({ motif: 'erreur{"a": 1}' });
    const b = await empreinte({ motif: 'erreur', avant: { a: 1 } });
    expect(a).not.toBe(b);
  });

  it('champs adjacents : « ab » + « c » ≠ « a » + « bc »', async () => {
    const a = await empreinte({ action: 'ab', cible_type: 'c' });
    const b = await empreinte({ action: 'a', cible_type: 'bc' });
    expect(a).not.toBe(b);
  });

  it('le tenant entre dans l’empreinte', async () => {
    expect(await empreinte({ tenant_id: T_A })).not.toBe(
      await empreinte({ tenant_id: T_B }),
    );
  });

  it('la formule est VERSIONNÉE : chaque entrée écrite porte la version 2', async () => {
    await ecrire(T_A, 'v.version');
    const r = await sql<{ v: number }>`
      select version_empreinte as v from journal_audit where action = 'v.version'
    `.execute(admin);
    expect(r.rows[0].v).toBe(2);
  });
});

describe('L1-7 — horodatage imposé par le trigger', () => {
  it('un horodatage fourni par l’appelant est ignoré', async () => {
    await sql`insert into journal_audit (tenant_id, horodatage, acteur_role, action,
                                         cible_type, empreinte)
              values (${T_A}, '2000-01-01T00:00:00Z', 'r', 'h.antidate', 'c', ''::bytea)`.execute(
      admin,
    );
    const r = await sql<{ ecart: number }>`
      select extract(epoch from (clock_timestamp() - horodatage))::int as ecart
      from journal_audit where action = 'h.antidate'
    `.execute(admin);
    expect(Math.abs(r.rows[0].ecart)).toBeLessThan(60);
  });
});

describe('L1-7 — queue tronquée', () => {
  it('la suppression de la DERNIÈRE entrée est détectée', async () => {
    for (const a of ['q.1', 'q.2', 'q.3']) await ecrire(T_B, a);
    expect((await new AuditService(admin).verifyChain(T_B)).valid).toBe(true);
    await supprimer(`action = 'q.3'`);
    const v = await new AuditService(admin).verifyChain(T_B);
    expect(v.valid).toBe(false);
  });

  it('une chaîne ENTIÈREMENT supprimée est détectée', async () => {
    await supprimer(`tenant_id = '${T_B}'`);
    const v = await new AuditService(admin).verifyChain(T_B);
    expect(v.valid).toBe(false);
    expect(v.checked).toBe(0);
  });

  it('une chaîne jamais écrite reste valide', async () => {
    const vierge = '22222222-0000-0000-0000-0000000000cc';
    await sql`insert into tenant (id, slug, nom, pays) values (${vierge}, 'c', 'C', 'CM')`.execute(
      admin,
    );
    expect((await new AuditService(admin).verifyChain(vierge)).valid).toBe(true);
  });
});

describe('L1-7 — performance (audit du 2026-09-27)', () => {
  it('index (tenant_id, id), (acteur_id, id) et (tenant_id, ressource_id, id)', async () => {
    const r = await sql<{ cols: string }>`
      select string_agg(a.attname, ',' order by k.ord) as cols
      from pg_index x
      join pg_class t on t.oid = x.indrelid and t.relname = 'journal_audit'
      cross join lateral unnest(x.indkey::int2[]) with ordinality as k(attnum, ord)
      join pg_attribute a on a.attrelid = t.oid and a.attnum = k.attnum
      group by x.indexrelid`.execute(admin);
    const index = r.rows.map((x) => x.cols);
    expect(index).toEqual(
      expect.arrayContaining([
        'tenant_id,id',
        'acteur_id,id',
        'tenant_id,ressource_id,id',
      ]),
    );
  });

  it('app_empreinte_audit est inlinable : ni SET, ni SECURITY DEFINER, noms qualifiés', async () => {
    const r = await sql<{ config: string[] | null; definer: boolean; source: string }>`
      select proconfig as config, prosecdef as definer, prosrc as source
      from pg_proc where proname = 'app_empreinte_audit'`.execute(admin);
    const f = r.rows[0];
    expect(f.config).toBeNull();
    expect(f.definer).toBe(false);
    // Aucune résolution de nom ne dépend du chemin de l'appelant.
    for (const fn of ['digest', 'jsonb_build_array', 'encode', 'to_char', 'timezone']) {
      expect(f.source).toMatch(new RegExp(`\\.${fn}\\(`));
      expect(f.source).not.toMatch(new RegExp(`[^.a-z_]${fn}\\(`));
    }
  });

  it('verifyChain rend la PREMIÈRE rupture, et le compte complet', async () => {
    const t = '22222222-0000-0000-0000-0000000000dd';
    await sql`insert into tenant (id, slug, nom, pays) values (${t}, 'd', 'D', 'CM')`.execute(
      admin,
    );
    for (const a of ['r.1', 'r.2', 'r.3', 'r.4']) await ecrire(t, a);
    await sql`alter table journal_audit disable rule journal_no_update`.execute(admin);
    await sql`update journal_audit set motif = 'falsifie'
              where tenant_id = ${t} and action in ('r.2', 'r.4')`.execute(admin);
    await sql`alter table journal_audit enable rule journal_no_update`.execute(admin);
    const premiere = await sql<{ id: string }>`
      select id from journal_audit where tenant_id = ${t} and action = 'r.2'`.execute(
      admin,
    );
    const v = await new AuditService(admin).verifyChain(t);
    expect(v).toMatchObject({ valid: false, checked: 4 });
    expect(v.brokenAt?.id).toBe(String(premiere.rows[0].id));
  });
});

describe('L1-7 — l’existant est recalculé par la migration', () => {
  it('une chaîne écrite en v1 est valide après la migration 007', async () => {
    // Base à l'état 006 : la migration 007 marquée appliquée d'avance.
    const nom = `${DB}_existant`;
    await superuser(`drop database if exists ${nom} with (force)`);
    await superuser(`create database ${nom}`);
    const db = new Kysely<any>({
      dialect: new PostgresDialect({
        pool: new pg.Pool({
          host: '127.0.0.1',
          port: 55432,
          database: nom,
          user: 'postgres',
          password: 'probe',
          max: 2,
        }),
      }),
    });
    try {
      await sql`create table tenancy_migrations (name text primary key,
                applied_at timestamptz not null default now())`.execute(db);
      await sql`insert into tenancy_migrations (name) values ('007-audit-v2')`.execute(
        db,
      );
      await runMigrations(db, { credentials: TEST_CREDENTIALS, verify: false });
      await sql`insert into tenant (id, slug, nom, pays) values (${T_A}, 'a', 'A', 'CM')`.execute(
        db,
      );
      for (const a of ['e.1', 'e.2', 'e.3'])
        await new AuditService(db).record({
          tenantId: T_A,
          acteurRole: 'r',
          action: a,
          cibleType: 'c',
          motif: 'erreur',
          avant: { a: 1 },
        });
      const avant = await sql<{ e: Buffer }>`select empreinte as e from journal_audit
                                            order by id desc limit 1`.execute(db);

      await sql`delete from tenancy_migrations where name = '007-audit-v2'`.execute(db);
      await runMigrations(db, { credentials: TEST_CREDENTIALS, verify: false });

      const apres = await sql<{ e: Buffer; v: number }>`
        select empreinte as e, version_empreinte as v from journal_audit order by id desc limit 1
      `.execute(db);
      expect(apres.rows[0].e.equals(avant.rows[0].e)).toBe(false);
      expect(apres.rows[0].v).toBe(2);
      const v = await new AuditService(db).verifyChain(T_A);
      expect(v).toMatchObject({ valid: true, checked: 3 });
      // La suite de la chaîne s'enchaîne sur l'existant recalculé.
      await new AuditService(db).record({
        tenantId: T_A,
        acteurRole: 'r',
        action: 'e.4',
        cibleType: 'c',
      });
      expect(await new AuditService(db).verifyChain(T_A)).toMatchObject({
        valid: true,
        checked: 4,
      });
    } finally {
      await db.destroy();
      await superuser(`drop database if exists ${nom} with (force)`);
    }
  });
});
