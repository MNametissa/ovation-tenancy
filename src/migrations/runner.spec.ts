/**
 * Tests de l'exécuteur de migrations, contre une base DÉDIÉE.
 *
 * Base séparée de `ovation_probe` : ces tests créent et détruisent tout le
 * schéma, ils ne doivent pas écraser les sondes de la phase 0.
 *
 * Prérequis : `cd probes/phase0 && docker compose up -d pg`
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { runMigrations, rollbackMigrations, MIGRATIONS } from './runner.js';
import { assertSafePassword } from './001-roles.js';
import type { TenancyLogger } from '../logging.js';

const { Pool, Client } = pg;
const DB = 'tenancy_test';

// Mots de passe de TEST uniquement. La validation exige 8 caractères minimum
// et refuse apostrophes et antislashs — vérifié par le describe
// « validation des mots de passe de rôle ».
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
  // Repartir d'un schéma vierge à chaque test.
  await sql`drop schema public cascade`.execute(db).catch(() => {});
  await sql`create schema public`.execute(db);
  await sql`drop table if exists tenancy_migrations`.execute(db).catch(() => {});
});

describe('runMigrations', () => {
  it('applique les 4 migrations et vérifie la RLS', async () => {
    const { logger, errors, logs } = mkLogger();
    const r = await runMigrations(db, { credentials: CREDENTIALS, logger });

    expect(r.applied).toEqual(MIGRATIONS.map((m) => m.name));
    expect(r.skipped).toHaveLength(0);
    expect(r.exposed).toHaveLength(0);
    expect(r.silent).toHaveLength(0);
    expect(errors).toHaveLength(0);
    expect(logs.some((l) => l.includes('toutes les tables sont protégées'))).toBe(true);
  });

  it('est idempotente : un second passage n’applique rien', async () => {
    await runMigrations(db, { credentials: CREDENTIALS });
    const { logger, logs } = mkLogger();
    const r = await runMigrations(db, { credentials: CREDENTIALS, logger });

    expect(r.applied).toHaveLength(0);
    expect(r.skipped).toEqual(MIGRATIONS.map((m) => m.name));
    expect(logs.some((l) => l.includes('à jour'))).toBe(true);
  });

  it('utilise une table de suivi DÉDIÉE, pas « migrations »', async () => {
    await runMigrations(db, { credentials: CREDENTIALS });
    const own = await sql<{ n: number }>`
      select count(*)::int as n from pg_class where relname = 'tenancy_migrations'
    `.execute(db);
    const shared = await sql<{ n: number }>`
      select count(*)::int as n from pg_class where relname = 'migrations'
    `.execute(db);
    expect(own.rows[0].n).toBe(1);
    expect(shared.rows[0].n).toBe(0);
  });

  it('crée les quatre rôles, dont app_policy en BYPASSRLS', async () => {
    await runMigrations(db, { credentials: CREDENTIALS });
    const r = await sql<{
      rolname: string;
      rolbypassrls: boolean;
      rolcanlogin: boolean;
    }>`
      select rolname, rolbypassrls, rolcanlogin from pg_roles
      where rolname in ('app_migration','app_runtime','app_policy','app_auth')
      order by rolname
    `.execute(db);

    const byName = Object.fromEntries(r.rows.map((x) => [x.rolname, x]));
    expect(Object.keys(byName).sort()).toEqual([
      'app_auth',
      'app_migration',
      'app_policy',
      'app_runtime',
    ]);
    // app_runtime NE DOIT PAS contourner la RLS
    expect(byName['app_runtime'].rolbypassrls).toBe(false);
    // app_policy porte la fonction : BYPASSRLS mais NOLOGIN
    expect(byName['app_policy'].rolbypassrls).toBe(true);
    expect(byName['app_policy'].rolcanlogin).toBe(false);
  });

  it('pose RLS + FORCE sur toutes les tables portant tenant_id', async () => {
    await runMigrations(db, { credentials: CREDENTIALS });
    const r = await sql<{ relname: string }>`
      select c.relname
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      join pg_attribute a on a.attrelid = c.oid and a.attname = 'tenant_id'
      where n.nspname = 'public' and c.relkind = 'r'
        and not (c.relrowsecurity and c.relforcerowsecurity)
    `.execute(db);
    expect(r.rows).toHaveLength(0);
  });

  it('pose une PERMISSIVE de base sur chaque table sous RLS', async () => {
    // Sans elle : 0 ligne partout, silencieusement (mesuré phase 0).
    await runMigrations(db, { credentials: CREDENTIALS });
    const r = await sql<{ relname: string; n: number }>`
      select c.relname, count(p.oid)::int as n
      from pg_class c
      join pg_namespace ns on ns.oid = c.relnamespace
      left join pg_policy p on p.polrelid = c.oid and p.polpermissive
      where ns.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity
      group by c.relname
    `.execute(db);
    for (const row of r.rows) {
      expect(row.n).toBeGreaterThanOrEqual(1);
    }
  });

  it('les restrictives portent toutes un WITH CHECK', async () => {
    // Sans WITH CHECK, PostgreSQL retombe sur USING pour les écritures et
    // bloque des INSERT légitimes (mesuré phase 0).
    await runMigrations(db, { credentials: CREDENTIALS });
    const r = await sql<{ relname: string; polname: string; has_check: boolean }>`
      select c.relname, p.polname, (p.polwithcheck is not null) as has_check
      from pg_policy p join pg_class c on c.oid = p.polrelid
      where not p.polpermissive and p.polcmd = '*'
    `.execute(db);
    for (const row of r.rows) {
      expect(row.has_check).toBe(true);
    }
  });

  it('app_a_permission appartient à app_policy, pas au propriétaire', async () => {
    // Détenue par app_migration, elle est soumise à FORCE RLS et rend
    // TOUJOURS false (mesuré phase 0).
    await runMigrations(db, { credentials: CREDENTIALS });
    const r = await sql<{ owner: string; secdef: boolean; config: string[] }>`
      select pg_get_userbyid(proowner) as owner, prosecdef as secdef, proconfig as config
      from pg_proc where proname = 'app_a_permission'
    `.execute(db);
    expect(r.rows[0].owner).toBe('app_policy');
    expect(r.rows[0].secdef).toBe(true);
    // search_path figé : sans lui, un SECURITY DEFINER est une porte dérobée
    expect(r.rows[0].config.join(',')).toContain('search_path');
  });

  it('journalise en log, pas en error, quand tout va bien', async () => {
    const { logger, errors, warns, logs } = mkLogger();
    await runMigrations(db, { credentials: CREDENTIALS, logger });
    expect(errors).toHaveLength(0);
    expect(warns).toHaveLength(0);
    expect(logs.length).toBeGreaterThanOrEqual(MIGRATIONS.length);
  });
});

/**
 * Validation des mots de passe de rôle.
 *
 * `CREATE ROLE` n'accepte PAS de paramètre lié : le mot de passe est
 * nécessairement interpolé dans un `sql.raw`. La validation est donc la seule
 * barrière contre une injection à cet endroit, et elle n'était pas mesurée —
 * le commentaire en tête de ce fichier annonçait une vérification absente.
 */
describe('validation des mots de passe de rôle', () => {
  const bons = { ...CREDENTIALS };

  it('refuse un mot de passe de moins de 8 caractères', async () => {
    await expect(
      runMigrations(db, { credentials: { ...bons, runtime: 'court' } }),
    ).rejects.toThrow(/trop court/);
  });

  it('refuse un mot de passe vide', async () => {
    await expect(
      runMigrations(db, { credentials: { ...bons, auth: '' } }),
    ).rejects.toThrow(/trop court/);
  });

  it('refuse une APOSTROPHE — la sortie du littéral SQL', async () => {
    // Sans ce refus : CREATE ROLE app_runtime login password 'x'; DROP …
    await expect(
      runMigrations(db, {
        credentials: { ...bons, runtime: "x'; drop table tenant; --" },
      }),
    ).rejects.toThrow(/apostrophe ou un antislash/);
  });

  it('refuse un ANTISLASH', async () => {
    await expect(
      runMigrations(db, { credentials: { ...bons, migration: 'abcdefgh\\' } }),
    ).rejects.toThrow(/apostrophe ou un antislash/);
  });

  it('le refus NOMME le rôle concerné et dit quoi faire', async () => {
    // Un message qui ne dit pas quel rôle corriger oblige à chercher.
    await expect(
      runMigrations(db, { credentials: { ...bons, auth: 'abc' } }),
    ).rejects.toThrow(/app_auth|auth/);
    await expect(
      runMigrations(db, { credentials: { ...bons, auth: 'abc' } }),
    ).rejects.toThrow(/jamais en dur/);
  });

  it('accepte un mot de passe conforme mais inhabituel', async () => {
    // La validation ne doit pas être plus restrictive que nécessaire : seules
    // l'apostrophe et l'antislash cassent le littéral.
    //
    // On appelle la validation DIRECTEMENT : passer par runMigrations
    // réaligne un mot de passe de rôle, et les rôles sont globaux au cluster
    // (défaut n°2 de la phase 3) — le test casserait les suites tournant en
    // parallèle.
    expect(() =>
      assertSafePassword('app_runtime', 'aB3!#$%&*()-_=+[]{}|;:,.<>?/~`"'),
    ).not.toThrow();
  });

  it('la validation directe refuse les mêmes cas', () => {
    expect(() => assertSafePassword('r', 'court')).toThrow(/trop court/);
    expect(() => assertSafePassword('r', '')).toThrow(/trop court/);
    expect(() => assertSafePassword('r', "abcdefgh'")).toThrow(/apostrophe/);
    expect(() => assertSafePassword('r', 'abcdefgh\\')).toThrow(/antislash/);
    // Exactement 8 caractères : la borne est inclusive.
    expect(() => assertSafePassword('r', 'abcdefgh')).not.toThrow();
  });
});

describe('rollbackMigrations', () => {
  it('exige un aveu explicite', async () => {
    await runMigrations(db, { credentials: CREDENTIALS });
    await expect(
      // @ts-expect-error — c'est justement ce qu'on teste
      rollbackMigrations(db, {}),
    ).rejects.toThrow('supprime les tables');
  });

  it('annule tout et AVERTIT à chaque étape', async () => {
    await runMigrations(db, { credentials: CREDENTIALS });
    const { logger, warns } = mkLogger();
    const reverted = await rollbackMigrations(db, {
      logger,
      iUnderstandThisIsDestructive: true,
    });

    expect(reverted).toEqual([...MIGRATIONS].reverse().map((m) => m.name));
    // Un avertissement par migration, plus celui sur les rôles conservés :
    // la règle « si le dev oublie, on le lui rappelle » impose de signaler
    // que les rôles app_* survivent au rollback.
    expect(warns.length).toBeGreaterThanOrEqual(MIGRATIONS.length);
    expect(warns[0]).toContain('DESTRUCTIVE');
    expect(warns.some((w) => w.includes('rôles app_* sont CONSERVÉS'))).toBe(true);
    expect(warns.some((w) => w.includes('DROP ROLE'))).toBe(true); // dit COMMENT

    const left = await sql<{ n: number }>`
      select count(*)::int as n from pg_class c
      join pg_namespace ns on ns.oid = c.relnamespace
      where ns.nspname='public' and c.relkind='r' and c.relname='tenant'
    `.execute(db);
    expect(left.rows[0].n).toBe(0);
  });

  it('aller-retour complet : migrate → rollback → migrate', async () => {
    await runMigrations(db, { credentials: CREDENTIALS });
    await rollbackMigrations(db, { iUnderstandThisIsDestructive: true });
    const again = await runMigrations(db, { credentials: CREDENTIALS });
    expect(again.applied).toEqual(MIGRATIONS.map((m) => m.name));
    expect(again.exposed).toHaveLength(0);
  });
});
