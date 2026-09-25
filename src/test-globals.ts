/**
 * Setup global des tests.
 *
 * POURQUOI CE FICHIER : les rôles PostgreSQL sont GLOBAUX AU CLUSTER, pas à la
 * base. Chaque suite qui migrait recréait donc les mêmes rôles, et deux suites
 * parallèles produisaient « tuple concurrently updated » sur le même
 * ALTER ROLE.
 *
 * La première correction — `maxWorkers: 1` — a résolu le conflit mais
 * sérialisé toute la suite : **19 secondes pour 77 tests**.
 *
 * La bonne correction est ici : créer les rôles UNE SEULE FOIS avant tous les
 * tests. Les suites peuvent alors tourner en parallèle, et la migration 001
 * devient un simple `ALTER ROLE` idempotent sur des rôles déjà présents.
 */
import pg from 'pg';

const { Client } = pg;

export const TEST_CREDENTIALS = {
  migration: 'test_migration_pwd',
  runtime: 'test_runtime_pwd',
  auth: 'test_auth_pwd',
};

export default async function globalSetup(): Promise<void> {
  const c = new Client({
    host: '127.0.0.1',
    port: 55432,
    database: 'postgres',
    user: 'postgres',
    password: 'probe',
  });

  await c.connect();
  try {
    const plan: Array<[string, string, string]> = [
      ['app_migration', TEST_CREDENTIALS.migration, 'login'],
      [
        'app_runtime',
        TEST_CREDENTIALS.runtime,
        'login nobypassrls nosuperuser nocreatedb nocreaterole',
      ],
      ['app_auth', TEST_CREDENTIALS.auth, 'login nobypassrls nosuperuser'],
    ];

    for (const [name, pwd, options] of plan) {
      const exists = await c.query('select 1 from pg_roles where rolname = $1', [name]);
      if (exists.rowCount === 0) {
        await c.query(`create role ${name} ${options} password '${pwd}'`);
      } else {
        await c.query(`alter role ${name} ${options} password '${pwd}'`);
      }
    }

    const policyExists = await c.query(
      "select 1 from pg_roles where rolname = 'app_policy'",
    );
    if (policyExists.rowCount === 0) {
      await c.query('create role app_policy nologin bypassrls');
    }
  } finally {
    await c.end();
  }
}
