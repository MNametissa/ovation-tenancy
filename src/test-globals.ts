/**
 * Setup global des tests.
 *
 * POURQUOI CE FICHIER : les rôles PostgreSQL sont GLOBAUX AU CLUSTER, pas à la
 * base. Chaque suite qui migrait recréait donc les mêmes rôles, et deux suites
 * parallèles produisaient « tuple concurrently updated » sur le même
 * ALTER ROLE. Les rôles sont créés ICI, une fois, s'ils manquent.
 *
 * UN SEUL JEU de mots de passe de test (`test_*_pwd`) pour les suites, la
 * fumée et l'intégration ; `scripts/audit-exposure.mjs` les déclare.
 *
 * Un rôle EXISTANT garde son mot de passe : le réécrire casserait toute autre
 * base du cluster qui l'utilise (L1-8). S'il ne correspond pas aux valeurs de
 * test, l'échec le dit, et `DB_REALIGNER_MOTS_DE_PASSE=1` le réécrit
 * explicitement.
 */
import pg from 'pg';

const { Client } = pg;

export const TEST_CREDENTIALS = {
  runtime: 'test_runtime_pwd',
  auth: 'test_auth_pwd',
};

/** Rôle de l'exécutant des notifications (`@ovation/notifications`). */
export const TEST_WORKER_PASSWORD = 'test_worker_pwd';

const connexion = (user: string, password: string) =>
  new Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user, password });

export default async function globalSetup(): Promise<void> {
  const c = connexion('postgres', 'probe');
  const realigner = process.env.DB_REALIGNER_MOTS_DE_PASSE === '1';

  await c.connect();
  try {
    const plan: Array<[string, string, string]> = [
      [
        'app_runtime',
        TEST_CREDENTIALS.runtime,
        'login nobypassrls nosuperuser nocreatedb nocreaterole',
      ],
      ['app_auth', TEST_CREDENTIALS.auth, 'login nobypassrls nosuperuser'],
      ['app_worker', TEST_WORKER_PASSWORD, 'login nobypassrls nosuperuser'],
    ];

    for (const [name, pwd, options] of plan) {
      const exists = await c.query('select 1 from pg_roles where rolname = $1', [name]);
      if (exists.rowCount === 0) {
        await c.query(`create role ${name} ${options} password '${pwd}'`).catch((e) => {
          // Une autre suite l'a créé entretemps.
          if (!/already exists|duplicate key/.test((e as Error).message)) throw e;
        });
      } else if (realigner) {
        await c.query(`alter role ${name} ${options} password '${pwd}'`);
      }
      const essai = connexion(name, pwd);
      try {
        await essai.connect();
      } catch (e) {
        throw new Error(
          `Le rôle « ${name} » existe avec un autre mot de passe que celui des tests ` +
            `(${(e as Error).message}). Les rôles sont globaux au cluster : il sert ` +
            `peut-être une autre base. Relancez avec DB_REALIGNER_MOTS_DE_PASSE=1 ` +
            `pour le réécrire en connaissance de cause.`,
          { cause: e },
        );
      } finally {
        await essai.end().catch(() => {});
      }
    }

    // `test_proprietaire` : propriétaire NON superuser des tables de certains
    // tests (FORCE RLS s'applique au propriétaire, pas au superuser).
    for (const [name, options] of [
      ['app_policy', 'nologin bypassrls'],
      ['test_proprietaire', 'nologin nobypassrls'],
    ]) {
      const existe = await c.query('select 1 from pg_roles where rolname = $1', [name]);
      if (existe.rowCount === 0) {
        await c.query(`create role ${name} ${options}`).catch((e) => {
          if (!/already exists|duplicate key/.test((e as Error).message)) throw e;
        });
      }
    }
  } finally {
    await c.end();
  }
}
