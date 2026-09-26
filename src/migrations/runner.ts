import { type Kysely, sql } from 'kysely';
import type { TenancyLogger } from '../logging.js';
import { assertForceEnabled, assertPoliciesPresent } from './rls-guard.js';
import * as m001 from './001-roles.js';
import * as m002 from './002-tables.js';
import * as m003 from './003-functions.js';
import * as m004 from './004-rls.js';
import * as m005 from './005-audit-chaine.js';
import type { RoleCredentials } from './001-roles.js';

/**
 * Exécuteur de migrations de la bibliothèque.
 *
 * TABLE DÉDIÉE — jamais la table `migrations` partagée avec l'hôte. Sinon les
 * migrations de la bibliothèque et celles de l'application s'entrelacent par
 * horodatage, dans un ordre qui dépend de l'ordre d'installation. C'est le
 * point dur des bibliothèques qui apportent leurs tables.
 *
 * L'HÔTE DÉCIDE QUAND — `runMigrations()` est exposée, jamais appelée
 * automatiquement au démarrage du module.
 */

const TABLE = 'tenancy_migrations';

export interface Migration {
  name: string;
  up(
    db: Kysely<any>,
    credentials: RoleCredentials,
    logger?: TenancyLogger,
  ): Promise<void>;
  down(db: Kysely<any>, logger?: TenancyLogger): Promise<void>;
  /**
   * Exécuter hors transaction.
   *
   * Réservé aux migrations qui doivent SURVIVRE à une erreur rattrapée : une
   * erreur PostgreSQL avorte la transaction entière, donc un `catch`
   * applicatif y est inopérant. Ne l'utiliser que si rien ne peut rester à
   * moitié appliqué de façon dangereuse.
   */
  outsideTransaction?: boolean;
}

/** Migrations exportées EN TABLEAU, pas en glob : un glob casse selon pnpm,
 *  le hoisting et le monorepo. */
export const MIGRATIONS: Migration[] = [
  // Hors transaction : tolère les courses sur les rôles, qui sont globaux au
  // cluster. Ne touche ni aux tables ni à FORCE RLS.
  { name: '001-roles', up: m001.up, down: m001.down, outsideTransaction: true },
  { name: '002-tables', up: (db) => m002.up(db), down: (db) => m002.down(db) },
  { name: '003-functions', up: (db) => m003.up(db), down: (db) => m003.down(db) },
  { name: '004-rls', up: (db) => m004.up(db), down: (db) => m004.down(db) },
  {
    name: '005-audit-chaine',
    up: (db) => m005.up(db),
    down: (db) => m005.down(db),
  },
];

export interface RunOptions {
  credentials: RoleCredentials;
  logger?: TenancyLogger;
  /** Vérifie l'état RLS après migration. Défaut : true. */
  verify?: boolean;
}

export interface MigrationResult {
  applied: string[];
  skipped: string[];
  /** Tables laissées sans FORCE, si la vérification est active. */
  exposed: string[];
  /** Tables sous RLS sans policy. */
  silent: string[];
}

async function ensureTable(db: Kysely<any>): Promise<void> {
  await sql`
    create table if not exists ${sql.ref(TABLE)} (
      name       text primary key,
      applied_at timestamptz not null default now()
    )
  `.execute(db);
}

async function alreadyApplied(db: Kysely<any>): Promise<Set<string>> {
  const rows = await sql<{ name: string }>`select name from ${sql.ref(TABLE)}`.execute(
    db,
  );
  return new Set(rows.rows.map((r) => r.name));
}

/**
 * Applique les migrations non encore appliquées.
 *
 * Chaque migration tourne **dans sa propre transaction** : un échec n'en laisse
 * aucune à moitié appliquée, et les `ALTER TABLE` de RLS sont annulés par le
 * ROLLBACK — c'est ce qui évite qu'une table reste exposée (mesuré : hors
 * transaction, FORCE reste désactivé).
 */
export async function runMigrations(
  db: Kysely<any>,
  opts: RunOptions,
): Promise<MigrationResult> {
  const { credentials, logger, verify = true } = opts;

  await ensureTable(db);
  const done = await alreadyApplied(db);

  const applied: string[] = [];
  const skipped: string[] = [];

  for (const migration of MIGRATIONS) {
    if (done.has(migration.name)) {
      skipped.push(migration.name);
      logger?.debug(`Migration « ${migration.name} » déjà appliquée`);
      continue;
    }

    logger?.log(`Application de la migration « ${migration.name} »`);
    try {
      if (migration.outsideTransaction) {
        // DÉCOUVERT À L'EXÉCUTION : une erreur PostgreSQL AVORTE la
        // transaction entière — un `catch` applicatif ne suffit pas, toute
        // requête suivante échoue sur « current transaction is aborted ».
        //
        // La migration des rôles doit donc tourner HORS transaction : elle
        // tolère les courses (deux migrations concurrentes créant les mêmes
        // rôles globaux au cluster), ce qui exige de pouvoir continuer après
        // une erreur rattrapée.
        //
        // Sans risque ici : elle ne touche ni aux tables ni à FORCE RLS, donc
        // rien ne peut rester à moitié appliqué de façon dangereuse.
        await migration.up(db, credentials, logger);
        await sql`insert into ${sql.ref(TABLE)} (name) values (${migration.name})`.execute(
          db,
        );
      } else {
        await db.transaction().execute(async (trx) => {
          await migration.up(trx, credentials, logger);
          await sql`insert into ${sql.ref(TABLE)} (name) values (${migration.name})`.execute(
            trx,
          );
        });
      }
      applied.push(migration.name);
    } catch (e) {
      logger?.error(
        `Migration « ${migration.name} » ÉCHOUÉE : ${(e as Error).message}. ` +
          (migration.outsideTransaction
            ? `Elle s'exécute HORS transaction : vérifiez son effet partiel ` +
              `avant de relancer.`
            : `Elle a été annulée par ROLLBACK — la base reste dans l'état ` +
              `précédent, et FORCE ROW LEVEL SECURITY est rétabli.`) +
          ` Corrigez la migration avant de relancer.`,
        (e as Error).stack,
      );
      throw e;
    }
  }

  if (applied.length > 0) {
    logger?.log(`${applied.length} migration(s) appliquée(s) : ${applied.join(', ')}`);
  } else {
    logger?.log('Aucune migration à appliquer — la base est à jour');
  }

  let exposed: string[] = [];
  let silent: string[] = [];
  if (verify) {
    exposed = await assertForceEnabled(db, logger);
    silent = await assertPoliciesPresent(db, logger);
    if (exposed.length === 0 && silent.length === 0) {
      logger?.log('Vérification RLS : toutes les tables sont protégées');
    }
  }

  return { applied, skipped, exposed, silent };
}

/**
 * Annule les migrations, de la plus récente à la plus ancienne.
 *
 * Destructif : `down()` supprime les tables. Réservé aux environnements de
 * test — d'où l'exigence d'un aveu explicite.
 */
export async function rollbackMigrations(
  db: Kysely<any>,
  opts: { logger?: TenancyLogger; iUnderstandThisIsDestructive: true },
): Promise<string[]> {
  // Le type exige littéralement `true`, donc TypeScript croit la condition
  // morte. Mais un appelant JavaScript passe ce qu'il veut, et c'est pour lui
  // que ce garde existe — couvert par le test « exige un aveu explicite ».
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (!opts.iUnderstandThisIsDestructive) {
    throw new Error(
      'rollbackMigrations() supprime les tables et leurs données. ' +
        'Passez { iUnderstandThisIsDestructive: true } pour confirmer.',
    );
  }
  const { logger } = opts;

  await ensureTable(db);
  const done = await alreadyApplied(db);
  const reverted: string[] = [];

  for (const migration of [...MIGRATIONS].reverse()) {
    if (!done.has(migration.name)) continue;
    logger?.warn(
      `Annulation de « ${migration.name} » — opération DESTRUCTIVE, ` +
        `les données des tables concernées seront perdues.`,
    );
    await db.transaction().execute(async (trx) => {
      await migration.down(trx, logger);
      await sql`delete from ${sql.ref(TABLE)} where name = ${migration.name}`.execute(
        trx,
      );
    });
    reverted.push(migration.name);
  }

  return reverted;
}
