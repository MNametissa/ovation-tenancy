import { type Kysely, sql } from 'kysely';
import type { TenancyLogger } from '../logging.js';
import { assertForceEnabled, assertPoliciesPresent } from './rls-guard.js';
import * as m001 from './001-roles.js';
import * as m002 from './002-tables.js';
import * as m003 from './003-functions.js';
import * as m004 from './004-rls.js';
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
}

/** Migrations exportées EN TABLEAU, pas en glob : un glob casse selon pnpm,
 *  le hoisting et le monorepo. */
export const MIGRATIONS: Migration[] = [
  { name: '001-roles', up: m001.up, down: m001.down },
  { name: '002-tables', up: (db) => m002.up(db), down: (db) => m002.down(db) },
  { name: '003-functions', up: (db) => m003.up(db), down: (db) => m003.down(db) },
  { name: '004-rls', up: (db) => m004.up(db), down: (db) => m004.down(db) },
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
  const rows = await sql<{ name: string }>`select name from ${sql.ref(TABLE)}`.execute(db);
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
      await db.transaction().execute(async (trx) => {
        await migration.up(trx, credentials, logger);
        await sql`insert into ${sql.ref(TABLE)} (name) values (${migration.name})`
          .execute(trx);
      });
      applied.push(migration.name);
    } catch (e) {
      logger?.error(
        `Migration « ${migration.name} » ÉCHOUÉE : ${(e as Error).message}. ` +
          `Elle a été annulée par ROLLBACK — la base reste dans l'état ` +
          `précédent, et FORCE ROW LEVEL SECURITY est rétabli. ` +
          `Corrigez la migration avant de relancer.`,
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
      await sql`delete from ${sql.ref(TABLE)} where name = ${migration.name}`
        .execute(trx);
    });
    reverted.push(migration.name);
  }

  return reverted;
}
