import { describe, it, expect } from '@jest/globals';
import {
  DummyDriver,
  Kysely,
  PostgresAdapter,
  PostgresIntrospector,
  PostgresQueryCompiler,
  type DatabaseConnection,
  type CompiledQuery,
  type QueryResult,
} from 'kysely';
import { assurerRole } from './001-roles.js';

class Pilote extends DummyDriver {
  readonly requetes: string[] = [];
  override acquireConnection(): Promise<DatabaseConnection> {
    return Promise.resolve({
      executeQuery: <R>(q: CompiledQuery): Promise<QueryResult<R>> => {
        this.requetes.push(q.sql);
        return Promise.resolve({
          rows: [
            {
              rolcanlogin: true,
              rolbypassrls: false,
              rolsuper: false,
              rolcreatedb: false,
              rolcreaterole: false,
            },
          ] as R[],
        });
      },
      // Le test ne fait aucune lecture en flux.
      // eslint-disable-next-line require-yield
      async *streamQuery<R>(): AsyncIterableIterator<QueryResult<R>> {
        throw new Error('Flux inattendu');
      },
    });
  }
}

describe('L8 — rôles PostgreSQL partagés', () => {
  it('refuse un attribut divergent sans modifier le rôle existant', async () => {
    const pilote = new Pilote();
    const db = new Kysely<any>({
      dialect: {
        createDriver: () => pilote,
        createAdapter: () => new PostgresAdapter(),
        createIntrospector: (k) => new PostgresIntrospector(k),
        createQueryCompiler: () => new PostgresQueryCompiler(),
      },
    });
    try {
      await expect(
        assurerRole(db, { name: 'app_policy', options: 'nologin bypassrls' }),
      ).rejects.toThrow(/incompatible.*administrateur/);
      expect(pilote.requetes.some((q) => /alter role/i.test(q))).toBe(false);
    } finally {
      await db.destroy();
    }
  });
});
