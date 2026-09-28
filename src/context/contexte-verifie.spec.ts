import { describe, expect, it, jest } from '@jest/globals';
import { Kysely, PostgresDialect } from 'kysely';
import { avecContexteVerifie, type PreuveContexte } from './contexte-verifie.js';

/** Contrat du connecteur : une seule transaction, SQL paramétré, échec fermé. */
function connexion(refuser = false) {
  const requetes: Array<{ sql: string; parameters: readonly unknown[] }> = [];
  const connexion = {
    query: async (sql: string, parameters: readonly unknown[] = []) => {
      requetes.push({ sql, parameters });
      if (refuser && sql.includes('app_ouvrir')) throw new Error('Contexte refusé');
      return { rows: [], rowCount: 0, command: 'SELECT' };
    },
    release() {},
  };
  const db = new Kysely<any>({
    dialect: new PostgresDialect({
      pool: { connect: async () => connexion, end: async () => {} } as any,
    }),
  });
  return { db, requetes };
}

describe('avecContexteVerifie', () => {
  const preuves: PreuveContexte[] = [
    {
      type: 'session',
      jetonSession: "secret';select 1;--",
      organisationId: '11111111-1111-1111-1111-111111111111',
    },
    { type: 'public', hote: "a.test';select 1;--" },
    { type: 'systeme', organisationId: '11111111-1111-1111-1111-111111111111' },
  ];
  for (const preuve of preuves) {
    it(`${preuve.type} : paramètres séparés et commit après le callback`, async () => {
      const { db, requetes } = connexion();
      const valeur = await avecContexteVerifie(db, preuve, async () => {
        expect(requetes.at(-1)?.sql).toContain('app_ouvrir_contexte_');
        return 'résultat';
      });
      expect(valeur).toBe('résultat');
      expect(requetes.at(-1)?.sql).toBe('commit');
      const ouverture = requetes.find((r) => r.sql.includes('app_ouvrir'))!;
      expect(ouverture.sql).not.toContain('select 1;--');
      expect(ouverture.parameters.length).toBe(preuve.type === 'session' ? 2 : 1);
      await db.destroy();
    });
  }
  it('un type forgé ne lance jamais le callback', async () => {
    const { db, requetes } = connexion();
    const action = jest.fn(async () => undefined);
    await expect(
      avecContexteVerifie(db, { type: 'invente' } as unknown as PreuveContexte, action),
    ).rejects.toThrow('Type de contexte inconnu');
    expect(action).not.toHaveBeenCalled();
    expect(requetes.at(-1)?.sql).toBe('rollback');
    await db.destroy();
  });
  it('une preuve refusée annule la transaction sans appeler le métier', async () => {
    const { db, requetes } = connexion(true);
    const action = jest.fn(async () => undefined);
    await expect(avecContexteVerifie(db, preuves[0], action)).rejects.toThrow(
      'Contexte refusé',
    );
    expect(action).not.toHaveBeenCalled();
    expect(requetes.at(-1)?.sql).toBe('rollback');
    await db.destroy();
  });
});
