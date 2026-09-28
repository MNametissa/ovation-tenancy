import { type Kysely, sql } from 'kysely';

/** Contrat A-4 optionnel : l’application installe les fonctions SQL documentées. */
export type PreuveContexte =
  | { type: 'session'; jetonSession: string; organisationId: string }
  | { type: 'public'; hote: string }
  | { type: 'systeme'; organisationId: string };

/** Le callback et la preuve partagent obligatoirement la même transaction. */
export function avecContexteVerifie<T>(
  db: Kysely<any>,
  preuve: PreuveContexte,
  executer: (trx: Kysely<any>) => Promise<T>,
): Promise<T> {
  return db.transaction().execute(async (trx) => {
    switch (preuve.type) {
      case 'session':
        await sql`select app_ouvrir_contexte_session(${preuve.jetonSession}, ${preuve.organisationId}::uuid)`.execute(
          trx,
        );
        break;
      case 'public':
        await sql`select app_ouvrir_contexte_public(${preuve.hote})`.execute(trx);
        break;
      case 'systeme':
        await sql`select app_ouvrir_contexte_systeme(${preuve.organisationId}::uuid)`.execute(
          trx,
        );
        break;
      default:
        throw new Error('Type de contexte inconnu.');
    }
    return executer(trx);
  });
}
