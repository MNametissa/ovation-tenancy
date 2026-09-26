import { type Kysely, sql } from 'kysely';
import type { TenancyLogger } from '../logging.js';

/**
 * Journal d'audit — immuable et chaîné.
 *
 * CE QUE LE CHAÎNAGE PROUVE : la suppression ponctuelle d'une entrée et
 * l'altération accidentelle. La vérification recalcule chaque empreinte à
 * partir de la précédente : retirer ou modifier une ligne casse la chaîne.
 *
 * CE QU'IL NE PROUVE PAS : il ne protège pas d'un opérateur qui recalculerait
 * TOUTE la chaîne après modification. À présenter comme tel — survendre une
 * garantie est pire que ne pas l'avoir, car on cesse de chercher ailleurs.
 *
 * Immuabilité posée à DEUX niveaux indépendants (migration 003) :
 *   - privilèges : UPDATE et DELETE révoqués pour le rôle applicatif ;
 *   - règles : DO INSTEAD NOTHING, qui neutralise même un privilège accordé
 *     par erreur.
 */

export interface AuditEntry {
  tenantId: string;
  ressourceId?: string;
  acteurId?: string;
  /** Rôle figé AU MOMENT de l'action : il peut changer ensuite. */
  acteurRole: string;
  action: string;
  cibleType: string;
  cibleId?: string;
  avant?: unknown;
  apres?: unknown;
  /** Obligatoire sur les actions destructrices. */
  motif?: string;
}

/** Actions exigeant un motif. */
const MOTIF_REQUIRED = new Set([
  'delete',
  'disqualify',
  'reject',
  'cancel',
  'revoke',
  'invalidate',
]);

export interface ChainVerification {
  valid: boolean;
  checked: number;
  /** Première entrée dont l'empreinte ne correspond pas. */
  brokenAt?: { id: string; expected: string; found: string };
}

export class AuditService {
  constructor(
    private readonly db: Kysely<any>,
    private readonly logger?: TenancyLogger,
  ) {}

  /**
   * Écrit une entrée. L'empreinte et le chaînage sont posés par le trigger —
   * l'application ne peut pas les falsifier.
   *
   * @throws si une action destructrice arrive sans motif.
   */
  async record(entry: AuditEntry): Promise<void> {
    const verb = entry.action.split('.').pop() ?? entry.action;
    if (MOTIF_REQUIRED.has(verb) && !entry.motif) {
      throw new Error(
        `L'action « ${entry.action} » est destructrice et exige un motif. ` +
          `Sans motif, le journal enregistre QUE quelque chose a été fait, ` +
          `pas POURQUOI — et c'est justement ce qu'on demandera en cas de ` +
          `contestation. Renseignez « motif ».`,
      );
    }

    await sql`
      insert into journal_audit
        (tenant_id, ressource_id, acteur_id, acteur_role, action,
         cible_type, cible_id, avant, apres, motif, empreinte)
      values
        (${entry.tenantId}, ${entry.ressourceId ?? null}, ${entry.acteurId ?? null},
         ${entry.acteurRole}, ${entry.action}, ${entry.cibleType},
         ${entry.cibleId ?? null},
         ${entry.avant ? JSON.stringify(entry.avant) : null}::jsonb,
         ${entry.apres ? JSON.stringify(entry.apres) : null}::jsonb,
         ${entry.motif ?? null},
         ''::bytea)
    `.execute(this.db);
  }

  /**
   * Vérifie l'intégrité de la chaîne d'un tenant.
   *
   * Recalcule chaque empreinte à partir de la précédente et compare. Une
   * suppression ou une altération casse la correspondance.
   */
  async verifyChain(tenantId: string): Promise<ChainVerification> {
    /**
     * L'empreinte est RECALCULÉE PAR POSTGRESQL, avec la formule exacte du
     * trigger `chaine_audit()` — `horodatage::text`, et non un format ISO
     * produit côté JavaScript.
     *
     * DÉFAUT CORRIGÉ : la version précédente calculait l'empreinte attendue
     * puis ne l'utilisait jamais (le linter a signalé la variable morte). Elle
     * ne comparait que `empreinte_precedente`, donc elle détectait la
     * SUPPRESSION d'une entrée mais pas la FALSIFICATION de son contenu —
     * exactement ce que son message d'erreur promettait de détecter. Au
     * passage, le format d'horodatage divergeait aussi : la comparaison aurait
     * échoué en permanence si elle avait existé.
     */
    const rows = await sql<{
      id: string;
      empreinte: Buffer;
      empreinte_precedente: Buffer | null;
      recalculee: Buffer;
    }>`
      select id, empreinte, empreinte_precedente,
             -- LA formule du trigger, et non une copie : une copie divergeait
             -- déjà une fois (format d'horodatage), faussant toute vérification.
             app_empreinte_audit(empreinte_precedente, journal_audit) as recalculee
      from journal_audit
      where tenant_id = ${tenantId}
      order by id
    `.execute(this.db);

    let previous: Buffer | null = null;

    for (const row of rows.rows) {
      // Deux vérifications indépendantes, et il faut les DEUX :
      //   1. le chaînage — une entrée retirée décale les liens ;
      //   2. l'empreinte de l'entrée — un contenu modifié ne correspond plus.
      const storedPrev = row.empreinte_precedente?.toString('hex') ?? '';
      const expectedPrev = previous?.toString('hex') ?? '';
      const stored = row.empreinte.toString('hex');
      const recalculated = row.recalculee.toString('hex');

      const chainageRompu = storedPrev !== expectedPrev;
      const contenuFalsifie = stored !== recalculated;

      if (chainageRompu || contenuFalsifie) {
        const broken = chainageRompu
          ? {
              id: row.id,
              expected: expectedPrev.slice(0, 16),
              found: storedPrev.slice(0, 16),
            }
          : {
              id: row.id,
              expected: recalculated.slice(0, 16),
              found: stored.slice(0, 16),
            };
        // Nommer le DIAGNOSTIC, pas seulement le symptôme : chercher une
        // suppression quand le contenu a été modifié fait perdre du temps au
        // moment où il en manque le plus.
        const diagnostic = chainageRompu
          ? `le chaînage ne correspond plus — une entrée a été SUPPRIMÉE ou ` +
            `insérée hors de l'application`
          : `l'empreinte de cette entrée ne correspond plus à son contenu — ` +
            `elle a été MODIFIÉE hors de l'application`;

        this.logger?.error(
          `Chaîne d'audit ROMPUE à l'entrée ${row.id} du tenant ` +
            `${tenantId.slice(0, 8)}… : ${diagnostic}. Le journal n'est plus ` +
            `opposable. Conservez une copie de la base avant toute action, ` +
            `puis identifiez qui détenait un accès direct à PostgreSQL.`,
        );
        return { valid: false, checked: rows.rows.length, brokenAt: broken };
      }

      previous = row.empreinte;
    }

    this.logger?.debug(
      `Chaîne d'audit vérifiée : ${rows.rows.length} entrée(s) cohérentes`,
    );
    return { valid: true, checked: rows.rows.length };
  }

  /** Entrées d'un tenant, les plus récentes d'abord. */
  async list(
    tenantId: string,
    opts: { limit?: number; ressourceId?: string } = {},
  ): Promise<unknown[]> {
    const limit = Math.min(opts.limit ?? 100, 1000);
    const r = opts.ressourceId
      ? await sql`
          select * from journal_audit
          where tenant_id = ${tenantId} and ressource_id = ${opts.ressourceId}
          order by id desc limit ${limit}
        `.execute(this.db)
      : await sql`
          select * from journal_audit
          where tenant_id = ${tenantId}
          order by id desc limit ${limit}
        `.execute(this.db);
    return r.rows;
  }
}
