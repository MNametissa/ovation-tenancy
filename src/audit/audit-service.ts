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
    //
    // TOUT se fait en SQL (audit de performance du 2026-09-27) : `lag()` donne
    // le maillon attendu, la base ne rend que le compte, le dernier maillon et
    // la PREMIÈRE rupture. Mémoire constante côté Node — la version précédente
    // chargeait toutes les entrées (290 Mo mesurés).
    //
    // Deux vérifications indépendantes, et il faut les DEUX :
    //   1. le chaînage — une entrée retirée décale les liens ;
    //   2. l'empreinte de l'entrée — un contenu modifié ne correspond plus.
    // LA formule du trigger (`app_empreinte_audit`), et non une copie : une
    // copie divergeait déjà une fois (format d'horodatage).
    const r = await sql<{
      nombre: string;
      dernier_id: string | null;
      derniere: Buffer | null;
      id: string | null;
      chainage: boolean | null;
      attendu: Buffer | null;
      trouve: Buffer | null;
    }>`
      with c as (
        select j.id, j.empreinte, j.empreinte_precedente,
               lag(j.empreinte) over (order by j.id) as prec_attendue,
               app_empreinte_audit(j.empreinte_precedente, j) as recalculee
        from journal_audit j
        where j.tenant_id = ${tenantId}
      ),
      rupture as (
        select id,
               empreinte_precedente is distinct from prec_attendue as chainage,
               case when empreinte_precedente is distinct from prec_attendue
                    then prec_attendue else recalculee end as attendu,
               case when empreinte_precedente is distinct from prec_attendue
                    then empreinte_precedente else empreinte end as trouve
        from c
        where empreinte_precedente is distinct from prec_attendue
           or empreinte <> recalculee
        order by id limit 1
      ),
      fin as (select count(*) as nombre, max(id) as dernier_id from c)
      select fin.nombre, fin.dernier_id,
             (select c.empreinte from c where c.id = fin.dernier_id) as derniere,
             rupture.id, rupture.chainage, rupture.attendu, rupture.trouve
      from fin left join rupture on true
    `.execute(this.db);
    const v = r.rows[0];
    const nombre = Number(v.nombre);

    if (v.id !== null) {
      const hex = (b: Buffer | null) => (b ? b.toString('hex') : '').slice(0, 16);
      // Nommer le DIAGNOSTIC, pas seulement le symptôme : chercher une
      // suppression quand le contenu a été modifié fait perdre du temps au
      // moment où il en manque le plus.
      const diagnostic = v.chainage
        ? `le chaînage ne correspond plus — une entrée a été SUPPRIMÉE ou ` +
          `insérée hors de l'application`
        : `l'empreinte de cette entrée ne correspond plus à son contenu — ` +
          `elle a été MODIFIÉE hors de l'application`;
      this.logger?.error(
        `Chaîne d'audit ROMPUE à l'entrée ${v.id} du tenant ` +
          `${tenantId.slice(0, 8)}… : ${diagnostic}. Le journal n'est plus ` +
          `opposable. Conservez une copie de la base avant toute action, ` +
          `puis identifiez qui détenait un accès direct à PostgreSQL.`,
      );
      return {
        valid: false,
        checked: nombre,
        brokenAt: { id: String(v.id), expected: hex(v.attendu), found: hex(v.trouve) },
      };
    }

    const queue = await this.verifierTete(tenantId, {
      nombre,
      dernierId: v.dernier_id,
      derniere: v.derniere,
    });
    if (queue) return queue;

    this.logger?.debug(`Chaîne d'audit vérifiée : ${nombre} entrée(s) cohérentes`);
    return { valid: true, checked: nombre };
  }

  /**
   * Compare la fin de la chaîne à la TÊTE tenue à part (`audit_chaine_tete`,
   * migration 007) : nombre d'entrées et dernier maillon.
   *
   * Sans elle, supprimer la DERNIÈRE entrée — ou toute la chaîne — laissait une
   * chaîne cohérente, donc « valide ». Une tête sans entrée, ou des entrées
   * sans tête, sont aussi une rupture.
   *
   * @returns le résultat d'échec, ou `null` si la fin de chaîne concorde.
   */
  private async verifierTete(
    tenantId: string,
    fin: { nombre: number; dernierId: string | null; derniere: Buffer | null },
  ): Promise<ChainVerification | null> {
    const t = await sql<{ nombre: string; dernier_id: string; derniere: Buffer }>`
      select nombre, dernier_id, derniere_empreinte as derniere
      from audit_chaine_tete where tenant_id = ${tenantId}
    `.execute(this.db);
    const tete = t.rows[0] as (typeof t.rows)[number] | undefined;
    if (!tete && fin.nombre === 0) return null;
    if (
      tete &&
      fin.derniere &&
      Number(tete.nombre) === fin.nombre &&
      String(tete.dernier_id) === String(fin.dernierId) &&
      tete.derniere.equals(fin.derniere)
    ) {
      return null;
    }
    const attendu = tete
      ? `${tete.nombre} entrée(s), dernière n° ${tete.dernier_id}`
      : 'aucune tête de chaîne';
    const trouve =
      fin.nombre > 0
        ? `${fin.nombre} entrée(s), dernière n° ${fin.dernierId}`
        : 'aucune entrée';
    this.logger?.error(
      `Chaîne d'audit ROMPUE en FIN de chaîne du tenant ${tenantId.slice(0, 8)}… : ` +
        `attendu ${attendu}, trouvé ${trouve}. Des entrées ont été SUPPRIMÉES ` +
        `(queue tronquée ou chaîne effacée) hors de l'application. Conservez une ` +
        `copie de la base avant toute action.`,
    );
    return {
      valid: false,
      checked: fin.nombre,
      brokenAt: {
        id: String(tete?.dernier_id ?? fin.dernierId ?? ''),
        expected: attendu,
        found: trouve,
      },
    };
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
