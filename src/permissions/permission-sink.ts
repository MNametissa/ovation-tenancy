import { type Kysely, sql } from 'kysely';
import type { TenancyLogger } from '../logging.js';

/**
 * Puits de permissions : persiste le catalogue découvert par
 * `permission-discovery`.
 *
 * Implémente l'interface `PermissionSink` de ce paquet sans en dépendre —
 * la forme minimale attendue est décrite ci-dessous. C'est ce qui garde les
 * deux bibliothèques indépendantes.
 *
 * RÈGLE CENTRALE : une permission disparue du code est marquée OBSOLÈTE,
 * jamais supprimée. Un rôle peut y référer ; la supprimer casserait ce rôle
 * en silence, et `role_permission.permission_id` est en ON DELETE RESTRICT
 * précisément pour l'empêcher.
 */

export interface DiscoveredPermission {
  key: string;
  resource?: string;
  action?: string;
  description?: string;
  origin?: string;
  ambiguous?: boolean;
}

export interface DiscoveredCatalog {
  permissions: DiscoveredPermission[];
}

export interface SyncReport {
  /** Nouvelles permissions insérées. */
  added: string[];
  /** Permissions déjà présentes, métadonnées rafraîchies. */
  updated: string[];
  /** Permissions disparues du code, marquées obsolètes. */
  obsoleted: string[];
  /** Permissions obsolètes réapparues dans le code. */
  revived: string[];
  /** Obsolètes encore référencées par un rôle : à nettoyer à la main. */
  stillReferenced: Array<{ code: string; roles: number }>;
}

export class PermissionSink {
  constructor(
    private readonly db: Kysely<any>,
    private readonly logger?: TenancyLogger,
  ) {}

  async sync(catalog: DiscoveredCatalog): Promise<SyncReport> {
    const report: SyncReport = {
      added: [],
      updated: [],
      obsoleted: [],
      revived: [],
      stillReferenced: [],
    };

    const discovered = new Map(catalog.permissions.map((p) => [p.key, p]));

    const existing = await sql<{ code: string; obsolete_le: Date | null }>`
      select code, obsolete_le from permission
    `.execute(this.db);
    const known = new Map(existing.rows.map((r) => [r.code, r.obsolete_le]));

    // ── Insertions et réveils ────────────────────────────────────────────
    for (const [code, p] of discovered) {
      // MESURÉ : `rest.join('.')` rend TOUJOURS une chaîne — `''` pour un code
      // sans point comme « ping ». Un `?? code` ne se déclenchait donc jamais
      // ('' n'est pas nullish) et le libellé partait VIDE en base. D'où `||`,
      // qui traite la chaîne vide, et un repli calculé une seule fois.
      const [premier, ...rest] = code.split('.');
      const resource = premier || 'general';
      const action = rest.join('.') || code;

      if (!known.has(code)) {
        await sql`
          insert into permission (code, libelle, description, domaine, source)
          values (${code}, ${p.action ?? action},
                  ${p.description ?? null},
                  ${p.resource ?? resource},
                  ${p.origin ?? 'convention'})
        `.execute(this.db);
        report.added.push(code);
        continue;
      }

      if (known.get(code) !== null) {
        // Elle était obsolète et revient : on la réveille plutôt que d'en
        // créer une seconde, sinon les rôles qui y référaient restent
        // rattachés à la version morte.
        await sql`update permission set obsolete_le = null where code = ${code}`.execute(
          this.db,
        );
        report.revived.push(code);
        this.logger?.log(
          `Permission « ${code} » réapparue dans le code : réactivée. ` +
            `Les rôles qui la portaient retrouvent leur effet.`,
        );
        continue;
      }

      await sql`
        update permission
        set libelle = ${p.action ?? action},
            description = ${p.description ?? null},
            domaine = ${p.resource ?? resource},
            source = ${p.origin ?? 'convention'}
        where code = ${code}
      `.execute(this.db);
      report.updated.push(code);
    }

    // ── Obsolescence ─────────────────────────────────────────────────────
    for (const [code, obsoleteLe] of known) {
      if (discovered.has(code) || obsoleteLe !== null) continue;

      await sql`update permission set obsolete_le = now() where code = ${code}`.execute(
        this.db,
      );
      report.obsoleted.push(code);

      const used = await sql<{ n: number }>`
        select count(*)::int as n
        from role_permission rp
        join permission p on p.id = rp.permission_id
        where p.code = ${code}
      `.execute(this.db);

      if (used.rows[0].n > 0) {
        report.stillReferenced.push({ code, roles: used.rows[0].n });
        // Le développeur DOIT le savoir : un rôle porte une permission qui
        // n'est plus appliquée par aucun code. L'utilisateur croit avoir un
        // droit qui ne protège plus rien.
        this.logger?.warn(
          `Permission « ${code} » a disparu du code mais reste attribuée à ` +
            `${used.rows[0].n} rôle(s). Elle est marquée obsolète, PAS ` +
            `supprimée — un rôle y réfère. Retirez-la de ces rôles, ou ` +
            `restaurez le garde qui l'appliquait.`,
        );
      } else {
        this.logger?.log(
          `Permission « ${code} » marquée obsolète (aucun rôle ne l'utilise)`,
        );
      }
    }

    if (report.added.length) {
      this.logger?.log(`${report.added.length} permission(s) ajoutée(s) au catalogue`);
    }

    return report;
  }

  /** Permissions obsolètes encore attribuées — le ménage à faire. */
  async listObsoleteInUse(): Promise<Array<{ code: string; roles: string[] }>> {
    const r = await sql<{ code: string; role_code: string }>`
      select p.code, r.code as role_code
      from permission p
      join role_permission rp on rp.permission_id = p.id
      join role r on r.id = rp.role_id
      where p.obsolete_le is not null
      order by p.code, r.code
    `.execute(this.db);

    const byCode = new Map<string, string[]>();
    for (const row of r.rows) {
      const list = byCode.get(row.code) ?? [];
      list.push(row.role_code);
      byCode.set(row.code, list);
    }
    return [...byCode].map(([code, roles]) => ({ code, roles }));
  }
}
