import { type Kysely, sql } from 'kysely';
import type { TenancyLogger } from '../logging.js';

/**
 * Rôles configurables.
 *
 * Les rôles sont des DONNÉES, pas un enum : un tenant qui organise des
 * concours voudra « coach », une fédération « délégué régional ». Figer les
 * rôles imposerait une migration de schéma à chaque besoin.
 *
 * La distinction structurante :
 *   - les PERMISSIONS forment un catalogue FERMÉ — chacune correspond à du
 *     code qui l'applique ; une permission sans garde ne protège rien ;
 *   - les RÔLES sont des assemblages LIBRES de ces permissions.
 */

export interface RoleInput {
  code: string;
  libelle: string;
  description?: string;
  /** Le rôle exige-t-il une portée sur une ressource ? */
  porteeRequise?: boolean;
  /** Codes de permissions. Doivent exister au catalogue. */
  permissions: string[];
}

export interface Role {
  id: string;
  tenantId: string | null;
  code: string;
  libelle: string;
  description: string | null;
  systeme: boolean;
  porteeRequise: boolean;
}

/** Les sept rôles système livrés. Modifiables par le tenant, non supprimables. */
export const SYSTEM_ROLES: RoleInput[] = [
  {
    code: 'proprietaire',
    libelle: 'Propriétaire',
    description: 'Tous les droits, y compris facturation et suppression',
    permissions: ['*'],
  },
  {
    code: 'administrateur',
    libelle: 'Administrateur',
    description: 'Configure les évènements et gère les membres',
    permissions: [],
  },
  {
    code: 'organisateur',
    libelle: 'Organisateur',
    description: 'Gère un évènement précis',
    porteeRequise: true,
    permissions: [],
  },
  {
    code: 'moderateur',
    libelle: 'Modérateur',
    description: 'Valide les candidatures, traite les signalements',
    permissions: [],
  },
  {
    code: 'jure',
    libelle: 'Juré',
    description: 'Accède à sa grille de notation, et à elle seule',
    porteeRequise: true,
    permissions: [],
  },
  {
    code: 'observateur',
    libelle: 'Observateur',
    description: 'Lecture seule du journal d’audit',
    permissions: ['audit.read'],
  },
  {
    code: 'tresorier',
    libelle: 'Trésorier',
    description: 'Flux financiers — jamais les votes ni les notes',
    permissions: [],
  },
];

export class RoleService {
  constructor(
    private readonly db: Kysely<any>,
    private readonly logger?: TenancyLogger,
  ) {}

  /**
   * Installe les rôles système manquants.
   *
   * Idempotent : un rôle déjà présent n'est pas écrasé — le tenant a pu le
   * modifier, et cette modification lui appartient.
   */
  async ensureSystemRoles(): Promise<string[]> {
    const created: string[] = [];

    for (const r of SYSTEM_ROLES) {
      const existing = await sql<{ id: string }>`
        select id from role where tenant_id is null and code = ${r.code}
      `.execute(this.db);

      if (existing.rows.length > 0) {
        this.logger?.debug(`Rôle système « ${r.code} » déjà présent`);
        continue;
      }

      const ins = await sql<{ id: string }>`
        insert into role (tenant_id, code, libelle, description, systeme, portee_requise)
        values (null, ${r.code}, ${r.libelle}, ${r.description ?? null}, true,
                ${r.porteeRequise ?? false})
        returning id
      `.execute(this.db);

      const roleId = ins.rows[0].id;
      // TOLÉRANT pour les rôles système : ils sont livrés avec la
      // bibliothèque, alors que le catalogue dépend de l'application hôte.
      // Un rôle `observateur` qui déclare `audit.read` ne doit pas empêcher
      // le démarrage d'une application qui n'expose pas encore cette route.
      //
      // DÉCOUVERT EN INTÉGRATION : la version stricte faisait planter
      // `ensureSystemRoles()` au démarrage de toute application dont le
      // catalogue ne contenait pas exactement les permissions attendues.
      //
      // Pour un rôle créé par un TENANT, la règle reste stricte : c'est une
      // saisie humaine, une permission inconnue y est une erreur.
      await this.attachPermissions(roleId, r.permissions, { tolerateUnknown: true });
      created.push(r.code);
      this.logger?.log(`Rôle système « ${r.code} » créé`);
    }

    return created;
  }

  /**
   * Crée un rôle propre à un tenant.
   *
   * @throws si le code entre en collision avec un rôle système ou existant.
   */
  async createTenantRole(tenantId: string, input: RoleInput): Promise<Role> {
    const clash = await sql<{ systeme: boolean }>`
      select systeme from role
      where code = ${input.code} and (tenant_id is null or tenant_id = ${tenantId})
    `.execute(this.db);

    if (clash.rows.length > 0) {
      const kind = clash.rows[0].systeme ? 'système' : 'de ce tenant';
      throw new Error(
        `Un rôle ${kind} porte déjà le code « ${input.code} ». ` +
          `Choisissez un autre code : les codes doivent être uniques au sein ` +
          `d'un tenant, rôles système inclus.`,
      );
    }

    const ins = await sql<Role>`
      insert into role (tenant_id, code, libelle, description, systeme, portee_requise)
      values (${tenantId}, ${input.code}, ${input.libelle},
              ${input.description ?? null}, false, ${input.porteeRequise ?? false})
      returning id, tenant_id as "tenantId", code, libelle, description,
                systeme, portee_requise as "porteeRequise"
    `.execute(this.db);

    const role = ins.rows[0];
    await this.attachPermissions(role.id, input.permissions);
    this.logger?.log(`Rôle « ${input.code} » créé pour le tenant ${tenantId.slice(0, 8)}…`);
    return role;
  }

  /**
   * Attache des permissions à un rôle.
   *
   * Une permission inconnue du catalogue est REFUSÉE : le catalogue décrit ce
   * que le code sait faire respecter, et cocher une case qui ne protège rien
   * donne un faux sentiment de sécurité.
   */
  async attachPermissions(
    roleId: string,
    codes: string[],
    opts: { tolerateUnknown?: boolean } = {},
  ): Promise<void> {
    if (codes.length === 0) return;

    // Le joker '*' du rôle propriétaire : toutes les permissions du catalogue.
    const effective = codes.includes('*')
      ? (
          await sql<{ code: string }>`
            select code from permission where obsolete_le is null
          `.execute(this.db)
        ).rows.map((r) => r.code)
      : codes;

    if (effective.length === 0) return;

    const found = await sql<{ id: string; code: string }>`
      select id, code from permission where code = any(${effective})
    `.execute(this.db);

    const known = new Set(found.rows.map((r) => r.code));
    const unknown = effective.filter((c) => !known.has(c));

    if (unknown.length > 0) {
      const explication =
        `Le catalogue décrit ce que le CODE sait faire respecter — une ` +
        `permission qui n'y figure pas ne protège rien.`;

      if (!opts.tolerateUnknown) {
        throw new Error(
          `Permission(s) inconnue(s) du catalogue : ${unknown.join(', ')}. ` +
            `${explication} Vérifiez qu'un garde l'applique, puis relancez ` +
            `la découverte.`,
        );
      }

      // Rôle système : on continue, mais le développeur DOIT savoir que ces
      // permissions sont déclarées sans être appliquées par du code.
      this.logger?.warn(
        `Rôle système : permission(s) absente(s) du catalogue ignorée(s) — ` +
          `${unknown.join(', ')}. ${explication} Le rôle est créé sans ` +
          `elles. Si votre application doit les appliquer, ajoutez le garde ` +
          `correspondant puis relancez la découverte et ce service.`,
      );
    }

    for (const row of found.rows) {
      await sql`
        insert into role_permission (role_id, permission_id)
        values (${roleId}, ${row.id})
        on conflict do nothing
      `.execute(this.db);
    }
  }

  /**
   * Supprime un rôle propre à un tenant.
   *
   * Refuse un rôle système, et refuse un rôle encore attribué : supprimer
   * silencieusement retirerait l'accès à des utilisateurs sans trace.
   */
  async deleteTenantRole(tenantId: string, code: string): Promise<void> {
    const r = await sql<{ id: string; systeme: boolean }>`
      select id, systeme from role
      where code = ${code} and (tenant_id = ${tenantId} or tenant_id is null)
    `.execute(this.db);

    if (r.rows.length === 0) {
      throw new Error(`Rôle « ${code} » introuvable pour ce tenant.`);
    }
    if (r.rows[0].systeme) {
      throw new Error(
        `Le rôle système « ${code} » ne peut pas être supprimé. ` +
          `Vous pouvez en revanche modifier ses permissions, ou créer un ` +
          `rôle propre à votre organisation.`,
      );
    }

    const used = await sql<{ n: number }>`
      select count(*)::int as n from appartenance where role_id = ${r.rows[0].id}
    `.execute(this.db);

    if (used.rows[0].n > 0) {
      throw new Error(
        `Le rôle « ${code} » est attribué à ${used.rows[0].n} membre(s). ` +
          `Réattribuez-les d'abord : supprimer le rôle leur retirerait ` +
          `l'accès sans autre trace.`,
      );
    }

    await sql`delete from role where id = ${r.rows[0].id}`.execute(this.db);
    this.logger?.log(`Rôle « ${code} » supprimé`);
  }

  /** Rôles visibles d'un tenant : les siens plus les rôles système. */
  async listRoles(tenantId: string): Promise<Role[]> {
    const r = await sql<Role>`
      select id, tenant_id as "tenantId", code, libelle, description,
             systeme, portee_requise as "porteeRequise"
      from role
      where tenant_id is null or tenant_id = ${tenantId}
      order by systeme desc, code
    `.execute(this.db);
    return r.rows;
  }
}
