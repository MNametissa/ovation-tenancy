import { AbilityBuilder, createMongoAbility, type MongoAbility } from '@casl/ability';
import { type Kysely, sql } from 'kysely';
import type { TenancyLogger } from '../logging.js';

/**
 * Autorisation applicative — CASL.
 *
 * DEUX BARRIÈRES, PAS UNE. CASL ne remplace pas la RLS :
 *
 *   RLS   protège la DONNÉE. Même si un garde est oublié sur une route, la
 *         base ne rend rien. C'est le filet.
 *   CASL  protège l'INTENTION et produit une erreur UTILE : un 403 explicite
 *         plutôt qu'un 404 silencieux ou une liste vide inexpliquée.
 *
 * Mesuré en phase 0 : la défense en profondeur est gratuite — 3 466 tx/s
 * contre 3 434 pour la RLS seule.
 *
 * Sans CASL, un utilisateur sans droit obtient une liste vide et croit qu'il
 * n'y a rien à voir. C'est exactement le cas que la règle « si le dev oublie,
 * on le lui rappelle » vise — appliquée ici à l'utilisateur final.
 */

export type Action = string;
export type Subject = string;
export type AppAbility = MongoAbility<[Action, Subject]>;

export interface AbilityContext {
  tenantId: string;
  userId: string;
  /** Codes de permissions détenus, tels qu'en base. */
  permissions: string[];
  /** Ressources sur lesquelles l'utilisateur a une portée. */
  scopedResourceIds: string[];
  /**
   * Chaque permission AVEC la portée de l'appartenance qui l'accorde.
   * Présent : fait foi. Absent : repli sur `scopedResourceIds` (historique).
   *
   * Sans lui, une seule portée restreignait TOUTES les permissions : un
   * propriétaire nommé juré sur un évènement perdait ses droits sur les autres.
   */
  grants?: Array<{ code: string; portee: string | null }>;
}

/**
 * Construit les règles à partir des permissions détenues.
 *
 * Convention : une permission `resource.action` devient `can(action, resource)`.
 * Les suffixes `.own` et `.all` sont interprétés :
 *
 *   score.read.own  → can('read', 'score', { ownerId: userId })
 *   score.read.all  → can('read', 'score')            (sans condition)
 *   event.publish   → can('publish', 'event')
 *
 * Et une permission accordée par une appartenance à portée ne vaut que sur ses
 * ressources — PAR APPARTENANCE, pas pour tout l'utilisateur :
 *
 *   event.update + portée sur E1 → can('update', 'event', { id: { $in: [E1] } })
 *   … sauf si une AUTRE appartenance, sans portée, accorde aussi event.update.
 */
export function buildAbility(ctx: AbilityContext): AppAbility {
  const { can, build } = new AbilityBuilder<AppAbility>(createMongoAbility);

  for (const code of ctx.permissions) {
    const parts = code.split('.');
    if (parts.length < 2) continue;

    const resource = parts[0];
    const modifier = parts[parts.length - 1];
    const hasModifier = modifier === 'own' || modifier === 'all';
    const action = hasModifier
      ? parts.slice(1, -1).join('.')
      : parts.slice(1).join('.');

    if (!action) continue;

    if (modifier === 'own') {
      // Ne voit que ce qui lui appartient. La RLS l'impose déjà côté base ;
      // CASL le dit côté application, pour produire un 403 explicite.
      can(action, resource, { ownerId: ctx.userId } as never);
      continue;
    }

    if (modifier === 'all') {
      can(action, resource);
      continue;
    }

    // Permission simple : limitée à la portée DES APPARTENANCES QUI L'ACCORDENT.
    const portees = porteesDe(ctx, code);
    if (portees === 'partout') {
      can(action, resource);
    } else {
      can(action, resource, { id: { $in: portees } } as never);
    }
  }

  return build();
}

/** `partout` si une appartenance SANS portée accorde ce code ; sinon ses portées. */
function porteesDe(ctx: AbilityContext, code: string): 'partout' | string[] {
  if (!ctx.grants) {
    return ctx.scopedResourceIds.length > 0 ? ctx.scopedResourceIds : 'partout';
  }
  const g = ctx.grants.filter((x) => x.code === code);
  if (g.some((x) => x.portee === null)) return 'partout';
  return [...new Set(g.map((x) => x.portee as string))];
}

/**
 * Charge le contexte d'autorisation depuis la base.
 *
 * Lu à CHAQUE requête, jamais mis en cache ni porté par un jeton : c'est ce
 * qui rend la révocation immédiate. Le coût est nul en pratique — la
 * transaction lit déjà la base pour poser le contexte RLS.
 */
export async function loadAbilityContext(
  db: Kysely<any>,
  tenantId: string,
  userId: string,
  logger?: TenancyLogger,
): Promise<AbilityContext> {
  const rows = await sql<{ code: string; portee: string | null }>`
    select p.code, a.portee_ressource_id as portee
    from appartenance a
    join role_permission rp on rp.role_id = a.role_id
    join permission p       on p.id = rp.permission_id
    where a.utilisateur_id = ${userId}
      and a.tenant_id = ${tenantId}
      and p.obsolete_le is null
  `.execute(db);

  const permissions = [...new Set(rows.rows.map((r) => r.code))];
  const scopedResourceIds = [
    ...new Set(rows.rows.map((r) => r.portee).filter((x): x is string => !!x)),
  ];

  if (permissions.length === 0) {
    logger?.debug(
      `Aucune permission pour l'utilisateur ${userId.slice(0, 8)}… dans le ` +
        `tenant ${tenantId.slice(0, 8)}… — toute action sera refusée`,
    );
  }

  const grants = rows.rows.map((r) => ({ code: r.code, portee: r.portee }));

  return { tenantId, userId, permissions, scopedResourceIds, grants };
}

/**
 * Erreur d'autorisation portant le motif exact du refus.
 *
 * Sans cela, l'utilisateur obtient une liste vide et croit qu'il n'y a rien à
 * voir ; le développeur, lui, cherche un bug qui n'existe pas.
 */
export class ForbiddenError extends Error {
  constructor(
    readonly action: string,
    readonly subject: string,
    readonly reason: string,
  ) {
    super(
      `Action « ${action} » refusée sur « ${subject} » : ${reason}. ` +
        `Vérifiez les permissions du rôle de cet utilisateur dans ce tenant.`,
    );
    this.name = 'ForbiddenError';
  }
}

/**
 * Vérifie une action, et explique le refus.
 *
 * @throws ForbiddenError avec le motif précis.
 */
/**
 * PIÈGE MESURÉ : interrogé sur un TYPE sans instance, CASL rend `true` dès
 * qu'une règle existe — il ne peut pas évaluer une condition sans objet.
 *
 *   ability.can('publish', 'event')             → true  (règle existante)
 *   ability.can('publish', { id: EV_2, … })     → false (hors portée)
 *
 * Une vérification sans instance ne prouve donc RIEN sur la portée. Toujours
 * passer la ressource quand elle est connue ; sinon on autorise un
 * organisateur à publier l'évènement d'un autre.
 */
export function assertCan(
  ability: AppAbility,
  action: string,
  subject: string,
  resource?: Record<string, unknown>,
): void {
  const target = resource ? { ...resource, __caslSubjectType__: subject } : subject;
  if (ability.can(action, target as never)) return;

  // Distinguer « aucune permission » de « permission mais hors portée » :
  // les deux se corrigent très différemment.
  const hasAnyRule = ability.rules.some(
    (r) => r.subject === subject && (r.action === action || r.action === 'manage'),
  );

  const reason = hasAnyRule
    ? resource
      ? `la permission existe, mais pas sur cette ressource (portée)`
      : `la permission existe, mais une condition n'est pas remplie`
    : `aucune permission « ${subject}.${action} » n'est attribuée`;

  throw new ForbiddenError(action, subject, reason);
}
