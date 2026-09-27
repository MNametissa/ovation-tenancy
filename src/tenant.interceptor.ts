import {
  Injectable,
  Inject,
  Optional,
  type CallHandler,
  type ExecutionContext,
  type NestInterceptor,
} from '@nestjs/common';
import { TenantContext } from './context/tenant-context.js';
import type { Observable } from 'rxjs';

/**
 * Pose le contexte de tenant UNE FOIS par requête HTTP.
 *
 * Responsabilité unique : lire l'identité de la requête, ouvrir le contexte,
 * déléguer. Aucune règle d'autorisation ici — c'est le rôle du guard CASL.
 *
 * POURQUOI PAR REQUÊTE ET NON PAR TRANSACTION — mesuré en phase 3 :
 *
 *   | Configuration                              | Débit      |
 *   |--------------------------------------------|------------|
 *   | contexte rechargé à chaque transaction     | 215 tx/s   |
 *   | contexte chargé une fois par requête HTTP  | 513 tx/s   |
 *
 * 101 % du surcoût était la requête SQL de chargement (1,845 ms) ; construire
 * les règles coûte 0,0035 ms. Déplacer le chargement ici, et non plus haut
 * (un cache entre requêtes), est le seul point qui gagne le débit SANS perdre
 * la révocation immédiate.
 *
 * CE QU'IL NE FAIT PAS : il ne lit aucun jeton et ne vérifie aucune signature.
 * L'authentification est T4.1 ; d'ici là, `extractIdentity` est le seul point
 * à remplacer.
 */

export interface RequestIdentity {
  tenantId: string;
  userId?: string;
}

/**
 * Source de l'identité d'une requête.
 *
 * Interface séparée pour que l'arrivée de Better Auth (T4.1) remplace une
 * implémentation, sans toucher à l'intercepteur.
 */
export abstract class IdentitySource {
  /**
   * Peut être ASYNCHRONE : la source réelle (`SessionIdentitySource`) lit la
   * session puis interroge la base pour établir le tenant. Le type l'admet
   * explicitement, plutôt que de laisser un `await` implicite décider.
   */
  abstract extract(
    request: unknown,
  ): RequestIdentity | undefined | Promise<RequestIdentity | undefined>;
}

/** Clé de mémoïsation de l'identité sur l'objet requête. */
const IDENTITE = Symbol('tenancy.identite');

/**
 * Posé à `true` par une source d'identité quand la requête porte une session
 * VALIDE — même si cette session n'ouvre aucune appartenance.
 *
 * C'est ce qui permet au garde de distinguer « non connecté » (401) de
 * « connecté mais sans accès à cette organisation » (403). Les confondre disait
 * « Connectez-vous » à quelqu'un qui l'était déjà — trouvé en test manuel.
 */
export const SESSION_VALIDE = Symbol('tenancy.sessionValide');

/**
 * Résout l'identité UNE SEULE FOIS par requête, pour le garde ET l'intercepteur.
 *
 * DÉFAUT CORRIGÉ, trouvé en test manuel : NestJS exécute les gardes AVANT les
 * intercepteurs (« Guards are executed after all middleware, but before any
 * interceptor or pipe » — doc officielle). Le `PermissionGuard` lisait donc un
 * contexte de tenant que l'intercepteur n'avait pas encore posé : il rendait
 * 401 à TOUT le monde, y compris à un utilisateur détenant la permission. La
 * route gardée était inaccessible, et aucun test ne le voyait, parce que seul le
 * cas « sans session → 401 » était testé.
 *
 * La mémoïsation évite de payer deux fois la résolution (session + base) : elle
 * est sur le chemin de chaque requête authentifiée.
 */
export function resoudreIdentite(
  source: IdentitySource,
  requete: unknown,
): Promise<RequestIdentity | undefined> {
  const req = requete as Record<symbol, unknown> | undefined;
  if (!req || typeof req !== 'object') {
    return Promise.resolve(source.extract(requete));
  }
  const deja = req[IDENTITE] as Promise<RequestIdentity | undefined> | undefined;
  if (deja) return deja;
  const promesse = Promise.resolve(source.extract(requete));
  req[IDENTITE] = promesse;
  return promesse;
}

export const IGNORER_CONTEXTE = Symbol('tenancy.ignorerContexte');

@Injectable()
export class TenantInterceptor implements NestInterceptor {
  constructor(
    private readonly tenantContext: TenantContext,
    private readonly identity: IdentitySource,
    @Optional()
    @Inject(IGNORER_CONTEXTE)
    private readonly ignorer?: (requete: unknown) => boolean,
  ) {}

  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<unknown> | Promise<Observable<unknown>> {
    // Hors HTTP (tâche planifiée, consommateur de messages), il n'y a pas de
    // requête : on laisse passer sans contexte. L'échec fermé de la RLS rendra
    // 0 ligne, et `TenantContext` avertira avec l'action corrective.
    if (context.getType() !== 'http') return next.handle();

    // Les routes d'authentification (Better Auth) n'ont pas de tenant. Y
    // résoudre l'identité ferait répondre 403 à `get-session` et `sign-out`
    // pour un `X-Tenant-Id` périmé (L2-4) : le front ne pourrait plus ni lire
    // sa session ni se déconnecter.
    if (this.ignorer?.(context.switchToHttp().getRequest())) return next.handle();

    // `await` obligatoire : l'extraction interroge la base pour établir le
    // tenant depuis la session. Sans lui, `scope` serait une Promise — donc
    // toujours vraie — et `tenantContext.run` recevrait un objet sans
    // `tenantId`. Le contexte serait posé avec `undefined`, la RLS rendrait
    // 0 ligne partout, et rien ne le signalerait.
    return this.poser(context, next);
  }

  private async poser(
    context: ExecutionContext,
    next: CallHandler,
  ): Promise<Observable<unknown>> {
    const scope = await resoudreIdentite(
      this.identity,
      context.switchToHttp().getRequest(),
    );
    if (!scope) return next.handle();

    return this.tenantContext.run(scope, async () => next.handle());
  }
}
