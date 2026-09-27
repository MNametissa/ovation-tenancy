import {
  CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Inject } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ResolutionPermissions, CONNEXION_TENANCY, SESSION_REQUISE } from './tokens.js';
import { type Kysely, sql } from 'kysely';
import {
  IdentitySource,
  SESSION_VALIDE,
  resoudreIdentite,
  type RequestIdentity,
} from './tenant.interceptor.js';

/**
 * Applique les permissions découvertes — le garde qui manquait.
 *
 * TROUVÉ PAR `npm run audit:exposure` (T4.8) : `GET /permissions` rendait **200
 * sans session** et exposait la carte des droits de la plateforme. Le catalogue
 * savait quelle permission gardait la route ; rien ne l'appliquait.
 *
 * C'est exactement le motif du garde muet de la phase 3 : un mécanisme qui décrit
 * une protection sans l'exercer. `permission-discovery` produit la carte,
 * `RoleService` refuse les permissions absentes du catalogue — et entre les deux,
 * aucun contrôle à l'exécution.
 *
 * TROIS COUCHES, et il faut les trois :
 *
 *   1. ce garde — refuse la requête avant d'atteindre le contrôleur ;
 *   2. CASL — évalue la PORTÉE sur l'instance (un organisateur sur SON évènement) ;
 *   3. la RLS — dernier rempart, rend 0 ligne si les deux premières tombent.
 *
 * Ce garde est le premier filtre, pas le seul. Il répond à « cet utilisateur a-t-il
 * ce droit dans ce tenant ? », pas à « sur cet objet précis ? ».
 *
 * IL RÉSOUT L'IDENTITÉ LUI-MÊME. Première version : il lisait `TenantContext`,
 * posé par l'intercepteur — or NestJS exécute les gardes AVANT les
 * intercepteurs. Le contexte était donc toujours vide, et le garde rendait 401 à
 * tout le monde, y compris au détenteur de la permission. Trouvé en test manuel ;
 * la couverture du fichier était de 22 %.
 */
@Injectable()
export class PermissionGuard implements CanActivate {
  private readonly logger = new Logger(PermissionGuard.name);

  constructor(
    private readonly discovery: ResolutionPermissions,
    private readonly identity: IdentitySource,
    @Inject(CONNEXION_TENANCY) private readonly db: Kysely<any>,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Hors HTTP, il n'y a pas de requête à garder : une tâche planifiée tourne
    // sous sa propre responsabilité, et la RLS reste le rempart.
    if (context.getType() !== 'http') return true;

    // `resolve(cible, nomDeMethode)` : l'API réelle du paquet rend la CLÉ.
    const permission = this.discovery.resolve(
      context.getClass(),
      context.getHandler().name,
    );

    /**
     * Aucune permission découverte = route PUBLIQUE, marquée `@PublicHandler()`.
     *
     * Si `permission-discovery` échouait silencieusement, TOUTES les routes
     * deviendraient publiques. C'est pourquoi `failOnAmbiguous: true` bloque le
     * démarrage sur une route non classable : l'échec est FERMÉ au bootstrap.
     */
    if (!permission) {
      // `@SessionRequise()` : pas de permission propre (elle dépend de l'instance
      // ou du corps), mais une identité EST exigée. `@PublicHandler()` seul
      // rendrait la route ouverte.
      const sessionRequise = this.reflector.getAllAndOverride<boolean>(
        SESSION_REQUISE,
        [context.getHandler(), context.getClass()],
      );
      if (!sessionRequise) return true;
      await this.exigerIdentite(context, 'une session et une appartenance');
      return true;
    }

    const scope = await this.exigerIdentite(
      context,
      `la permission « ${permission} »`,
      permission,
    );

    /**
     * `app_a_permission()` — la fonction SECURITY DEFINER de la phase 3, dans
     * une transaction où l'on pose NOUS-MÊMES `app.tenant` et `app.user` : le
     * contexte de l'intercepteur n'existe pas encore à ce stade.
     */
    const autorise = await this.db.transaction().execute(async (trx) => {
      await sql`select set_config('app.tenant', ${scope.tenantId}, true)`.execute(trx);
      await sql`select set_config('app.user', ${scope.userId}, true)`.execute(trx);
      const r = await sql<{ ok: boolean }>`
        select app_a_permission(${permission}) as ok
      `.execute(trx);
      return r.rows[0]?.ok === true;
    });

    if (!autorise) {
      this.logger.warn(
        `Accès refusé : « ${permission} » manquante pour l'utilisateur ` +
          `${scope.userId.slice(0, 8)}… dans le tenant ${scope.tenantId.slice(0, 8)}…. ` +
          `Si ce droit devait être accordé, ajoutez la permission au rôle de cet ` +
          `utilisateur — le catalogue la contient déjà.`,
      );
      throw new ForbiddenException({
        message:
          `Permission « ${permission} » requise. Votre rôle dans cette ` +
          `organisation ne la porte pas. Demandez-la à un administrateur.`,
        permission,
      });
    }

    return true;
  }

  /** 401 sans session ; 403 si la session n'ouvre aucune appartenance. */
  private async exigerIdentite(
    context: ExecutionContext,
    exigence: string,
    permission?: string,
  ): Promise<RequestIdentity & { userId: string }> {
    const requete = context.switchToHttp().getRequest<Record<symbol, unknown>>();
    const scope = await resoudreIdentite(this.identity, requete);
    if (scope?.userId) return scope as RequestIdentity & { userId: string };
    if (requete[SESSION_VALIDE]) {
      // Connecté, mais sans appartenance dans aucune organisation. Lui dire
      // « Connectez-vous » était faux — trouvé en test manuel.
      throw new ForbiddenException({
        message:
          `Vous êtes connecté, mais votre compte n'appartient à aucune ` +
          `organisation — ${exigence} ne peut donc pas vous être accordée. ` +
          `Demandez à un administrateur de vous ajouter.`,
        ...(permission ? { permission } : {}),
      });
    }
    // 401 : le problème est l'absence d'identité, pas un droit manquant.
    throw new UnauthorizedException({
      message: `Authentification requise : cette route exige ${exigence}. Connectez-vous, puis réessayez.`,
      ...(permission ? { permission } : {}),
    });
  }
}
