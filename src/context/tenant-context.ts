import { Injectable, Inject, Optional } from '@nestjs/common';
import { ClsService } from 'nestjs-cls';
import { TransactionHost } from '@nestjs-cls/transactional';
import { type Kysely, sql } from 'kysely';
import { MSG, TENANCY_LOGGER, type TenancyLogger } from '../logging.js';

/**
 * Contexte de tenant, posé dans la transaction.
 *
 * C'est la pièce où l'oubli doit devenir IMPOSSIBLE, pas seulement inoffensif.
 * L'échec fermé protège la donnée ; ce service, lui, DIT au développeur ce qui
 * manque et comment le corriger.
 *
 * Deux variables de session, mesurées nécessaires en phase 0 :
 *
 *   app.tenant  isolation INTER-tenant
 *   app.user    isolation INTRA-tenant — sans elle, deux jurés du même tenant
 *               voient les notes l'un de l'autre
 *
 * `set_config(…, true)` : transaction-local. Avec `false`, la variable survit
 * au COMMIT et fuit vers la requête suivante sur la même connexion de pool.
 */

export const CLS_TENANT = 'tenancy.tenant';
export const CLS_USER = 'tenancy.user';

export interface TenantScope {
  tenantId: string;
  userId?: string;
}

@Injectable()
export class TenantContext {
  constructor(
    private readonly cls: ClsService,
    private readonly txHost: TransactionHost<any>,
    @Optional() @Inject(TENANCY_LOGGER) private readonly logger?: TenancyLogger,
  ) {}

  /** Tenant courant, ou `undefined` hors contexte. */
  get tenantId(): string | undefined {
    return this.cls.isActive() ? this.cls.get(CLS_TENANT) : undefined;
  }

  /** Utilisateur courant, ou `undefined`. */
  get userId(): string | undefined {
    return this.cls.isActive() ? this.cls.get(CLS_USER) : undefined;
  }

  /**
   * Exécute `fn` avec le contexte posé dans le CLS.
   *
   * Ne pose PAS encore le contexte SQL : c'est `applyToTransaction()` qui le
   * fait, à l'ouverture de chaque transaction. Séparer les deux permet au
   * contexte de survivre à plusieurs transactions successives.
   */
  run<T>(scope: TenantScope, fn: () => Promise<T>): Promise<T> {
    return this.cls.run(async () => {
      this.cls.set(CLS_TENANT, scope.tenantId);
      if (scope.userId) this.cls.set(CLS_USER, scope.userId);
      return fn();
    });
  }

  /**
   * Pose `app.tenant` et `app.user` dans la transaction courante.
   *
   * Appelée automatiquement par l'intercepteur de transaction. Si le contexte
   * manque, on AVERTIT avec l'action corrective — la requête rendra 0 ligne,
   * et le développeur saura pourquoi au lieu de chercher.
   */
  async applyToTransaction(trx: Kysely<any>, operation = 'requête'): Promise<void> {
    const tenantId = this.tenantId;
    const userId = this.userId;

    if (!tenantId) {
      this.logger?.warn(MSG.noTenantContext(operation));
      return;
    }

    await sql`select set_config('app.tenant', ${tenantId}, true)`.execute(trx);

    if (userId) {
      await sql`select set_config('app.user', ${userId}, true)`.execute(trx);
    } else {
      // Pas une erreur : certaines opérations n'ont pas d'utilisateur (tâche
      // planifiée, migration). Mais les règles intra-tenant rendront 0 ligne,
      // et ça doit se savoir.
      this.logger?.warn(MSG.noUserContext(operation));
    }

    this.logger?.debug(
      `Contexte posé : tenant=${tenantId.slice(0, 8)}…` +
        (userId ? ` user=${userId.slice(0, 8)}…` : ' (sans utilisateur)'),
    );
  }

  /**
   * Exécute `fn` dans une transaction, contexte posé.
   *
   * C'est la voie recommandée : le contexte ne peut pas être oublié, puisque
   * c'est cette méthode qui le pose.
   */
  async withContext<T>(fn: (trx: Kysely<any>) => Promise<T>): Promise<T> {
    return this.txHost.withTransaction(async () => {
      const trx = this.txHost.tx as Kysely<any>;
      await this.applyToTransaction(trx);
      return fn(trx);
    });
  }

  /**
   * Vérifie qu'une transaction est active.
   *
   * Sans transaction, `set_config(…, true)` n'a nulle part où s'appliquer :
   * la requête part sans contexte et rend 0 ligne. On le dit plutôt que de
   * laisser chercher.
   */
  assertInTransaction(operation = 'requête'): void {
    // `isTransactionActive()` est une MÉTHODE, pas un accesseur. Sans les
    // parenthèses, la condition portait sur la fonction elle-même — toujours
    // vraie — et ce garde n'avertissait JAMAIS. Un garde muet est pire que
    // pas de garde : il donne l'illusion d'une protection.
    if (!this.txHost.isTransactionActive()) {
      this.logger?.warn(MSG.noTransaction(operation));
    }
  }
}
