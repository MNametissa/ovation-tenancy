import { Logger, type LoggerService } from '@nestjs/common';

/**
 * Journalisation de la bibliothèque.
 *
 * PRINCIPE — l'échec fermé ne suffit pas.
 *
 * Une garantie qui échoue en silence laisse le développeur devant un résultat
 * vide sans explication : il perd des heures, ou pire, il contourne la
 * garantie. Chaque protection qui se déclenche doit donc DIRE pourquoi, et
 * dire quoi faire.
 *
 * Niveaux, et ce qu'ils signifient ici :
 *
 *   error  une garantie de sécurité a été violée, ou une opération a échoué
 *          d'une façon qui laisse le système dans un état incorrect.
 *          → exige une action immédiate.
 *
 *   warn   le développeur a oublié quelque chose. La donnée est protégée
 *          (échec fermé), mais le code ne fait pas ce qu'il croit.
 *          → c'est le niveau des OUBLIS. Le plus important de tous.
 *
 *   log    événement de cycle de vie qu'un exploitant doit voir : migration
 *          appliquée, policies posées, catalogue synchronisé.
 *
 *   debug  détail utile au diagnostic : contexte posé, requête tracée.
 *          Coupé en production.
 *
 * Règle : un `warn` porte TOUJOURS trois éléments — ce qui s'est passé,
 * pourquoi c'est un problème, et comment le corriger. Un avertissement qu'on
 * ne sait pas traiter finit par être ignoré, et c'est ainsi qu'on rate le seul
 * qui comptait.
 */

export const TENANCY_LOGGER = Symbol('TENANCY_LOGGER');

export interface TenancyLogger {
  error(message: string, trace?: string): void;
  warn(message: string): void;
  log(message: string): void;
  debug(message: string): void;
}

export function createLogger(
  custom?: LoggerService,
  context = 'Tenancy',
): TenancyLogger {
  const nest = custom ?? new Logger(context);
  return {
    error: (m, t) => nest.error?.(m, t),
    warn: (m) => nest.warn?.(m),
    log: (m) => nest.log?.(m),
    debug: (m) => nest.debug?.(m),
  };
}

/**
 * Messages destinés au développeur.
 *
 * Centralisés pour trois raisons : ils sont testables, ils restent cohérents,
 * et on peut vérifier d'un coup d'œil qu'ils disent tous quoi faire.
 */
export const MSG = {
  /** Requête hors transaction : le contexte n'a pas pu être posé. */
  noTransaction: (operation: string) =>
    `Aucune transaction active pour « ${operation} ». Le contexte de tenant ` +
    `n'a pas été posé : cette requête ne verra AUCUNE ligne (échec fermé). ` +
    `Enveloppez l'appel dans @Transactional() ou TransactionHost.withTransaction().`,

  /** Contexte de tenant absent dans une transaction. */
  noTenantContext: (operation: string) =>
    `Contexte de tenant absent pour « ${operation} ». La requête ne verra ` +
    `AUCUNE ligne. Vérifiez que TenantContext.run() enveloppe l'appel, ou ` +
    `que l'intercepteur de tenant est actif sur cette route.`,

  /** Contexte utilisateur absent : les règles intra-tenant ne s'appliquent pas. */
  noUserContext: (operation: string) =>
    `Contexte utilisateur absent pour « ${operation} ». Les règles d'isolation ` +
    `INTRA-tenant (visibilité des notes de jury, portée par ressource) ne ` +
    `pourront pas s'évaluer et rendront 0 ligne. Posez app.user en même temps ` +
    `que app.tenant.`,

  /** Table sous RLS sans policy : elle est vide pour tout le monde. */
  rlsWithoutPolicy: (table: string) =>
    `La table « ${table} » a RLS activée mais AUCUNE policy : elle est vide ` +
    `pour tous les rôles, silencieusement. Ajoutez une policy permissive de ` +
    `base, puis vos restrictives.`,

  /** Table avec tenant_id mais sans FORCE. */
  missingForce: (table: string) =>
    `La table « ${table} » porte tenant_id mais n'a pas FORCE ROW LEVEL ` +
    `SECURITY : son propriétaire CONTOURNE les policies. ` +
    `Exécutez : ALTER TABLE ${table} FORCE ROW LEVEL SECURITY;`,

  /** Rôle applicatif mal configuré. */
  unsafeRole: (role: string, why: string) =>
    `Le rôle applicatif « ${role} » ${why}. Il contourne donc la RLS et ` +
    `l'isolation entre tenants ne vaut plus rien. Utilisez un rôle NOBYPASSRLS, ` +
    `non propriétaire des tables.`,

  /** FORCE désactivé hors transaction pendant une migration. */
  forceLeftDisabled: (tables: string[]) =>
    `FORCE ROW LEVEL SECURITY est resté DÉSACTIVÉ sur : ${tables.join(', ')}. ` +
    `Ces tables sont exposées à leur propriétaire. Une migration a dû ` +
    `s'interrompre hors transaction. ` +
    `Exécutez : ALTER TABLE <table> FORCE ROW LEVEL SECURITY;`,

  /** Migration hors transaction. */
  migrationOutsideTransaction: () =>
    `Migration exécutée HORS transaction alors qu'elle désactive FORCE RLS. ` +
    `Si elle échoue, FORCE restera désactivé et les tables seront exposées ` +
    `(mesuré). Utilisez le harnais withRlsDisabled(), qui garantit le ` +
    `rétablissement par ROLLBACK.`,
} as const;
