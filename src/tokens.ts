/** Connexion métier sous app_runtime, fournie par le consommateur. */
export const CONNEXION_TENANCY = Symbol('tenancy.connexion');
export const SESSION_REQUISE = 'tenancy:session-requise';

/** Adaptateur de catalogue : aucune dépendance à permission-discovery. */
export abstract class ResolutionPermissions {
  abstract resolve(controleur: object, methode: string): string | undefined;
}
