import type { RoleInput } from '../roles/role-service.js';

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
