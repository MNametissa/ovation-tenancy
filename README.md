# Intégrer `@ovation/tenancy`

Tenancy fournit le socle des tenants, appartenances, rôles, permissions, contexte
transactionnel et journal d’audit. L’application fournit l’identité vérifiée, son
catalogue de permissions, ses rôles système et ses colonnes métier.

## Installation

Node.js 22 ou plus récent, PostgreSQL 17, NestJS 11 ou 12 et application ESM :

```sh
npm install @ovation/tenancy @nestjs/common @nestjs/core reflect-metadata \
  kysely pg nestjs-cls @nestjs-cls/transactional rxjs
```

`nestjs-cls` et `@nestjs-cls/transactional` sont des dépendances de pair : une seule
instance de chaque bibliothèque doit fournir le CLS et les transactions de
l’application. L’adaptateur Kysely est fourni par tenancy. Les exports publics
sont `@ovation/tenancy` et `@ovation/tenancy/migrations` (JavaScript et types).

## Contrat des rôles PostgreSQL

Les noms suivants sont fixes. Les rôles sont **globaux au cluster**, leurs droits
sur les objets sont propres à chaque base. Un administrateur les provisionne avant
le déploiement ; aucune connexion superuser n’est nécessaire au traitement des
requêtes ni à la synchronisation du catalogue.

| Rôle          | Attributs attendus                                        | Usage                                                                                               |
| ------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `app_runtime` | LOGIN, NOBYPASSRLS, NOSUPERUSER, NOCREATEDB, NOCREATEROLE | Requêtes métier ; jamais propriétaire des tables                                                    |
| `app_policy`  | NOLOGIN, BYPASSRLS                                        | Propriétaire des fonctions SECURITY DEFINER ; jamais utilisé comme connexion applicative            |
| `app_auth`    | LOGIN, NOBYPASSRLS, NOSUPERUSER                           | Connexion de confiance réservée à l’identité ; tenancy n’y installe aucun moteur d’authentification |

`app_migration` n’est plus créé ni utilisé. Les objets appartiennent au compte qui
exécute les migrations. `app_worker` appartient au paquet notifications et n’est
pas requis par tenancy.

La migration des rôles vérifie les attributs existants et refuse une divergence
avec un message explicite ; elle ne les réaligne jamais. Le mode
`rolesExistants: true` refuse un rôle absent, n’exige aucun mot de passe et interdit
toute réécriture, même si `realignerMotsDePasse` est aussi transmis. Sans ce mode,
les rôles absents peuvent être créés avec les identifiants fournis. La rotation
explicite `realignerMotsDePasse` reste disponible pour un administrateur qui assume
son effet sur toutes les bases du cluster ; ce n’est pas une option de démarrage.

Connectez le pool métier directement avec `app_runtime` et son secret fourni par
l’environnement, ou avec un compte de connexion non privilégié portant ce rôle.
Une connexion superuser suivie de `SET ROLE` ne constitue pas cette séparation :
`RESET ROLE` retrouverait les privilèges initiaux.

## Migrations et données existantes

Exécuter dans une étape de déploiement, avec une connexion d’administration :

```ts
import { runMigrations } from '@ovation/tenancy/migrations';

await runMigrations(administration, { rolesExistants: true });
```

Le compte de migration doit pouvoir créer extensions, tables, policies et fonctions,
et attribuer les fonctions à `app_policy`. Le provisionnement peut nécessiter le
superuser ; ce compte ne doit pas alimenter les pools de l’API. Les migrations sont
suivies dans `tenancy_migrations`, chaque migration de schéma étant transactionnelle.
Le consommateur sérialise ses déploiements par base. Aucune migration n’est lancée
implicitement par le module NestJS.

Sur une base neuve, `tenant` contient seulement `id`, `slug`, `nom`, `statut` et
`creee_le`. L’application étend cette table dans ses propres migrations, après
celles du socle et avant de semer ses données. Ovation installe `raison_sociale`,
`rccm`, `pays char(2) not null` dans sa migration versionnée `tenant-metier` et
`motif_suspension` dans sa migration de suspension.

Les colonnes métier des bases historiques sont **conservées en place**, avec leurs
données et contraintes. La mise à jour du socle ne supprime aucune colonne. Une
application qui veut retirer ses anciennes colonnes doit organiser sa propre
migration de données.

## Module NestJS

```ts
import { TenancyModule, TenantContext } from '@ovation/tenancy';

@Module({
  imports: [
    TenancyModule.forRoot({
      imports: [BaseModule, IdentiteModule, CatalogueModule],
      connexion: BASE_METIER,
      identite: { useExisting: IdentiteVerifiee },
      permissions: { useExisting: CataloguePermissions },
      // Facultatif : endpoints servis par le moteur d’authentification.
      ignorerContexte: (req) => estRouteAuthentification(req),
      gardesAvant: [GardeDebit],
      gardesApres: [GardeSuspension],
    }),
  ],
})
export class ApplicationModule {}
```

Les modules importés exportent les providers référencés. `IdentiteVerifiee`
implémente `IdentitySource.extract(requete)` : elle rend
`{ tenantId, userId }`, une promesse de cette valeur, ou `undefined`. Elle vérifie
l’authentification et l’appartenance avant de rendre un tenant. Pour distinguer
401 et 403 quand une session valide n’a aucune appartenance, elle pose
`requete[SESSION_VALIDE] = true`. Une application tierce doit fournir sa résolution
avant contexte, éventuellement par une fonction SQL étroite SECURITY DEFINER ;
tenancy ne devine ni les tables d’authentification ni les identifiants du client.

`CataloguePermissions.resolve(controleur, methode)` rend un code de permission,
ou `undefined` pour une route publique. Avec `nest-permission-discovery`, fournir
`PermissionDiscoveryService` et activer `failOnAmbiguous`. Une route sans permission
mais exigeant une identité porte `SetMetadata(SESSION_REQUISE, true)`.

Le module installe globalement le garde, l’intercepteur, le CLS et le plugin
transactionnel Kysely. L’identité est mémorisée seulement pendant la requête :
le garde s’exécute avant l’intercepteur. Les services passent leurs requêtes métier
à `TenantContext.withContext(trx => …)` ; cette méthode ouvre une transaction et
pose `app.tenant` et `app.user` localement. Hors HTTP, utiliser
`TenantContext.run({ tenantId, userId }, () => contexte.withContext(...))`.

## Rôles système et catalogue

```ts
await new RoleService(administration).ensureSystemRoles([
  { code: 'proprietaire', libelle: 'Propriétaire', permissions: ['*'] },
  {
    code: 'decorateur',
    libelle: 'Décorateur',
    porteeRequise: true,
    permissions: ['meuble.deplacer'],
  },
]);
```

Sans argument, aucun rôle n’est installé. Tenancy ne fournit plus `SYSTEM_ROLES`.
Le consommateur conserve ses définitions et sa stratégie de mise à jour :
`ensureSystemRoles` crée seulement les rôles absents. `*` attache les permissions
actives connues à cet instant ; une synchronisation ultérieure ne les ajoute pas
automatiquement aux rôles existants.

`PermissionSink` prend une connexion de publication distincte du pool métier.
`app_runtime` conserve SELECT sur `permission`, mais perd INSERT, UPDATE et DELETE.
Le publieur requiert SELECT/INSERT/UPDATE sur `permission` et SELECT sur
`role_permission` pour compter les références. Le consommateur accorde ces droits
sur sa base au rôle choisi. Pour `listObsoleteInUse`, il lui faut aussi la lecture
autorisée de `role` ; cette méthode ne fait pas partie du démarrage.

Ovation utilise `app_auth` via son pool de confiance et une transaction dont le
`search_path` local vise `public`. Sa migration `permissions-catalogue` accorde les
seuls droits nécessaires au puits. La synchronisation conserve les insertions
idempotentes : plusieurs instances du **même catalogue** peuvent démarrer ensemble.
Des versions concurrentes avec des catalogues différents doivent être coordonnées
par le déploiement pour éviter une obsolescence contradictoire.

## Portée côté SQL et CASL

`app_a_permission(code)` répond seulement à l’existence du droit dans le tenant :
il convient au garde de route. `app_a_permission_portee(code, ressource_uuid)`
exige, pour ce même code, une appartenance sans portée ou portant cet UUID. Une
ressource NULL n’est lisible que par un titulaire sans portée. Les permissions
obsolètes ne donnent aucun droit. Les deux fonctions utilisent les variables
transactionnelles `app.tenant` et `app.user`.

La policy restrictive `audit_lecture` appelle la fonction à portée sur
`journal_audit.ressource_id`. Une appartenance limitée à E1 ne lit ni E2 ni les
entrées sans ressource, même en interrogeant directement PostgreSQL. Les tables du
consommateur doivent ajouter leurs propres policies en plus de l’isolation tenant.

Exemple exécutable, vérifié depuis le paquet construit :

```js
import assert from 'node:assert/strict';
import { buildAbility, assertCan } from '@ovation/tenancy';

const capacite = buildAbility(
  {
    tenantId: 'maison',
    userId: 'habitant',
    permissions: ['meuble.deplacer'],
    scopedResourceIds: ['salon'],
  },
  { champsPortee: { meuble: 'pieceId' } },
);
assert.doesNotThrow(() =>
  assertCan(capacite, 'deplacer', 'meuble', { id: 'fauteuil', pieceId: 'salon' }),
);
assert.throws(() =>
  assertCan(capacite, 'deplacer', 'meuble', { id: 'salon', pieceId: 'cuisine' }),
);
```

Le champ par défaut reste `id`. La configuration est par type de sujet CASL.
Pour un déplacement, vérifier la portée de départ **et** d’arrivée. Utiliser
`loadAbilityContext` pour conserver les permissions avec la portée de chaque
appartenance, puis passer cette valeur à `buildAbility`. Une vérification CASL
sur un type sans instance n’évalue pas sa portée.

## Limites et contrôles

- L’authentification, la résolution d’identité, la suspension métier et les tables
  de ressources restent à la charge du consommateur.
- La portée n’a pas de clé étrangère dans le socle : l’application impose la
  cohérence entre sa ressource et son tenant.
- Les suffixes historiques CASL `.own` et `.all` conservent leur sens : propriétaire
  et absence de condition. `champsPortee` s’applique aux permissions simples.
- Le journal neutralise UPDATE et DELETE par des règles `DO INSTEAD NOTHING` :
  le résultat peut être zéro ligne sans exception. Sa chaîne détecte l’altération
  et la suppression, pas un administrateur capable de tout recalculer.
- La vérification de chaîne requiert le journal complet du tenant ; l’application
  doit la refuser à un lecteur limité à une portée. Ovation le fait.
- Appeler `assertRlsIsSound` sous le rôle métier au démarrage, en déclarant les tables
  supplémentaires attendues et les rares tables globales autorisées.

Les tests `independance.spec.ts`, `roles-partages.spec.ts`, `tenancy.module.spec.ts`,
`contrat-paquet.spec.ts` et `readme.spec.ts` vérifient ces contrats. Ovation vérifie
également la conservation des tenants historiques et la lecture directe du journal
sous `app_runtime` dans ses tests de migration et d’audit à portée.
