# Implications de la phase 3 — sécurité, performance, objectifs

Mesuré le 25 septembre 2026 contre PostgreSQL 17 réel.
Banc : `probes/phase3/t39-bench.mjs`. Volume : 101 tenants, 10 001 appartenances.

---

## 1. Performance — la pile tient, mais avec une condition

| Configuration                               | p50           | p95      | Débit              |
| ------------------------------------------- | ------------- | -------- | ------------------ |
| A. RLS + contexte, requête simple           | 2,67 ms       | 3,75 ms  | **375 tx/s**       |
| B. + chargement CASL à chaque transaction   | 4,64 ms       | 6,21 ms  | **215 tx/s**       |
| C. Construction CASL seule, hors base       | **0,0035 ms** | 0,016 ms | —                  |
| D. Sous concurrence (50 en parallèle)       | —             | —        | **757–1 001 tx/s** |
| F. Contexte chargé **une fois** par requête | 1,95 ms       | —        | **513 tx/s**       |

### Le résultat qui compte

**101 % du surcoût CASL est la requête SQL de chargement** (1,85 ms). La
construction des règles coûte **0,0035 ms** — trois microsecondes, négligeable.

Conséquence directe sur la conception :

> Le contexte d'autorisation se charge **une fois par requête HTTP**, pas à
> chaque transaction. Avec ce seul changement : **513 tx/s**, soit la cible
> haute atteinte, contre 215 en rechargeant à chaque fois.

Et sous concurrence — le régime réel d'un serveur — la pile complète tient
**757 à 1 001 tx/s**, soit **1,5 à 2× la cible**.

### Ce que ça implique pour la suite

| Décision                                                                                 | Fondement                                                                            |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Charger le contexte d'autorisation **au début de la requête HTTP**, dans un intercepteur | 101 % du coût est la requête SQL                                                     |
| **Ne pas** mettre le contexte en cache entre requêtes                                    | la révocation immédiate en dépend (mesurée : la requête suivante voit le changement) |
| Le chemin chaud d'un vote **reste hors PostgreSQL** (`INCR` Redis)                       | 513 tx/s suffisent au métier, pas à un pic de votes                                  |
| Vérifier CASL sur l'**instance**, pas sur le type                                        | sinon la portée n'est pas évaluée (voir §2)                                          |

### Comparaison avec la phase 0

La phase 0 mesurait +96 µs pour la RLS seule, à allers-retours réseau égaux.
Ici, 2,67 ms pour une transaction complète : la différence est le **nombre
d'allers-retours** (BEGIN + 2 `set_config` + requête + COMMIT), pas la RLS.
La règle « une transaction = un aller-retour » reste la principale marge
disponible.

---

## 2. Sécurité — ce qui est acquis, ce qui reste

### Acquis, et mesuré

| Garantie                      | Comment                           | Test                                        |
| ----------------------------- | --------------------------------- | ------------------------------------------- |
| Isolation inter-tenant        | RLS + `FORCE`                     | un tenant ne voit que ses lignes            |
| **Isolation intra-tenant**    | second GUC `app.user`             | deux jurés du même tenant, même évènement   |
| Échec **fermé**               | policies `RESTRICTIVE`            | sans contexte : 0 ligne, pas d'exception    |
| Oubli du contexte inoffensif  | default-deny                      | transaction sans `set_config` : 0 ligne     |
| **Révocation immédiate**      | lecture en base à chaque requête  | la requête suivante voit le changement      |
| Journal inaltérable           | privilèges **et** règles          | `UPDATE`/`DELETE` sans effet                |
| Suppression détectable        | chaînage SHA-256                  | entrée retirée par la bande → chaîne rompue |
| Permission fantôme impossible | catalogue fermé                   | une permission inconnue est refusée         |
| Rôle à portée                 | trigger sur `role.portee_requise` | vaut pour les rôles créés par un tenant     |

### Piège trouvé pendant les tests

**CASL interrogé sur un TYPE sans instance rend `true`** dès qu'une règle
existe — il ne peut pas évaluer une condition sans objet :

```ts
ability.can('publish', 'event')           // true  — règle existante
ability.can('publish', { id: EV_2, … })   // false — hors portée
```

Une vérification sans instance **ne prouve rien sur la portée**. Sans ce
constat, un organisateur aurait pu publier l'évènement d'un autre. Documenté
dans `assertCan()` et couvert par un test.

### Défauts réels trouvés en phase 3

| #   | Défaut                                                                         | Conséquence évitée                                                                                     |
| --- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| 1   | `ALTER DEFAULT PRIVILEGES` ne vaut que pour les tables créées **après**        | `app_runtime` sans aucun privilège — **application entièrement inutilisable**                          |
| 2   | Les rôles PostgreSQL sont **globaux au cluster**                               | mot de passe d'un rôle écrasé par une autre base → panne d'authentification inexplicable               |
| 3   | Une erreur PostgreSQL **avorte la transaction entière**                        | un `catch` applicatif inopérant, toutes les requêtes suivantes en échec                                |
| 4   | Les paramètres liés ne traversent pas un bloc `DO $$`                          | migration des rôles impossible                                                                         |
| 5   | **Hors transaction, `FORCE` reste désactivé** après un échec                   | table exposée à son propriétaire, sans aucun signal                                                    |
| 6   | `ensureSystemRoles()` **levait** si le catalogue hôte n'avait pas `audit.read` | **aucune application tierce ne démarrait** — le catalogue appartient à l'hôte, pas à la bibliothèque   |
| 7   | `isTransactionActive` est une **méthode**, testée comme un accesseur           | `assertInTransaction()` n'avertissait **JAMAIS** — un garde muet qui donne l'illusion d'une protection |

Le défaut 7 est le plus instructif : `if (!this.txHost.isTransactionActive)` teste
la fonction elle-même, donc toujours vraie. Le garde était **mort depuis son
écriture**, et aucun test ne le voyait parce que `TenantContext` n'était jamais
instanciée — les tests posaient `set_config` à la main.

> Une garantie mesurée sur PostgreSQL n'est pas une garantie mesurée sur le code
> qui l'utilise.

Corrigé, plus un test qui verrouille la **forme** (`typeof … === 'function'`) et
pas seulement le comportement.

Le défaut 6 n'était visible qu'en installant les deux paquets **depuis leurs
tarballs** : les suites unitaires importent le source et fabriquent leur propre
catalogue, donc la dépendance au catalogue de l'hôte leur est invisible. D'où
`integration/` — 11 vérifications dans une application NestJS 12 neuve.

### Ce qui n'est PAS couvert — surfaces restantes

| Surface                                | État                                                               | Phase            |
| -------------------------------------- | ------------------------------------------------------------------ | ---------------- |
| **Authentification**                   | Better Auth non installé                                           | 4                |
| **Secret TOTP chiffré au repos**       | spécifié, non fait — une fuite de dump livrerait le second facteur | 4                |
| **Anti-fraude**                        | Turnstile contourné à ~100 %, IP inutilisable au Cameroun          | sous-projet      |
| **Limitation de débit**                | rien                                                               | 4                |
| **CSRF avec front séparé**             | rien                                                               | 4/5              |
| **Injection**                          | requêtes paramétrées partout (Kysely), non audité                  | 4                |
| **Intégration des deux paquets**       | couverte — `integration/`, 11/11 depuis tarballs                   | fait             |
| **Sauvegardes et restauration testée** | rien                                                               | avant production |
| **Exposition de données**              | T4.8 — le défaut exact des deux concurrents                        | 4                |

**La RLS ne protège que la donnée en base.** Elle ne dit rien d'une API mal
protégée, d'un secret en clair ou d'une fuite par les messages d'erreur.

---

## 3. Objectifs du produit — ce que la phase 3 sert

| Objectif                                                                       | Apport                                                          |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------- |
| **Intégrité démontrable** — la différenciation face à VOTAR et ses 324 litiges | journal chaîné, vérifiable, inaltérable à deux niveaux          |
| **Transparence juridique** — RCCM publié, ce qu'aucun concurrent ne fait       | `tenant.rccm` et `raison_sociale` au schéma                     |
| **Rôles adaptés au métier** — « coach », « délégué régional »                  | rôles configurables, portée comprise, sans modification de code |
| **Le silence pendant la délibération**                                         | policies conditionnées à l'état de la ressource                 |
| **Multi-évènements par organisation**                                          | l'unité de configuration est l'évènement, pas le tenant         |

### Ce que la phase 3 ne résout pas, et qui reste bloquant

- **La taxe de 4 FCFA** s'applique-t-elle aux paiements marchands ? Détermine
  le prix plancher.
- **Grille Notch Pay** : aucune donnée publique.
- **Qualification écrite des agrégateurs** : leurs contrats interdisent
  nommément les activités « avec frais d'entrée et un prix ».
- **Avis juridique** sur le régime de la loterie commerciale — 3 mois
  maximum, huissier, garantie bancaire.

Aucun n'affecte le socle. Tous bloquent le paiement.

---

## 4. Couverture — ce que l'audit a révélé

La suite annonçait vert à 95 tests. Un vert ne prouve rien sans son périmètre :
en mesurant la couverture fichier par fichier, **87,84 %** au total cachait
des zones mortes sur les pièces les plus sensibles.

| Fichier             | Avant       | Après                                             | Ce qui n'était pas exécuté                                                     |
| ------------------- | ----------- | ------------------------------------------------- | ------------------------------------------------------------------------------ |
| `tenant-context.ts` | **13,33 %** | **100 %**                                         | la classe entière — `applyToTransaction`, `withContext`, `assertInTransaction` |
| `logging.ts`        | 62,5 %      | **100 %**                                         | `createLogger`, seul chemin d'une application réelle                           |
| `audit-service.ts`  | 86,95 %     | **100 %**                                         | `list()`, que servira l'écran « Journal d'audit »                              |
| `guards.ts`         | 88,52 %     | 96,72 %                                           | `assertRlsIsSound` face à un `WITH CHECK` manquant et à une unicité globale    |
| `001-roles.ts`      | 74,28 %     | 80 %                                              | la validation de mot de passe — seule barrière d'un `CREATE ROLE`              |
| **Total**           | **87,84 %** | **97,22 %** (lignes 98,58 %, **fonctions 100 %**) |                                                                                |

Tests : **95 → 131**, déclarés = exécutés à chaque mesure.

### Ce que ça a coûté de ne pas mesurer plus tôt

Le défaut 7 vivait précisément dans les 86,67 % non couverts de
`tenant-context.ts`. Le fichier qui pose `app.tenant` et `app.user` — le point
dont dépend TOUTE l'isolation — était couvert à 13 %, alors que les tests
« d'isolation » passaient tous : ils prouvaient le comportement de PostgreSQL en
posant `set_config` à la main, jamais celui du code appelé par l'application.

### Non couvert, et assumé

| Zone                                          | Pourquoi                                                                                                                                     |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `001-roles.ts` 125-131 — chemin `create role` | les rôles sont globaux au cluster et créés par le `globalSetup` ; ce chemin est inatteignable en test, c'est la contrepartie du 19 s → 7,5 s |
| Branches d'erreur de courses concurrentes     | déclenchables seulement par une vraie course entre deux migrations                                                                           |

---

## 5. Dettes assumées

| Dette                                                                      | Raison                                                                                                        | Quand                                  |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| Le contexte d'autorisation se charge par transaction, pas par requête HTTP | l'intercepteur NestJS relève de la phase 4                                                                    | T4.1                                   |
| `policies` métier (silence pendant la délibération) non implémentées       | elles appartiennent à l'application, pas à la bibliothèque                                                    | T4.5                                   |
| Pas de fabrique `definePolicies` déclarative                               | le SQL direct suffit tant qu'il n'y a qu'un consommateur                                                      | quand un second apparaîtra             |
| `scopedResource` non paramétrable                                          | `appartenance.portee_ressource_id` est sans clé étrangère, donc déjà générique                                | si besoin                              |
| `assertInTransaction()` **avertit** au lieu de lever                       | lever romprait une application qui lit hors transaction volontairement ; l'échec fermé protège déjà la donnée | à revoir si l'avertissement est ignoré |
| Le banc d'intégration n'est pas encore dans une CI                         | aucune CI n'est configurée sur le dépôt                                                                       | phase 4                                |
