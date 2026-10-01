# Journal des modifications

## 0.3.0 — 2026-10-01

- `avecContexteVerifie` : contexte d'organisation prouvé (session, public
  par hôte, système) dans la même transaction que le travail (contrat A-4,
  optionnel ; fonctions SQL documentées dans le README).
- Dépôt séparé ; `prepare` construit le paquet installé depuis Git.

## 0.2.0 — 2026-09-27

- Rôles partagés vérifiés sans réécriture implicite ; module NestJS intégrable.
- Colonnes métier et rôles système fournis par l’application consommatrice.
- Permissions à portée vérifiées en SQL et champ CASL configurable.
- CLS, transactions et RxJS en dépendances de pair ; export de migrations.
- Guide d’intégration, exemple exécutable et installation externe du tarball.
