/** @type {import('jest').Config} */
export default {
  testEnvironment: 'node',
  rootDir: 'src',
  // Les rôles PostgreSQL sont GLOBAUX AU CLUSTER, pas à la base : deux suites
  // parallèles se disputaient le même ALTER ROLE. Première correction,
  // `maxWorkers: 1`, qui résolvait le conflit mais sérialisait tout —
  // 19 secondes pour 77 tests.
  //
  // Correction retenue : les rôles sont créés UNE SEULE FOIS dans
  // `globalSetup`, et la migration 001 tolère la course. Le parallélisme est
  // donc rétabli.
  globalSetup: '<rootDir>/test-globals.ts',
  testRegex: '\\.spec\\.ts$',
  extensionsToTreatAsEsm: ['.ts'],
  // NestJS 12 is ESM-only ("type": "module", no CJS build), so the test runner
  // must run in ESM mode too. Relative imports therefore need the .js suffix.
  moduleNameMapper: { '^(\\.{1,2}/.*)\\.js$': '$1' },
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      { useESM: true, tsconfig: '<rootDir>/../tsconfig.json' },
    ],
  },
  // Coverage is measured on code that runs at BOOTSTRAP: the tests build real
  // Nest applications and call app.init(), which is what fires
  // onApplicationBootstrap. Nothing here is covered by unit-calling a method.
  collectCoverageFrom: [
    '**/*.ts',
    '!**/*.spec.ts',
    '!**/index.ts',
    '!**/fixtures/**',
    // bin.ts est la couche d'entrées/sorties : lecture de fichiers, import
    // dynamique du module de l'hôte, process.exit. Sa logique pure
    // (parseArgs, isDirectInvocation) est testée ; le reste est vérifié par
    // le harnais d'intégration e2e/, pas par des mocks de système de fichiers.
    '!**/cli/bin.ts',
  ],
  coverageDirectory: '../coverage',
  coverageThreshold: {
    global: { branches: 75, functions: 85, lines: 85, statements: 85 },
  },
};
