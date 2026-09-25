/** @type {import('jest').Config} */
export default {
  testEnvironment: 'node',
  rootDir: 'src',
  // Les rôles PostgreSQL sont GLOBAUX AU CLUSTER, pas à la base. Deux suites
  // parallèles qui migrent sur deux bases différentes se disputent le même
  // ALTER ROLE et produisent « tuple concurrently updated » — un verrou
  // consultatif n'y suffit pas, il est lui aussi propre à une base.
  // Ces suites touchent une ressource globale : elles tournent en série.
  maxWorkers: 1,
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
