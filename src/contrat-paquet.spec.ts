import { it, expect } from '@jest/globals';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

it('L8 — CLS est fourni par le consommateur et migrations est importable', async () => {
  const racine = resolve(process.cwd());
  const manifeste = JSON.parse(
    readFileSync(resolve(racine, 'package.json'), 'utf8'),
  ) as {
    peerDependencies: Record<string, string>;
    dependencies: Record<string, string>;
    exports: Record<string, { default: string; types: string }>;
  };
  for (const nom of ['nestjs-cls', '@nestjs-cls/transactional']) {
    expect(manifeste.peerDependencies[nom]).toBeDefined();
    expect(manifeste.dependencies[nom]).toBeUndefined();
  }
  const entree = manifeste.exports['./migrations'];
  expect(existsSync(resolve(racine, entree.default))).toBe(true);
  expect(existsSync(resolve(racine, entree.types))).toBe(true);
  const migrations = await import('@ovation/tenancy/migrations');
  expect(typeof migrations.runMigrations).toBe('function');
});
