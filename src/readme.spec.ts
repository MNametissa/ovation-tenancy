import { it, expect } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

it('L8 — l’exemple du README fonctionne depuis l’export public construit', () => {
  const readme = readFileSync('README.md', 'utf8');
  const exemple = /```js\n([\s\S]*?)```/.exec(readme)?.[1];
  expect(exemple).toBeDefined();
  expect(() =>
    execFileSync(process.execPath, ['--input-type=module', '-e', exemple!], {
      stdio: 'pipe',
    }),
  ).not.toThrow();
});
