/**
 * Bundle guard (slice 9 pre-merge gate): `@azure/storage-blob` is a DEV-ONLY test
 * oracle and must never ship. Rather than build the app in a unit test, we enforce
 * the invariant at its root: no shippable source file may import the SDK — it may
 * appear ONLY in `*.spec.ts`. A tree-shaker can't include what nothing imports, so
 * this statically guarantees the SDK stays out of the bundle (and the CI build's
 * own artifact scan is the belt to this suspenders).
 */
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// Match an actual module specifier (import/require), not a mere mention of the
// package name in prose/comments (which several files legitimately reference).
const SDK_IMPORT = /(?:from|require\()\s*['"]@azure\/storage-blob['"]/;
// Derive src/app from THIS spec's own location (…/src/app/core/sas/), not the
// process cwd — so the guard holds regardless of where the runner is invoked from.
const APP_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walk(full));
    } else if (entry.name.endsWith('.ts')) {
      out.push(full);
    }
  }
  return out;
}

const allTs = walk(APP_ROOT);
const shippableTs = allTs.filter((f) => !f.endsWith('.spec.ts'));

describe('bundle guard — @azure/storage-blob is dev-only', () => {
  it('no shippable source file imports the Azure SDK', () => {
    const offenders = shippableTs.filter((f) => SDK_IMPORT.test(readFileSync(f, 'utf8')));
    expect(offenders).toEqual([]);
  });

  it('is not vacuous: the equality fixture DOES import the SDK (scan works)', () => {
    const importers = allTs.filter((f) => SDK_IMPORT.test(readFileSync(f, 'utf8')));
    expect(importers.some((f) => f.includes('sign-service-sas.equality.spec'))).toBe(true);
  });
});
