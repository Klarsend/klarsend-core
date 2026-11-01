/**
 * Bundle guard (slice 14 pre-merge gate, STOP-gate (ii) item (e)): the AWS SigV4
 * oracle packages (`@smithy/signature-v4`, `@smithy/protocol-http`,
 * `@aws-crypto/sha256-js`) are DEV-ONLY test oracles and must never ship — our
 * runtime signer uses WebCrypto only. As with the Azure SDK guard
 * (sign-service-sas.bundle.spec), we enforce this at the root: no shippable source
 * file may import these packages — they may appear ONLY in `*.spec.ts`. A
 * tree-shaker can't include what nothing imports, so this statically guarantees
 * they stay out of the bundle (the CI build's artifact scan is the belt to this).
 */
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// Match an actual module specifier (import/require) for any AWS-oracle package,
// not a mere mention of the name in prose/comments (which this repo does).
const SDK_IMPORT = /(?:from|require\()\s*['"](?:@smithy\/[\w-]+|@aws-crypto\/[\w-]+|@aws-sdk\/[\w-]+)['"]/;
// Derive src/app from THIS spec's own location (…/src/app/core/sigv4/).
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

describe('bundle guard — the AWS SigV4 oracle packages are dev-only', () => {
  it('no shippable source file imports @smithy/* or @aws-crypto/* (or @aws-sdk/*)', () => {
    const offenders = shippableTs.filter((f) => SDK_IMPORT.test(readFileSync(f, 'utf8')));
    expect(offenders).toEqual([]);
  });

  it('is not vacuous: the equality fixtures DO import the oracle (scan works)', () => {
    const importers = allTs.filter((f) => SDK_IMPORT.test(readFileSync(f, 'utf8')));
    // The header-auth KAT (slice 14) and the presign KAT (slice 15) both use the
    // dev-only oracle — the scan must see them both.
    expect(importers.some((f) => f.includes('sigv4.equality.spec'))).toBe(true);
    expect(importers.some((f) => f.includes('sigv4.presign.equality.spec'))).toBe(true);
  });
});
