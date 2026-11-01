/**
 * Key-material canary for the SigV4 signer (slice 14; CLAUDE.md invariants 1, 2,
 * 7). The S3 secret access key is key material — S3 keys are root-adjacent by
 * default, so this is the PRIMARY marker, the same byte-scan treatment the Azure
 * account key got (sign-service-sas.canary.spec). Signing happens ENTIRELY
 * client-side (no network), the secret is never logged, and it never appears in
 * the request headers the signer emits — only its derived HMAC signature does. An
 * STS `sessionToken` is deliberately NOT a canary: AWS itself puts it on the wire
 * as `x-amz-security-token`, so it is expected in the output; only the SECRET must
 * never appear.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import { signSigV4, type SigV4Options } from './sigv4';

// A unique, greppable canary embedded in a well-formed secret access key.
const CANARY = 'KLARSEND-S3SECRET-CANARY-4e5f6a7b8c9d';
const SECRET = `${CANARY}/000000000000000000000000000`;

const OPTS: SigV4Options = {
  region: 'eu-west-1',
  service: 's3',
  credentials: { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: SECRET },
  signingDate: new Date('2026-07-10T12:00:00Z'),
  uriEscapePath: false,
};
const REQ = {
  method: 'GET',
  url: 'https://client-masters.s3.eu-west-1.amazonaws.com/?list-type=2&delimiter=%2F',
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('SigV4 canary — the secret access key stays client-side', () => {
  it('signing makes NO network call (fetch is never invoked)', async () => {
    const fetchSpy = vi.fn(() => Promise.reject(new Error('no network allowed')));
    const original = globalThis.fetch;
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    try {
      await signSigV4(REQ, OPTS);
    } finally {
      globalThis.fetch = original;
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('the secret access key is never written to the console', async () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
    const spies = methods.map((m) => vi.spyOn(console, m).mockImplementation(() => {}));
    await signSigV4(REQ, OPTS);
    for (const spy of spies) {
      for (const call of spy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(CANARY);
        expect(JSON.stringify(call)).not.toContain(SECRET);
      }
    }
  });

  it('the secret never appears in the emitted headers — only its HMAC signature does', async () => {
    const headers = await signSigV4(REQ, OPTS);
    const serialized = JSON.stringify(headers);
    expect(serialized).not.toContain(SECRET);
    expect(serialized).not.toContain(CANARY);
    // Positive control: the request IS signed (so the scan isn't trivially passing).
    expect(headers['Authorization']).toContain('Signature=');
  });

  it('SANITY: the scan would CATCH the secret if it leaked (not vacuous)', () => {
    const leaked = `Authorization: ...&debugSecret=${SECRET}&...`;
    expect(leaked).toContain(SECRET);
  });
});
