/**
 * Key-material canary for the S3 PRESIGN signer (slice 15; CLAUDE.md invariants
 * 1, 2, 7). A presigned URL is a bearer credential — the whole point is that the
 * URL alone grants a download — so it is doubly important that the URL carries
 * ONLY the derived `X-Amz-Signature`, never the secret access key it was signed
 * with. Presigning happens ENTIRELY client-side (no network), the secret is never
 * logged, and it never appears in the produced URL. An STS `X-Amz-Security-Token`
 * is deliberately NOT a canary: AWS itself puts it in the URL query, so it is
 * expected in the output; only the SECRET must never appear.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import { presignQueryUrl, type PresignOptions } from './sigv4';

// A unique, greppable canary embedded in a well-formed secret access key.
const CANARY = 'KLARSEND-S3SECRET-PRESIGN-CANARY-4e5f6a7b8c9d';
const SECRET = `${CANARY}/000000000000000000000000000`;

const BASE = 'https://client-masters.s3.eu-west-1.amazonaws.com/masters/reel1.wav';
const OPTS: PresignOptions = {
  region: 'eu-west-1',
  service: 's3',
  credentials: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: SECRET,
    sessionToken: 'FQoGZXIvYXdzEBcaDNTESTSESSIONTOKEN//////////wEXAMPLE=',
  },
  signingDate: new Date('2026-07-10T12:00:00Z'),
  expiresInSeconds: 3600,
  uriEscapePath: false,
  extraQuery: { 'response-content-disposition': 'attachment; filename="reel 1.wav"' },
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('S3 presign canary — the secret access key stays client-side', () => {
  it('presigning makes NO network call (fetch is never invoked)', async () => {
    const fetchSpy = vi.fn(() => Promise.reject(new Error('no network allowed')));
    const original = globalThis.fetch;
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    try {
      await presignQueryUrl(BASE, OPTS);
    } finally {
      globalThis.fetch = original;
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('the secret access key is never written to the console', async () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
    const spies = methods.map((m) => vi.spyOn(console, m).mockImplementation(() => {}));
    await presignQueryUrl(BASE, OPTS);
    for (const spy of spies) {
      for (const call of spy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(CANARY);
        expect(JSON.stringify(call)).not.toContain(SECRET);
      }
    }
  });

  it('the secret never appears in the presigned URL — only its HMAC signature does', async () => {
    const url = await presignQueryUrl(BASE, OPTS);
    expect(url).not.toContain(SECRET);
    expect(url).not.toContain(CANARY);
    // Positive control: the URL IS signed (so the scan isn't trivially passing).
    expect(url).toContain('X-Amz-Signature=');
    // The STS token IS expected in the URL (AWS puts it on the wire); the secret is not.
    expect(url).toContain('X-Amz-Security-Token=');
  });

  it('SANITY: the scan would CATCH the secret if it leaked (not vacuous)', () => {
    const leaked = `${BASE}?debugSecret=${SECRET}&X-Amz-Signature=abc`;
    expect(leaked).toContain(SECRET);
  });
});
