/**
 * Key-material canary for the signer (slice 9 pre-merge gate, item 8; CLAUDE.md
 * invariants 1, 2, 7). The storage account key and every token minted from it are
 * key material: generation happens ENTIRELY client-side (no network), the key is
 * never logged, and it never appears in its own output (only its HMAC does). The
 * account key is the PRIMARY marker here — the same byte-scan treatment the SAS
 * got in the wizard slice.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import { mintBlobReadSasUrl, mintContainerBrowseSas } from './mint-sas';

// A unique, greppable canary embedded in a well-formed base64 account key.
const CANARY = 'KLARSEND-ACCTKEY-CANARY-4e5f6a7b8c9d';
const ACCOUNT_KEY = btoa(`${CANARY}-000000000000000000000000000000`);

const EXPIRES = new Date('2027-03-14T18:30:00Z');
const mintBoth = () =>
  Promise.all([
    mintBlobReadSasUrl('clientmasters', 'deliverables', 'reel1/master.mov', ACCOUNT_KEY, EXPIRES),
    mintContainerBrowseSas('clientmasters', 'deliverables', ACCOUNT_KEY),
  ]);

afterEach(() => {
  vi.restoreAllMocks();
});

describe('signer canary — the account key stays client-side', () => {
  it('generation makes NO network call (fetch is never invoked)', async () => {
    const fetchSpy = vi.fn(() => Promise.reject(new Error('no network allowed')));
    const original = globalThis.fetch;
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    try {
      await mintBoth();
    } finally {
      globalThis.fetch = original;
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('the account key is never written to the console', async () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
    const spies = methods.map((m) => vi.spyOn(console, m).mockImplementation(() => {}));
    await mintBoth();
    for (const spy of spies) {
      for (const call of spy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(CANARY);
        expect(JSON.stringify(call)).not.toContain(ACCOUNT_KEY);
      }
    }
  });

  it('the account key never appears in the generated URL/token — only its HMAC does', async () => {
    const [url, token] = await mintBoth();
    for (const out of [url, token]) {
      expect(out).not.toContain(ACCOUNT_KEY);
      expect(out).not.toContain(CANARY);
    }
    // Positive control: the outputs ARE signed (so the scan isn't trivially passing).
    expect(url).toContain('sig=');
    expect(token).toContain('sig=');
  });

  it('SANITY: the scan would CATCH the key if it leaked (not vacuous)', () => {
    const leaked = `...&debugKey=${ACCOUNT_KEY}&...`;
    expect(leaked).toContain(ACCOUNT_KEY);
  });
});
