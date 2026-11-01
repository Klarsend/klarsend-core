/**
 * Vault-sync core tests — written before the implementation. Same harness
 * pattern as auth.spec.ts: a fake VaultApi that records every body that would
 * cross the wire, real WebCrypto for everything else. Pin the wire boundary
 * (ciphertext + nonce + version only — never plaintext, never wrapped keys),
 * pull-on-unlock, push-on-change, and the 409 → re-fetch → retry loop.
 */
import { describe, expect, it } from 'vitest';

import {
  decryptEntry,
  deserializeVaultBlob,
  encryptEntry,
  generateVaultKey,
  serializeVaultBlob,
} from '../vault-crypto';
import { toBase64, toHex, utf8Decode, utf8Encode } from '../vault-crypto/encoding';
import { VaultSync } from './vault-sync';
import { VaultConflictError, type PutVaultBody, type SerializedVaultBlob, type VaultApi } from './wire';

/** Mutable "server" state: what the fake API stores, exactly like vaultBlobs. */
interface ServerState {
  blob: SerializedVaultBlob | null;
}

interface Harness {
  api: VaultApi;
  state: ServerState;
  events: string[];
  putBodies: PutVaultBody[];
}

/** Fake API mirroring the real server contract: atomic version check, 409 with currentVersion. */
function harness(initial: SerializedVaultBlob | null = null): Harness {
  const state: ServerState = { blob: initial };
  const events: string[] = [];
  const putBodies: PutVaultBody[] = [];

  const api: VaultApi = {
    getVault: async () => {
      events.push('get');
      return state.blob;
    },
    putVault: async (body) => {
      events.push('put');
      putBodies.push(JSON.parse(JSON.stringify(body)) as PutVaultBody);
      const current = state.blob?.version ?? 0;
      if (body.version !== current) {
        throw new VaultConflictError(current);
      }
      state.blob = { ciphertext: body.ciphertext, nonce: body.nonce, version: current + 1 };
      return { version: current + 1, updatedAt: '2026-01-01T00:00:00Z' };
    },
  };

  return { api, state, events, putBodies };
}

async function remoteBlobFor(vaultKey: CryptoKey, text: string, version: number): Promise<SerializedVaultBlob> {
  return serializeVaultBlob(await encryptEntry(vaultKey, utf8Encode(text)), version);
}

/** Decrypt what the fake server currently stores — proves a write really landed. */
async function decryptServerBlob(vaultKey: CryptoKey, state: ServerState): Promise<string> {
  const { payload } = deserializeVaultBlob(state.blob!);
  return utf8Decode(await decryptEntry(vaultKey, payload));
}

describe('pull on unlock', () => {
  it('decrypts the server blob locally and adopts its version', async () => {
    const vaultKey = await generateVaultKey();
    const h = harness(await remoteBlobFor(vaultKey, 'entries-from-another-device', 3));
    const sync = new VaultSync({ api: h.api, vaultKey });

    const pulled = await sync.pull();

    expect(pulled.version).toBe(3);
    expect(utf8Decode(pulled.plaintext!)).toBe('entries-from-another-device');
    expect(h.events).toEqual(['get']);
  });

  it('returns an empty vault at version 0 when the server has no blob yet (fresh account)', async () => {
    const h = harness(null);
    const sync = new VaultSync({ api: h.api, vaultKey: await generateVaultKey() });

    const pulled = await sync.pull();

    expect(pulled.plaintext).toBeNull();
    expect(pulled.version).toBe(0);
  });

  it('rejects a tampered blob (GCM authentication) instead of returning garbage', async () => {
    const vaultKey = await generateVaultKey();
    const blob = await remoteBlobFor(vaultKey, 'authentic', 1);
    // flip one character of the base64 ciphertext
    const corrupted = blob.ciphertext[0] === 'A' ? 'B' + blob.ciphertext.slice(1) : 'A' + blob.ciphertext.slice(1);
    const h = harness({ ...blob, ciphertext: corrupted });
    const sync = new VaultSync({ api: h.api, vaultKey });

    await expect(sync.pull()).rejects.toThrow();
  });
});

describe('push on change: the wire carries ciphertext and version metadata only', () => {
  // Distinctive plaintext so a byte-level scan of the PUT body cannot collide
  // with unrelated random bytes — same technique as the auth PRF-leak scan.
  const MARKER = 'vault-entry-marker-0123456789-abcdef';

  it('PUT body has exactly {ciphertext, nonce, version} — no wrapped-key fields, ever', async () => {
    const vaultKey = await generateVaultKey();
    const h = harness();
    const sync = new VaultSync({ api: h.api, vaultKey });
    await sync.pull();

    await sync.push(utf8Encode(MARKER));

    const body = h.putBodies[0];
    // pinned closed shape: sync never accepts or re-serializes wrapped key material
    expect(Object.keys(body).sort()).toEqual(['ciphertext', 'nonce', 'version']);
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain('wrappedVaultKey');
    expect(serialized).not.toContain('recoveryWrappedVaultKey');
    expect(serialized).not.toContain('kdf');
  });

  it('SECURITY: the plaintext appears in NO encoding anywhere in the PUT body', async () => {
    const vaultKey = await generateVaultKey();
    const h = harness();
    const sync = new VaultSync({ api: h.api, vaultKey });
    await sync.pull();

    await sync.push(utf8Encode(MARKER));

    const serialized = JSON.stringify(h.putBodies[0]);
    const markerBytes = utf8Encode(MARKER);
    for (const encoded of [MARKER, toHex(markerBytes), toBase64(markerBytes).replace(/=+$/, '')]) {
      // generous substring survives base64 phase/alignment shifts
      expect(serialized).not.toContain(encoded.slice(4, 28));
    }
  });

  it('sanity: the leak scan would CATCH plaintext going over the wire', () => {
    const serialized = JSON.stringify({ ciphertext: toBase64(utf8Encode(MARKER)) });
    expect(serialized).toContain(toBase64(utf8Encode(MARKER)).replace(/=+$/, '').slice(4, 28));
  });

  it('what crossed the wire really decrypts back to the pushed plaintext (real crypto round trip)', async () => {
    const vaultKey = await generateVaultKey();
    const h = harness();
    const sync = new VaultSync({ api: h.api, vaultKey });
    await sync.pull();

    await sync.push(utf8Encode('round-trip-me'));

    expect(await decryptServerBlob(vaultKey, h.state)).toBe('round-trip-me');
  });

  it('every push encrypts fresh: new nonce and new ciphertext even for identical plaintext', async () => {
    const vaultKey = await generateVaultKey();
    const h = harness();
    const sync = new VaultSync({ api: h.api, vaultKey });
    await sync.pull();

    await sync.push(utf8Encode('same-content'));
    await sync.push(utf8Encode('same-content'));

    expect(h.putBodies[0].nonce).not.toBe(h.putBodies[1].nonce);
    expect(h.putBodies[0].ciphertext).not.toBe(h.putBodies[1].ciphertext);
  });

  it('tracks versions across pushes: first PUT bases on 0, the next on the server-confirmed 1', async () => {
    const h = harness();
    const sync = new VaultSync({ api: h.api, vaultKey: await generateVaultKey() });
    await sync.pull();

    const v1 = await sync.push(utf8Encode('first'));
    const v2 = await sync.push(utf8Encode('second'));

    expect(v1).toBe(1);
    expect(v2).toBe(2);
    expect(h.putBodies.map((b) => b.version)).toEqual([0, 1]);
  });
});

describe('409 conflict: re-fetch and retry (last writer wins for MVP)', () => {
  it('on 409, re-fetches the server state and retries with the current version', async () => {
    const vaultKey = await generateVaultKey();
    const h = harness();
    const sync = new VaultSync({ api: h.api, vaultKey });
    await sync.pull(); // version 0

    // another device pushed twice while we were editing
    h.state.blob = await remoteBlobFor(vaultKey, 'other-device-content', 2);

    const version = await sync.push(utf8Encode('our-edit-wins'));

    // stale put (v0) → 409 → GET → retry put (v2) → server at v3
    expect(h.events).toEqual(['get', 'put', 'get', 'put']);
    expect(h.putBodies.map((b) => b.version)).toEqual([0, 2]);
    expect(version).toBe(3);
    expect(await decryptServerBlob(vaultKey, h.state)).toBe('our-edit-wins'); // LWW
  });

  it('gives up after bounded attempts when conflicts persist (no infinite loop)', async () => {
    const vaultKey = await generateVaultKey();
    let serverVersion = 5;
    const puts: number[] = [];
    const api: VaultApi = {
      // a pathological server that is always one version ahead
      getVault: async () => remoteBlobFor(vaultKey, 'always-ahead', serverVersion),
      putVault: async (body) => {
        puts.push(body.version);
        serverVersion += 1;
        throw new VaultConflictError(serverVersion);
      },
    };
    const sync = new VaultSync({ api, vaultKey });
    await sync.pull();

    await expect(sync.push(utf8Encode('never-lands'))).rejects.toThrow(/conflict/i);
    expect(puts.length).toBe(3); // bounded
  });

  it('non-conflict errors propagate immediately without re-fetch or retry', async () => {
    const vaultKey = await generateVaultKey();
    const h = harness();
    const failing: VaultApi = {
      getVault: h.api.getVault,
      putVault: async (body) => {
        h.events.push('put');
        void body;
        throw new Error('network down');
      },
    };
    const sync = new VaultSync({ api: failing, vaultKey });
    await sync.pull();

    await expect(sync.push(utf8Encode('x'))).rejects.toThrow('network down');
    expect(h.events).toEqual(['get', 'put']); // exactly one attempt, no retry loop
  });
});
