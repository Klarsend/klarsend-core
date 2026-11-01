/**
 * HttpVaultApi status-code mapping. The key pin: a 401 from either /vault call
 * surfaces as a distinct VaultUnauthorizedError (expired vault-scoped JWT), so
 * the UI can say "sign in again" rather than uselessly retrying a dead token.
 * fetch is stubbed on globalThis so no server is needed.
 */
import { afterEach, describe, expect, it } from 'vitest';

import { HttpVaultApi } from './http-vault-api';
import { VaultConflictError, VaultUnauthorizedError } from './wire';

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function stubFetch(status: number, body?: unknown): void {
  globalThis.fetch = (async () =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })) as typeof fetch;
}

function api(): HttpVaultApi {
  return new HttpVaultApi('/api', () => 'expired-token');
}

describe('HttpVaultApi → typed errors', () => {
  it('401 on GET /vault → VaultUnauthorizedError', async () => {
    stubFetch(401);
    await expect(api().getVault()).rejects.toBeInstanceOf(VaultUnauthorizedError);
  });

  it('401 on PUT /vault → VaultUnauthorizedError (checked before the 409 branch)', async () => {
    stubFetch(401);
    await expect(api().putVault({ ciphertext: 'c', nonce: 'n', version: 0 })).rejects.toBeInstanceOf(
      VaultUnauthorizedError,
    );
  });

  it('409 on PUT /vault still maps to VaultConflictError (unchanged)', async () => {
    stubFetch(409, { currentVersion: 7 });
    await expect(api().putVault({ ciphertext: 'c', nonce: 'n', version: 0 })).rejects.toBeInstanceOf(
      VaultConflictError,
    );
  });

  it('204 on GET /vault is still an empty vault, not an error', async () => {
    stubFetch(204);
    await expect(api().getVault()).resolves.toBeNull();
  });
});
