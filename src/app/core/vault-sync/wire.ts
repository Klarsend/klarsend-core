/**
 * Wire contracts for /vault sync plus the API seam injected into VaultSync so
 * tests can fake the server. SECURITY (CLAUDE.md invariant 1): the only fields
 * that ever cross this boundary are ciphertext, nonce, and version metadata.
 * Wrapped vault keys are write-once at registration (/auth) and are not a
 * member of any type in this file — sync can neither send nor receive them.
 */
import type { SerializedVaultBlob } from '../vault-crypto';

export type { SerializedVaultBlob };

/** PUT /vault body: `version` is the version this edit was based on (0 = no vault yet). */
export type PutVaultBody = SerializedVaultBlob;

/** PUT /vault success: the server-confirmed new version. */
export interface PutVaultResult {
  version: number;
  updatedAt: string;
}

/** 409 from PUT /vault — carries the server's current version for re-fetch + retry. */
export class VaultConflictError extends Error {
  constructor(readonly currentVersion: number) {
    super(`vault version conflict (server is at version ${currentVersion})`);
    this.name = 'VaultConflictError';
  }
}

/**
 * 401 from any /vault call — the short-lived vault-scoped JWT has expired or is
 * invalid. Distinct from a generic failure so the UI can tell the user to sign
 * in again rather than uselessly retrying with the same dead token. There is no
 * refresh flow in the MVP (§2.1: session token is deliberately short-lived).
 */
export class VaultUnauthorizedError extends Error {
  constructor() {
    super('vault request unauthorized (session token expired or invalid)');
    this.name = 'VaultUnauthorizedError';
  }
}

export interface VaultApi {
  /** GET /vault → the stored blob, or null when no vault exists yet (204). */
  getVault(): Promise<SerializedVaultBlob | null>;
  /** PUT /vault → new version on success; throws VaultConflictError on 409. */
  putVault(body: PutVaultBody): Promise<PutVaultResult>;
}
