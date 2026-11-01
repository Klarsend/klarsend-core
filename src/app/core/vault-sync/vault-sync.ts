/**
 * Vault blob sync (spec §3.1 #2): pull on unlock, push on change, optimistic
 * concurrency. All encryption happens here on the device with the session
 * vault key — the API only ever sees {ciphertext, nonce, version}. On a 409
 * the client re-fetches the server state and retries; the retried push keeps
 * this device's plaintext (last-writer-wins, the documented MVP conflict
 * policy — a merge UI is deliberately out of scope).
 */
import { decryptEntry, deserializeVaultBlob, encryptEntry, serializeVaultBlob } from '../vault-crypto';
import { VaultConflictError, type VaultApi } from './wire';

/** Conflicts should resolve in one round; more than this means something is broken, not busy. */
const MAX_PUSH_ATTEMPTS = 3;

export interface VaultSyncDeps {
  api: VaultApi;
  /** The unlocked session vault key (in memory only — CLAUDE.md invariant 7). */
  vaultKey: CryptoKey;
}

export interface PulledVault {
  /** Decrypted vault contents, or null when no vault exists on the server yet. */
  plaintext: Uint8Array | null;
  version: number;
}

export class VaultSync {
  private version = 0;

  constructor(private readonly deps: VaultSyncDeps) {}

  /**
   * Pull on unlock (and on 409 recovery): fetch the blob, decrypt it locally,
   * adopt the server's version as the base for the next push.
   */
  async pull(): Promise<PulledVault> {
    const remote = await this.deps.api.getVault();
    if (remote === null) {
      this.version = 0;
      return { plaintext: null, version: 0 };
    }
    const { payload, version } = deserializeVaultBlob(remote);
    const plaintext = await decryptEntry(this.deps.vaultKey, payload); // throws on tamper (GCM)
    this.version = version;
    return { plaintext, version };
  }

  /**
   * Push on change: encrypt (fresh nonce), PUT with the last-seen version.
   * 409 → re-fetch, adopt the current version, retry with the same plaintext.
   * Returns the server-confirmed version.
   */
  async push(plaintext: Uint8Array): Promise<number> {
    for (let attempt = 0; attempt < MAX_PUSH_ATTEMPTS; attempt++) {
      const payload = await encryptEntry(this.deps.vaultKey, plaintext);
      try {
        const result = await this.deps.api.putVault(serializeVaultBlob(payload, this.version));
        this.version = result.version;
        return result.version;
      } catch (error) {
        if (!(error instanceof VaultConflictError)) {
          throw error;
        }
        await this.pull(); // adopt the winning writer's version; our plaintext still wins the retry
      }
    }
    throw new Error(`vault push failed: version conflicts persisted after ${MAX_PUSH_ATTEMPTS} attempts`);
  }
}
