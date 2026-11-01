import { Injectable, computed, signal } from '@angular/core';

/**
 * In-memory holder for the unlocked session's secrets: the vault key (used to
 * encrypt connections before sync) and the vault-scoped access token (used to
 * authorize GET/PUT /vault). Distinct from {@link SessionStore}, which holds
 * only non-sensitive identity for route gating.
 *
 * SECURITY (CLAUDE.md invariant 7): key material lives ONLY in memory. This
 * store is never persisted to localStorage/sessionStorage/cookies; a page
 * refresh drops it and the user unlocks again. The `vaultKey` is a
 * non-extractable CryptoKey (see unwrapVaultKey) so it cannot be read out even
 * from here. This is the runtime seam login/signup populate and the connection
 * wizard consumes — design-foundation deliberately deferred it ("token/vault-key
 * persistence is a later slice's concern").
 */
export interface VaultUnlock {
  vaultKey: CryptoKey;
  accessToken: string;
  /**
   * Slice 24: the recovery wrap (ciphertext — same trust class as the synced
   * wrapped VK) plus the non-secret enrolled flag. Fuels the settings
   * recovery-code verifier as a PURE-LOCAL operation and the migration banner.
   * In memory only, like everything here.
   */
  recovery?: {
    wrappedKey: { ciphertext: string; nonce: string };
    enrolled: boolean;
  };
}

@Injectable({ providedIn: 'root' })
export class VaultSessionStore {
  private readonly _unlock = signal<VaultUnlock | null>(null);

  readonly isUnlocked = computed(() => this._unlock() !== null);

  /** Slice 24: null while locked; drives the enroll-your-recovery-code banner. */
  readonly recovery = computed(() => this._unlock()?.recovery ?? null);

  unlock(unlock: VaultUnlock): void {
    this._unlock.set(unlock);
  }

  clear(): void {
    this._unlock.set(null);
  }

  /** Flip the enrolled flag after a successful PUT /auth/recovery-lookup. */
  markRecoveryEnrolled(): void {
    const current = this._unlock();
    if (current?.recovery) {
      this._unlock.set({ ...current, recovery: { ...current.recovery, enrolled: true } });
    }
  }

  /** The non-extractable session vault key. Throws if the vault is locked. */
  requireVaultKey(): CryptoKey {
    return this.require().vaultKey;
  }

  /** The vault-scoped access token for /vault calls. Throws if the vault is locked. */
  requireAccessToken(): string {
    return this.require().accessToken;
  }

  private require(): VaultUnlock {
    const unlock = this._unlock();
    if (!unlock) {
      throw new Error('vault is locked — sign in to unlock before accessing vault data');
    }
    return unlock;
  }
}
