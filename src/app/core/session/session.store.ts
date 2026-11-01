import { Injectable, computed, signal } from '@angular/core';

/**
 * Minimal in-memory session state for route gating. Deliberately holds only
 * non-sensitive identity — NEVER key material, and never persisted to
 * localStorage/sessionStorage/cookies (security invariant §7). A page refresh
 * clears it; token/vault-key persistence is a later slice's concern.
 */
export interface AppSession {
  userId: string;
  unlockMethod: 'passkey-prf' | 'passphrase';
}

@Injectable({ providedIn: 'root' })
export class SessionStore {
  private readonly _session = signal<AppSession | null>(null);

  readonly session = this._session.asReadonly();
  readonly isAuthenticated = computed(() => this._session() !== null);

  start(session: AppSession): void {
    this._session.set(session);
  }

  clear(): void {
    this._session.set(null);
  }
}
