/**
 * Signup flow (§2.1): recovery-code confirm → WebAuthn registration →
 * PRF-or-passphrase Unlock Key → vault creation → POST wrapped material. The
 * server receives ciphertext, public KDF config, and (slice 24) the one-way
 * hash of the recovery lookup key only.
 *
 * ORDERING (deliberate): the recovery code is generated and confirmed BEFORE
 * `registerOptions` fetches the WebAuthn challenge. The challenge has a short
 * server-side TTL, and confirming a 24-word recovery code can take minutes;
 * keeping that human step outside the challenge window is what prevents the
 * challenge from expiring mid-signup. Only steps that genuinely need the
 * ceremony output (PRF/passphrase Unlock Key, the VK wrap) run inside the
 * window — see the dependency note above `signup()`.
 */
import {
  RecoveryCodeUnlockKeySource,
  createVault,
  generateRecoveryCode,
  hashLookupKey,
  lookupKeyFromRecoveryCode,
  serializeKdfConfig,
  serializeWrappedKey,
  toBase64,
} from '../vault-crypto';
import { performEnrollmentCeremony } from './credential-enrollment';
import { toWireAttestation } from './wire-response';
import type { AuthApi, WebAuthnClient } from './wire';
import { CURRENT_TERMS_VERSION } from '../legal';

export interface SignupCallbacks {
  /**
   * Present the 24-word recovery code — the ONE time it is ever shown — and
   * resolve only when the user confirms they stored it. Rejecting aborts the
   * signup before anything is sent to the server.
   *
   * NOTE FOR THE UI (register page): this now runs BEFORE the passkey ceremony,
   * so the code is shown while signup is still incomplete. If the ceremony or
   * the register POST then fails, this code is VOID — it was never bound to a
   * vault. The page copy must say so, e.g. "This code only becomes valid once
   * setup finishes. If setup doesn't complete, discard it — you'll be shown a
   * new one next time." Do not present it as final until `signup()` resolves.
   */
  confirmRecoveryCode(words: string[]): Promise<void>;
  /** Only invoked when the authenticator lacks PRF support. */
  getPassphrase(): Promise<string>;
}

export interface SignupDeps {
  api: AuthApi;
  webauthn: WebAuthnClient;
  callbacks: SignupCallbacks;
}

export interface SignupResult {
  userId: string;
  accessToken: string;
  expiresInSeconds: number;
  sessionVaultKey: CryptoKey;
  unlockMethod: 'passkey-prf' | 'passphrase';
  /** Slice 24: the recovery wrap, serialized — seeds the session for the settings verifier. */
  recoveryWrappedVaultKey: ReturnType<typeof serializeWrappedKey>;
}

export async function signup(
  deps: SignupDeps,
  input: { displayName?: string; termsAccepted?: boolean } = {},
): Promise<SignupResult> {
  const { api, webauthn, callbacks } = deps;

  if (input.termsAccepted !== true) {
    throw new Error('terms acceptance required');
  }

  // ── Outside the challenge window ─────────────────────────────────────────
  // The recovery words are independent random entropy (no dependency on the
  // credential, PRF output, or VK), so this — the slow human step — runs
  // before any challenge exists. They are wrapped later, once the ceremony
  // has produced an Unlock Key.
  const recoveryWords = await generateRecoveryCode();
  await callbacks.confirmRecoveryCode(recoveryWords);

  // ── Challenge window opens ───────────────────────────────────────────────
  const { challengeId, options } = await api.registerOptions(input.displayName);
  const { attestation, kdf, source } = await performEnrollmentCeremony(
    webauthn,
    options,
    callbacks.getPassphrase,
  );

  const unlockKey = await source.deriveUnlockKey();
  const recoveryUnlockKey = await new RecoveryCodeUnlockKeySource(recoveryWords).deriveUnlockKey();

  const { sessionVaultKey, wrappedVaultKey, recoveryWrappedVaultKey } = await createVault(
    unlockKey,
    recoveryUnlockKey,
  );

  const recoveryWrapWire = serializeWrappedKey(recoveryWrappedVaultKey);
  const registered = await api.register({
    challengeId,
    // toWireAttestation: allowlist copy — PRF output can't reach the wire
    attestationResponse: toWireAttestation(attestation),
    kdf: kdf ? serializeKdfConfig(kdf) : null,
    wrappedVaultKey: serializeWrappedKey(wrappedVaultKey),
    recoveryWrappedVaultKey: recoveryWrapWire,
    // slice 24: the one-way fingerprint of the lookup key — never L itself
    recoveryLookupHash: toBase64(await hashLookupKey(await lookupKeyFromRecoveryCode(recoveryWords))),
    termsAccepted: true,
    termsVersion: CURRENT_TERMS_VERSION,
  });
  // ── Challenge window closes (consumed by register) ───────────────────────

  return {
    ...registered,
    sessionVaultKey,
    unlockMethod: kdf ? 'passphrase' : 'passkey-prf',
    recoveryWrappedVaultKey: recoveryWrapWire,
  };
}
