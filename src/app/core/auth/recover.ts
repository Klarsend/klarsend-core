/**
 * Account recovery flow (slice 24) — recovery is RE-ENROLLMENT, not login.
 *
 *   old words ─ validated locally (BIP39 checksum, before ANY network)
 *             ─ derive L ─► probe /auth/recover/options (validates the claim,
 *               returns the recovery wrap; fail-fast unwrap check, discarded)
 *   NEW words ─ generated, shown once, confirmed  ← the SLOW human step
 *   /auth/recover/options again ─► fresh challenge (5-min TTL) ─► WebAuthn
 *   registration ─► rewrapVault under the new credential + new code ─►
 *   /auth/recover commits everything atomically. The old code is burned by
 *   that commit; the new one was confirmed BEFORE it (burn-before-commit:
 *   a user who completes recovery has always already saved the new words).
 *
 * ORDERING (same frozen discipline as signup): the slow ceremony sits between
 * the probe and the challenge fetch, so no human step ever runs inside the
 * challenge window. A normal attempt therefore makes TWO options calls; the
 * abandoned probe challenge is TTL-reaped like an abandoned signup's.
 *
 * ZERO-KNOWLEDGE ACCOUNTING (canary-pinned): the words (old and new) and both
 * recovery unlock keys never leave the device in any encoding. The OLD code's
 * L goes on the wire exactly twice — both times to the endpoint whose ceremony
 * burns it. The NEW code's L never travels at all; only its SHA-256 does.
 */
import {
  RecoveryCodeUnlockKeySource,
  deserializeWrappedKey,
  generateRecoveryCode,
  hashLookupKey,
  lookupKeyFromRecoveryCode,
  rewrapVault,
  serializeKdfConfig,
  serializeWrappedKey,
  toBase64,
  unwrapVaultKey,
} from '../vault-crypto';
import { performEnrollmentCeremony } from './credential-enrollment';
import { toWireAttestation } from './wire-response';
import type { AuthApi, WebAuthnClient } from './wire';

export interface RecoverCallbacks {
  /**
   * Present the NEW 24-word recovery code — shown once, exactly like signup's —
   * and resolve only when the user confirms (the page adds the transcription
   * check). Runs BEFORE anything server-side changes: rejecting aborts the
   * recovery with the account untouched.
   */
  confirmRecoveryCode(words: string[]): Promise<void>;
  /** Only invoked when the new authenticator lacks PRF support. */
  getPassphrase(): Promise<string>;
}

export interface RecoverDeps {
  api: AuthApi;
  webauthn: WebAuthnClient;
  callbacks: RecoverCallbacks;
}

export interface RecoverResult {
  userId: string;
  accessToken: string;
  expiresInSeconds: number;
  sessionVaultKey: CryptoKey;
  unlockMethod: 'passkey-prf' | 'passphrase';
  /** The NEW recovery wrap, serialized — seeds the session for the settings verifier. */
  recoveryWrappedVaultKey: ReturnType<typeof serializeWrappedKey>;
}

export async function recover(deps: RecoverDeps, input: { words: string[] }): Promise<RecoverResult> {
  const { api, webauthn, callbacks } = deps;

  // ── Local validation first: a typo dies here, before any network ────────
  const lookupKey = toBase64(await lookupKeyFromRecoveryCode(input.words));

  // ── Probe: validate the claim and fail fast, BEFORE the slow ceremony ───
  // The server generic-fails an unknown/burned code, so a wrong-but-checksum-
  // valid code (another service's words, an un-enrolled legacy account) is
  // caught before the user transcribes a new code for nothing. The unwrap
  // check is fail-fast honesty against a corrupted wrap; its key is
  // non-extractable and discarded.
  const probe = await api.recoverOptions(lookupKey);
  const oldRecoveryUk = await new RecoveryCodeUnlockKeySource(input.words).deriveUnlockKey();
  await unwrapVaultKey(deserializeWrappedKey(probe.recoveryWrappedVaultKey), oldRecoveryUk);

  // ── The SLOW human step, outside any challenge window ────────────────────
  // Burn-before-commit: the new code is confirmed before the commit that
  // invalidates the old one, so a completed recovery ALWAYS has saved words.
  const newWords = await generateRecoveryCode();
  await callbacks.confirmRecoveryCode(newWords);

  // ── Challenge window opens (fresh challenge; the probe's is TTL-reaped) ──
  const { challengeId, recoveryWrappedVaultKey, options } = await api.recoverOptions(lookupKey);
  const { attestation, kdf, source } = await performEnrollmentCeremony(
    webauthn,
    options,
    callbacks.getPassphrase,
  );

  const newUnlockKey = await source.deriveUnlockKey();
  const newRecoveryUnlockKey = await new RecoveryCodeUnlockKeySource(newWords).deriveUnlockKey();

  const rewrapped = await rewrapVault(
    deserializeWrappedKey(recoveryWrappedVaultKey),
    oldRecoveryUk,
    newUnlockKey,
    newRecoveryUnlockKey,
  );

  const newRecoveryWrapWire = serializeWrappedKey(rewrapped.recoveryWrappedVaultKey);
  const recovered = await api.recover({
    challengeId,
    // toWireAttestation: allowlist copy — PRF output can't reach the wire
    attestationResponse: toWireAttestation(attestation),
    kdf: kdf ? serializeKdfConfig(kdf) : null,
    wrappedVaultKey: serializeWrappedKey(rewrapped.wrappedVaultKey),
    recoveryWrappedVaultKey: newRecoveryWrapWire,
    // the NEW code's one-way fingerprint — its L never goes on the wire
    recoveryLookupHash: toBase64(await hashLookupKey(await lookupKeyFromRecoveryCode(newWords))),
  });
  // ── Challenge window closes (consumed by the atomic commit) ──────────────

  return {
    ...recovered,
    sessionVaultKey: rewrapped.sessionVaultKey,
    unlockMethod: kdf ? 'passphrase' : 'passkey-prf',
    recoveryWrappedVaultKey: newRecoveryWrapWire,
  };
}
