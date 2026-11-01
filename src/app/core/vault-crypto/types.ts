/** Argon2id cost parameters (§2.1). `memoryKiB` is in KiB (65536 = 64 MiB). */
export interface Argon2idParams {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

/** Spec §2.1: memory 64 MB, iterations 3, parallelism 4. */
export const DEFAULT_ARGON2ID_PARAMS: Argon2idParams = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 4,
};

/**
 * Per-user KDF configuration, stored server-side alongside the wrapped vault
 * key (`users.kdf` in the data model) — salt and params are not secret.
 */
export interface KdfConfig {
  algorithm: 'argon2id';
  salt: Uint8Array;
  params: Argon2idParams;
}

/** AES-256-GCM output. The GCM tag is the trailing 16 bytes of `ciphertext`. */
export interface EncryptedPayload {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

/** A vault key wrapped (AES-256-GCM) under an unlock key. Same shape, distinct meaning. */
export type WrappedKey = EncryptedPayload;

/**
 * Anything that can produce the Unlock Key (UK). Passphrase (Argon2id),
 * passkey PRF (HKDF over the PRF extension output), and the recovery code
 * (HKDF over the code's entropy) all converge on the same key type, so the
 * wrap/unwrap API is source-agnostic.
 */
export interface UnlockKeySource {
  readonly kind: 'passphrase' | 'passkey-prf' | 'recovery-code';
  /** Returns a non-extractable AES-256-GCM CryptoKey with wrapKey/unwrapKey usages. */
  deriveUnlockKey(): Promise<CryptoKey>;
}
