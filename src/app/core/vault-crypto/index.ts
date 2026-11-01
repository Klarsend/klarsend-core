/**
 * Vault crypto module (spec §2.1) — standalone: no UI, no API dependencies.
 *
 * Key hierarchy:
 *   passphrase ── Argon2id ──┐
 *   passkey PRF ── HKDF ─────┼──► Unlock Key ── wraps ──► Vault Key ── encrypts ──► entries
 *   recovery code ── HKDF ───┘        (AES-256-GCM everywhere, fresh random nonce per encryption)
 *
 * CLAUDE.md invariant 3: changes here require extending vault-crypto.spec.ts first.
 */
export { VaultCryptoError, type VaultCryptoErrorCode } from './errors';
export {
  DEFAULT_ARGON2ID_PARAMS,
  type Argon2idParams,
  type EncryptedPayload,
  type KdfConfig,
  type UnlockKeySource,
  type WrappedKey,
} from './types';
export { PassphraseUnlockKeySource, PrfUnlockKeySource } from './unlock-key';
export {
  RecoveryCodeUnlockKeySource,
  entropyFromRecoveryCode,
  generateRecoveryCode,
  recoveryCodeFromEntropy,
} from './recovery-code';
export {
  deriveLookupKeyFromEntropy,
  hashLookupKey,
  lookupKeyFromRecoveryCode,
} from './recovery-lookup';
export {
  createVault,
  decryptEntry,
  encryptEntry,
  generateKdfConfig,
  generateVaultKey,
  rewrapVault,
  unwrapVaultKey,
  wrapVaultKey,
} from './vault-crypto';
export { fromBase64, toBase64 } from './encoding';
export {
  deserializeKdfConfig,
  deserializeVaultBlob,
  deserializeWrappedKey,
  serializeKdfConfig,
  serializeVaultBlob,
  serializeWrappedKey,
  type SerializedKdfConfig,
  type SerializedVaultBlob,
  type SerializedWrappedKey,
} from './serialization';
