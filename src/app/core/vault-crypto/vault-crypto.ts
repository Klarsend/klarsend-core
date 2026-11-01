import { VaultCryptoError } from './errors';
import type { Argon2idParams, EncryptedPayload, KdfConfig, WrappedKey } from './types';
import { DEFAULT_ARGON2ID_PARAMS } from './types';

const NONCE_BYTES = 12; // 96-bit GCM nonce
const KDF_SALT_BYTES = 16;

/** Fresh per-user KDF config (random salt) for signup / passphrase change. */
export function generateKdfConfig(params: Argon2idParams = DEFAULT_ARGON2ID_PARAMS): KdfConfig {
  return {
    algorithm: 'argon2id',
    salt: crypto.getRandomValues(new Uint8Array(KDF_SALT_BYTES)),
    params: { ...params },
  };
}

/**
 * Random 256-bit Vault Key (§2.1), generated once at signup. Extractable so
 * it can be wrapped under the unlock key and the recovery key; session keys
 * obtained later via `unwrapVaultKey` are non-extractable by default.
 */
export function generateVaultKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

/** Wrap the vault key under an unlock key (AES-256-GCM, fresh nonce). */
export async function wrapVaultKey(vaultKey: CryptoKey, unlockKey: CryptoKey): Promise<WrappedKey> {
  const nonce = randomNonce();
  const ciphertext = await crypto.subtle.wrapKey('raw', vaultKey, unlockKey, { name: 'AES-GCM', iv: nonce });
  return { ciphertext: new Uint8Array(ciphertext), nonce };
}

/**
 * Unwrap the vault key. Throws `VaultCryptoError('unwrap-failed')` on a wrong
 * unlock key or tampered blob — GCM authentication makes both indistinguishable
 * by design. Pass `extractable: true` only to rewrap (passphrase change, recovery).
 */
export async function unwrapVaultKey(
  wrapped: WrappedKey,
  unlockKey: CryptoKey,
  opts: { extractable?: boolean } = {},
): Promise<CryptoKey> {
  try {
    return await crypto.subtle.unwrapKey(
      'raw',
      wrapped.ciphertext,
      unlockKey,
      { name: 'AES-GCM', iv: wrapped.nonce },
      { name: 'AES-GCM', length: 256 },
      opts.extractable ?? false,
      ['encrypt', 'decrypt'],
    );
  } catch {
    throw new VaultCryptoError('unwrap-failed', 'could not unwrap vault key');
  }
}

/**
 * Signup helper: generate the VK, wrap it under the unlock key and the
 * recovery key, then discard the extractable original and return a
 * non-extractable session copy — no extractable VK handle outlives signup.
 */
export async function createVault(
  unlockKey: CryptoKey,
  recoveryUnlockKey: CryptoKey,
): Promise<{ sessionVaultKey: CryptoKey; wrappedVaultKey: WrappedKey; recoveryWrappedVaultKey: WrappedKey }> {
  const extractableVk = await generateVaultKey();
  const wrappedVaultKey = await wrapVaultKey(extractableVk, unlockKey);
  const recoveryWrappedVaultKey = await wrapVaultKey(extractableVk, recoveryUnlockKey);
  // last reference to the extractable handle ends here; the session key is unwrapped non-extractable
  const sessionVaultKey = await unwrapVaultKey(wrappedVaultKey, unlockKey);
  return { sessionVaultKey, wrappedVaultKey, recoveryWrappedVaultKey };
}

/**
 * Recovery / credential-change helper (slice 24): unwrap the VK from an
 * existing wrap, rewrap it under a new unlock key and a new recovery key,
 * then discard the extractable handle — same discipline as `createVault`:
 * no extractable VK outlives the call. The inputs are never mutated; the
 * caller's old wraps stay valid until the server-side atomic replace.
 */
export async function rewrapVault(
  oldWrapped: WrappedKey,
  oldUnlockKey: CryptoKey,
  newUnlockKey: CryptoKey,
  newRecoveryUnlockKey: CryptoKey,
): Promise<{ sessionVaultKey: CryptoKey; wrappedVaultKey: WrappedKey; recoveryWrappedVaultKey: WrappedKey }> {
  const extractableVk = await unwrapVaultKey(oldWrapped, oldUnlockKey, { extractable: true });
  const wrappedVaultKey = await wrapVaultKey(extractableVk, newUnlockKey);
  const recoveryWrappedVaultKey = await wrapVaultKey(extractableVk, newRecoveryUnlockKey);
  // last reference to the extractable handle ends here; the session key is unwrapped non-extractable
  const sessionVaultKey = await unwrapVaultKey(wrappedVaultKey, newUnlockKey);
  return { sessionVaultKey, wrappedVaultKey, recoveryWrappedVaultKey };
}

/** Encrypt a vault entry / vault blob under the vault key. Fresh random nonce every call. */
export async function encryptEntry(vaultKey: CryptoKey, plaintext: Uint8Array): Promise<EncryptedPayload> {
  const nonce = randomNonce();
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, vaultKey, plaintext);
  return { ciphertext: new Uint8Array(ciphertext), nonce };
}

/** Decrypt a payload. Throws `VaultCryptoError('decrypt-failed')` if GCM authentication fails. */
export async function decryptEntry(vaultKey: CryptoKey, payload: EncryptedPayload): Promise<Uint8Array> {
  try {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: payload.nonce },
      vaultKey,
      payload.ciphertext,
    );
    return new Uint8Array(plain);
  } catch {
    throw new VaultCryptoError('decrypt-failed', 'could not decrypt payload');
  }
}

function randomNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
}
