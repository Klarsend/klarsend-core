/**
 * Wire shapes for the sync API — the exact JSON the client exchanges with
 * the server. All byte fields are standard base64 strings; nothing here is
 * plaintext key material (only ciphertext, nonces, and public KDF config).
 */
import { fromBase64, toBase64 } from './encoding';
import type { Argon2idParams, EncryptedPayload, KdfConfig, WrappedKey } from './types';

/** Wire form of a wrapped vault key (`users.wrappedVaultKey` / `recoveryWrappedVaultKey`). */
export interface SerializedWrappedKey {
  ciphertext: string;
  nonce: string;
}

/** Wire form of the whole-vault blob (`vaultBlobs` document, §4 data model). */
export interface SerializedVaultBlob {
  ciphertext: string;
  nonce: string;
  version: number;
}

/** Wire form of the per-user KDF config (`users.kdf`) — salt and params are not secret. */
export interface SerializedKdfConfig extends Argon2idParams {
  algorithm: 'argon2id';
  salt: string;
}

export function serializeWrappedKey(wrapped: WrappedKey): SerializedWrappedKey {
  return { ciphertext: toBase64(wrapped.ciphertext), nonce: toBase64(wrapped.nonce) };
}

export function deserializeWrappedKey(wire: SerializedWrappedKey): WrappedKey {
  return { ciphertext: fromBase64(wire.ciphertext), nonce: fromBase64(wire.nonce) };
}

export function serializeVaultBlob(payload: EncryptedPayload, version: number): SerializedVaultBlob {
  return { ciphertext: toBase64(payload.ciphertext), nonce: toBase64(payload.nonce), version };
}

export function deserializeVaultBlob(wire: SerializedVaultBlob): { payload: EncryptedPayload; version: number } {
  return {
    payload: { ciphertext: fromBase64(wire.ciphertext), nonce: fromBase64(wire.nonce) },
    version: wire.version,
  };
}

export function serializeKdfConfig(kdf: KdfConfig): SerializedKdfConfig {
  return { algorithm: kdf.algorithm, salt: toBase64(kdf.salt), ...kdf.params };
}

export function deserializeKdfConfig(wire: SerializedKdfConfig): KdfConfig {
  return {
    algorithm: wire.algorithm,
    salt: fromBase64(wire.salt),
    params: { memoryKiB: wire.memoryKiB, iterations: wire.iterations, parallelism: wire.parallelism },
  };
}
