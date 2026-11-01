import { argon2id } from 'hash-wasm';

import type { KdfConfig } from './types';

/**
 * Raw Argon2id derivation (hash-wasm, wasm — CLAUDE.md invariant 4: no
 * hand-rolled primitives). Internal: exported for the known-answer test
 * vectors only; production code goes through `PassphraseUnlockKeySource`,
 * which never exposes the raw key bytes.
 */
export async function deriveArgon2idBytes(passphrase: string, kdf: KdfConfig): Promise<Uint8Array> {
  return argon2id({
    password: passphrase,
    salt: kdf.salt,
    memorySize: kdf.params.memoryKiB,
    iterations: kdf.params.iterations,
    parallelism: kdf.params.parallelism,
    hashLength: 32,
    outputType: 'binary',
  });
}

/** Import 32 raw key bytes as a non-extractable AES-256-GCM unlock key, then zero the input. */
export async function importUnlockKeyBytes(bytes: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['wrapKey', 'unwrapKey']);
  } finally {
    bytes.fill(0);
  }
}

/**
 * Derive a non-extractable AES-256-GCM unlock key from full-entropy input
 * key material (passkey PRF output or recovery-code entropy) via HKDF-SHA256.
 * A slow KDF is unnecessary here: the IKM is already 256 uniform bits.
 */
export async function deriveUnlockKeyFromEntropy(
  ikm: Uint8Array,
  context: 'prf' | 'recovery',
): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(`klarsend/v1/${context}`),
      info: new TextEncoder().encode('unlock-key'),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey'],
  );
}
