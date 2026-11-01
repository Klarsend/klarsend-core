import { entropyFromRecoveryCode } from './recovery-code';
import { utf8Encode } from './encoding';

/**
 * Recovery lookup key L (slice 24 — account recovery).
 *
 * A second, independent HKDF branch from the same 24-word recovery entropy
 * that derives the recovery unlock key:
 *
 *   entropy ─ HKDF salt "klarsend/v1/recovery"        → UK_recovery (unwraps; never leaves device)
 *          └─ HKDF salt "klarsend/v1/recovery-lookup" → L           (identifies + authenticates recovery)
 *
 * L is sent to the server ONCE, at redemption, over TLS; the server stores
 * only SHA-256(L), so a database breach yields a value that cannot be
 * inverted, cannot unwrap anything, and cannot even be replayed (the server
 * demands the preimage). Standard HKDF domain separation guarantees L reveals
 * nothing about UK_recovery. Test vectors: vault-crypto.spec.ts (invariant 3).
 */
export async function deriveLookupKeyFromEntropy(entropy: Uint8Array): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey('raw', entropy, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: utf8Encode('klarsend/v1/recovery-lookup'),
      info: utf8Encode('lookup-key'),
    },
    ikm,
    256,
  );
  return new Uint8Array(bits);
}

/** Words → L, through the slice-1 BIP39 validation (length, wordlist, checksum). */
export async function lookupKeyFromRecoveryCode(words: string[]): Promise<Uint8Array> {
  const entropy = await entropyFromRecoveryCode(words);
  try {
    return await deriveLookupKeyFromEntropy(entropy);
  } finally {
    entropy.fill(0);
  }
}

/** The enrollment form of L: SHA-256(L). This — never L itself — is what enrollment uploads. */
export async function hashLookupKey(lookupKey: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', lookupKey));
}
