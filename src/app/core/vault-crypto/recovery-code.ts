import { wordlist } from '@scure/bip39/wordlists/english.js';

import { VaultCryptoError } from './errors';
import { deriveUnlockKeyFromEntropy } from './kdf';
import type { UnlockKeySource } from './types';

const WORD_COUNT = 24;
const ENTROPY_BYTES = 32;

/**
 * 24-word recovery code (§2.1), BIP39-compatible encoding: 256 bits of
 * entropy + 8-bit SHA-256 checksum → 24 × 11-bit wordlist indices. Only the
 * *encoding* is implemented here; hashing and randomness come from WebCrypto
 * and the wordlist is imported as data (invariant 4).
 */
export async function generateRecoveryCode(): Promise<string[]> {
  const entropy = crypto.getRandomValues(new Uint8Array(ENTROPY_BYTES));
  try {
    return await recoveryCodeFromEntropy(entropy);
  } finally {
    entropy.fill(0);
  }
}

/** Deterministic entropy → words mapping. Exported for the BIP39 known-answer vector test. */
export async function recoveryCodeFromEntropy(entropy: Uint8Array): Promise<string[]> {
  if (entropy.length !== ENTROPY_BYTES) {
    throw new VaultCryptoError('invalid-recovery-code', 'recovery entropy must be 32 bytes');
  }
  const checksum = await checksumByte(entropy);

  // 33 bytes = 264 bits = 24 × 11-bit indices
  let acc = 0n;
  for (const byte of entropy) {
    acc = (acc << 8n) | BigInt(byte);
  }
  acc = (acc << 8n) | BigInt(checksum);

  const words = new Array<string>(WORD_COUNT);
  for (let i = WORD_COUNT - 1; i >= 0; i--) {
    words[i] = wordlist[Number(acc & 0x7ffn)];
    acc >>= 11n;
  }
  return words;
}

/** Words → entropy, validating length, wordlist membership, and checksum. */
export async function entropyFromRecoveryCode(words: string[]): Promise<Uint8Array> {
  if (words.length !== WORD_COUNT) {
    throw new VaultCryptoError('invalid-recovery-code', 'recovery code must be exactly 24 words');
  }
  let acc = 0n;
  for (const raw of words) {
    const index = wordlist.indexOf(raw.trim().toLowerCase());
    if (index < 0) {
      throw new VaultCryptoError('invalid-recovery-code', 'recovery code contains an unknown word');
    }
    acc = (acc << 11n) | BigInt(index);
  }

  const checksum = Number(acc & 0xffn);
  acc >>= 8n;
  const entropy = new Uint8Array(ENTROPY_BYTES);
  for (let i = ENTROPY_BYTES - 1; i >= 0; i--) {
    entropy[i] = Number(acc & 0xffn);
    acc >>= 8n;
  }

  if ((await checksumByte(entropy)) !== checksum) {
    entropy.fill(0);
    throw new VaultCryptoError('invalid-recovery-code', 'recovery code checksum mismatch');
  }
  return entropy;
}

async function checksumByte(entropy: Uint8Array): Promise<number> {
  const digest = await crypto.subtle.digest('SHA-256', entropy);
  return new Uint8Array(digest)[0];
}

/** Unlock-key source backed by a 24-word recovery code. */
export class RecoveryCodeUnlockKeySource implements UnlockKeySource {
  readonly kind = 'recovery-code';

  constructor(private readonly words: string[]) {}

  async deriveUnlockKey(): Promise<CryptoKey> {
    const entropy = await entropyFromRecoveryCode(this.words);
    try {
      return await deriveUnlockKeyFromEntropy(entropy, 'recovery');
    } finally {
      entropy.fill(0);
    }
  }
}
