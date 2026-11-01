export type VaultCryptoErrorCode =
  /** Wrong unlock key (wrong passphrase / PRF output / recovery code) or corrupted wrapped key. */
  | 'unwrap-failed'
  /** GCM authentication failed: wrong vault key or tampered/corrupted payload. */
  | 'decrypt-failed'
  /** Recovery code malformed: wrong word count, unknown word, or checksum mismatch. */
  | 'invalid-recovery-code';

/**
 * The only error type this module throws for crypto failures. Messages are
 * static and never contain key material or plaintext (CLAUDE.md invariant 2).
 */
export class VaultCryptoError extends Error {
  constructor(
    readonly code: VaultCryptoErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'VaultCryptoError';
  }
}
