import { deriveArgon2idBytes, deriveUnlockKeyFromEntropy, importUnlockKeyBytes } from './kdf';
import type { KdfConfig, UnlockKeySource } from './types';

/** Passphrase → Argon2id → Unlock Key (§2.1, the non-PRF fallback path). */
export class PassphraseUnlockKeySource implements UnlockKeySource {
  readonly kind = 'passphrase';

  constructor(
    private readonly passphrase: string,
    private readonly kdf: KdfConfig,
  ) {}

  async deriveUnlockKey(): Promise<CryptoKey> {
    return importUnlockKeyBytes(await deriveArgon2idBytes(this.passphrase, this.kdf));
  }
}

/**
 * Passkey PRF → HKDF → Unlock Key. The WebAuthn ceremony itself lands with
 * the auth slice; this class only needs the 32-byte PRF extension output,
 * supplied by the provider function (tests inject fixed bytes).
 */
export class PrfUnlockKeySource implements UnlockKeySource {
  readonly kind = 'passkey-prf';

  constructor(private readonly getPrfOutput: () => Promise<Uint8Array>) {}

  async deriveUnlockKey(): Promise<CryptoKey> {
    const prf = await this.getPrfOutput();
    try {
      return await deriveUnlockKeyFromEntropy(prf, 'prf');
    } finally {
      prf.fill(0);
    }
  }
}
