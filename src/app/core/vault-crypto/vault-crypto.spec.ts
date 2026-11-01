/**
 * Test-vector suite for the vault crypto module (spec §2.1) — written BEFORE
 * the implementation (CLAUDE.md security invariant 3).
 *
 * Key hierarchy under test:
 *   passphrase ── Argon2id ──┐
 *   passkey PRF ── HKDF ─────┼──► Unlock Key (UK) ── wraps ──► Vault Key (VK)
 *   recovery code ── HKDF ───┘                                    │
 *                                        AES-256-GCM, fresh nonce ▼
 *                                                          vault entries
 */
import { describe, expect, it, vi } from 'vitest';

import {
  DEFAULT_ARGON2ID_PARAMS,
  PassphraseUnlockKeySource,
  PrfUnlockKeySource,
  RecoveryCodeUnlockKeySource,
  VaultCryptoError,
  createVault,
  decryptEntry,
  deserializeKdfConfig,
  deserializeVaultBlob,
  deserializeWrappedKey,
  encryptEntry,
  generateKdfConfig,
  generateRecoveryCode,
  generateVaultKey,
  recoveryCodeFromEntropy,
  serializeKdfConfig,
  serializeVaultBlob,
  serializeWrappedKey,
  deriveLookupKeyFromEntropy,
  hashLookupKey,
  lookupKeyFromRecoveryCode,
  rewrapVault,
  unwrapVaultKey,
  wrapVaultKey,
  type EncryptedPayload,
  type KdfConfig,
  type SerializedVaultBlob,
  type SerializedWrappedKey,
  type UnlockKeySource,
} from './index';
import { deriveArgon2idBytes } from './kdf';
import { fromHex, toHex, utf8Decode, utf8Encode } from './encoding';

/** Fast Argon2id params for tests that don't assert on KDF strength. */
const LIGHT_PARAMS = { memoryKiB: 1024, iterations: 3, parallelism: 4 };

const FIXED_SALT = fromHex('000102030405060708090a0b0c0d0e0f');

function lightKdf(): KdfConfig {
  return { algorithm: 'argon2id', salt: FIXED_SALT.slice(), params: { ...LIGHT_PARAMS } };
}

const SAMPLE_ENTRY = utf8Encode(
  JSON.stringify({
    type: 'azure-sas-url',
    label: 'Client X — masters container',
    value: 'https://clientx.blob.core.windows.net/masters?sv=2024-11-04&sig=REDACTED',
  }),
);

describe('key hierarchy round-trip (§2.1)', () => {
  it('passphrase → UK wraps VK; entry encrypts and decrypts', async () => {
    const uk = await new PassphraseUnlockKeySource('correct horse battery staple', lightKdf()).deriveUnlockKey();
    const vk = await generateVaultKey();
    const wrapped = await wrapVaultKey(vk, uk);

    const blob = await encryptEntry(vk, SAMPLE_ENTRY);
    const unlockedVk = await unwrapVaultKey(wrapped, uk);
    const plain = await decryptEntry(unlockedVk, blob);

    expect(toHex(plain)).toBe(toHex(SAMPLE_ENTRY));
    expect(utf8Decode(plain)).toContain('azure-sas-url');
  });

  it('new device flow: fresh UK derivation unwraps the synced wrapped VK', async () => {
    const kdf = lightKdf();
    const passphrase = 'correct horse battery staple';

    // Device A: signup
    const ukA = await new PassphraseUnlockKeySource(passphrase, kdf).deriveUnlockKey();
    const vk = await generateVaultKey();
    const wrapped = await wrapVaultKey(vk, ukA);
    const blob = await encryptEntry(vk, SAMPLE_ENTRY);

    // Device B: downloads {wrapped VK, encrypted blob, kdf config}, derives UK independently
    const ukB = await new PassphraseUnlockKeySource(passphrase, kdf).deriveUnlockKey();
    const vkB = await unwrapVaultKey(wrapped, ukB);
    expect(toHex(await decryptEntry(vkB, blob))).toBe(toHex(SAMPLE_ENTRY));
  });

  it('unwrapped vault key is non-extractable by default', async () => {
    const uk = await new PassphraseUnlockKeySource('pw', lightKdf()).deriveUnlockKey();
    const vk = await generateVaultKey();
    const unlocked = await unwrapVaultKey(await wrapVaultKey(vk, uk), uk);
    expect(unlocked.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', unlocked)).rejects.toThrow();
  });

  it('passphrase change: rewrap VK under a new UK', async () => {
    const oldUk = await new PassphraseUnlockKeySource('old pw', lightKdf()).deriveUnlockKey();
    const vk = await generateVaultKey();
    const oldWrapped = await wrapVaultKey(vk, oldUk);
    const blob = await encryptEntry(vk, SAMPLE_ENTRY);

    // change passphrase: unwrap extractable, rewrap under new UK
    const extractableVk = await unwrapVaultKey(oldWrapped, oldUk, { extractable: true });
    const newKdf = generateKdfConfig(LIGHT_PARAMS);
    const newUk = await new PassphraseUnlockKeySource('new pw', newKdf).deriveUnlockKey();
    const newWrapped = await wrapVaultKey(extractableVk, newUk);

    const vkViaNew = await unwrapVaultKey(newWrapped, newUk);
    expect(toHex(await decryptEntry(vkViaNew, blob))).toBe(toHex(SAMPLE_ENTRY));
  });

  it('default Argon2id params match spec §2.1 (64 MiB, t=3, p=4) and derive a working UK', async () => {
    expect(DEFAULT_ARGON2ID_PARAMS).toEqual({ memoryKiB: 65536, iterations: 3, parallelism: 4 });

    const kdf = generateKdfConfig(); // defaults
    expect(kdf.params).toEqual(DEFAULT_ARGON2ID_PARAMS);
    expect(kdf.salt.length).toBe(16);

    const uk = await new PassphraseUnlockKeySource('correct horse battery staple', kdf).deriveUnlockKey();
    const vk = await generateVaultKey();
    const roundTripped = await unwrapVaultKey(await wrapVaultKey(vk, uk), uk);
    expect(roundTripped.type).toBe('secret');
  });
});

describe('Argon2id known-answer vectors (pin the KDF + parameter mapping)', () => {
  it('light params vector', async () => {
    const out = await deriveArgon2idBytes('correct horse battery staple', {
      algorithm: 'argon2id',
      salt: FIXED_SALT,
      params: LIGHT_PARAMS,
    });
    expect(toHex(out)).toBe('00a25649dddfe222ccc5e274c6e01824376754449f71182d45084a020f3b5e19');
  });

  it('full spec-params vector (64 MiB, t=3, p=4)', async () => {
    const out = await deriveArgon2idBytes('correct horse battery staple', {
      algorithm: 'argon2id',
      salt: FIXED_SALT,
      params: DEFAULT_ARGON2ID_PARAMS,
    });
    expect(toHex(out)).toBe('853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e');
  });
});

describe('wrong credentials fail cleanly', () => {
  it('wrong passphrase → VaultCryptoError("unwrap-failed"), not garbage output', async () => {
    const kdf = lightKdf();
    const uk = await new PassphraseUnlockKeySource('right passphrase', kdf).deriveUnlockKey();
    const wrapped = await wrapVaultKey(await generateVaultKey(), uk);

    const wrongUk = await new PassphraseUnlockKeySource('wrong passphrase', kdf).deriveUnlockKey();
    const attempt = unwrapVaultKey(wrapped, wrongUk);
    await expect(attempt).rejects.toBeInstanceOf(VaultCryptoError);
    await expect(attempt).rejects.toMatchObject({ code: 'unwrap-failed' });
  });

  it('wrong PRF output → unwrap-failed', async () => {
    const prfA = new Uint8Array(32).fill(7);
    const prfB = new Uint8Array(32).fill(8);
    const ukA = await new PrfUnlockKeySource(async () => prfA).deriveUnlockKey();
    const ukB = await new PrfUnlockKeySource(async () => prfB).deriveUnlockKey();
    const wrapped = await wrapVaultKey(await generateVaultKey(), ukA);
    await expect(unwrapVaultKey(wrapped, ukB)).rejects.toMatchObject({ code: 'unwrap-failed' });
  });
});

describe('recovery code path (§2.1)', () => {
  it('generates 24 distinct-entropy words from the BIP39 english wordlist', async () => {
    const words = await generateRecoveryCode();
    expect(words).toHaveLength(24);
    for (const w of words) {
      expect(w).toMatch(/^[a-z]+$/);
    }
    // two generations must differ (256 bits of entropy)
    expect((await generateRecoveryCode()).join(' ')).not.toBe(words.join(' '));
  });

  it('recovery code independently wraps VK and recovers the vault', async () => {
    // signup: VK wrapped under both the passphrase UK and the recovery UK
    const passUk = await new PassphraseUnlockKeySource('some passphrase', lightKdf()).deriveUnlockKey();
    const vk = await generateVaultKey();
    const wrappedForPassphrase = await wrapVaultKey(vk, passUk);
    void wrappedForPassphrase; // stored server-side; unused in the recovery flow below

    const words = await generateRecoveryCode();
    const recoveryUk = await new RecoveryCodeUnlockKeySource(words).deriveUnlockKey();
    const recoveryWrapped = await wrapVaultKey(vk, recoveryUk);
    const blob = await encryptEntry(vk, SAMPLE_ENTRY);

    // user lost the passphrase: recovery code alone must recover the vault
    const recoveryUk2 = await new RecoveryCodeUnlockKeySource([...words]).deriveUnlockKey();
    const recoveredVk = await unwrapVaultKey(recoveryWrapped, recoveryUk2, { extractable: true });
    expect(toHex(await decryptEntry(recoveredVk, blob))).toBe(toHex(SAMPLE_ENTRY));

    // ...and the recovered (extractable) VK can be rewrapped under a new passphrase
    const newUk = await new PassphraseUnlockKeySource('brand new passphrase', lightKdf()).deriveUnlockKey();
    const rewrapped = await wrapVaultKey(recoveredVk, newUk);
    const vkViaNewPass = await unwrapVaultKey(rewrapped, newUk);
    expect(toHex(await decryptEntry(vkViaNewPass, blob))).toBe(toHex(SAMPLE_ENTRY));
  });

  it('BIP39 known-answer vector: all-zero entropy → abandon ×23 + art', async () => {
    const words = await recoveryCodeFromEntropy(new Uint8Array(32));
    expect(words).toHaveLength(24);
    expect(words.slice(0, 23)).toEqual(Array(23).fill('abandon'));
    expect(words[23]).toBe('art');
  });

  it('rejects a code with a corrupted word (checksum mismatch)', async () => {
    const words = await generateRecoveryCode();
    const tampered = [...words];
    tampered[3] = tampered[3] === 'abandon' ? 'ability' : 'abandon';
    const attempt = new RecoveryCodeUnlockKeySource(tampered).deriveUnlockKey();
    await expect(attempt).rejects.toBeInstanceOf(VaultCryptoError);
    await expect(attempt).rejects.toMatchObject({ code: 'invalid-recovery-code' });
  });

  it('rejects words not in the wordlist and codes of the wrong length', async () => {
    const words = await generateRecoveryCode();
    const unknown = [...words];
    unknown[0] = 'klarsend';
    await expect(new RecoveryCodeUnlockKeySource(unknown).deriveUnlockKey()).rejects.toMatchObject({
      code: 'invalid-recovery-code',
    });
    await expect(new RecoveryCodeUnlockKeySource(words.slice(0, 23)).deriveUnlockKey()).rejects.toMatchObject({
      code: 'invalid-recovery-code',
    });
  });
});

describe('nonce discipline (§2.1: fresh random nonce per encryption)', () => {
  it('200 encryptions of the same plaintext yield 200 unique nonces and ciphertexts', async () => {
    const vk = await generateVaultKey();
    const payloads: EncryptedPayload[] = [];
    for (let i = 0; i < 200; i++) {
      payloads.push(await encryptEntry(vk, SAMPLE_ENTRY));
    }

    const nonces = new Set(payloads.map((p) => toHex(p.nonce)));
    const ciphertexts = new Set(payloads.map((p) => toHex(p.ciphertext)));
    expect(nonces.size).toBe(200);
    expect(ciphertexts.size).toBe(200);
    for (const p of payloads) {
      expect(p.nonce.length).toBe(12); // 96-bit GCM nonce
    }
    // spot-check they all still decrypt
    expect(toHex(await decryptEntry(vk, payloads[0]))).toBe(toHex(SAMPLE_ENTRY));
    expect(toHex(await decryptEntry(vk, payloads[199]))).toBe(toHex(SAMPLE_ENTRY));
  });
});

describe('tamper rejection (GCM authentication)', () => {
  async function encryptedFixture() {
    const vk = await generateVaultKey();
    const payload = await encryptEntry(vk, SAMPLE_ENTRY);
    return { vk, payload };
  }

  it('flipped ciphertext byte → decrypt-failed', async () => {
    const { vk, payload } = await encryptedFixture();
    const tampered = { ...payload, ciphertext: payload.ciphertext.slice() };
    tampered.ciphertext[0] ^= 0x01;
    await expect(decryptEntry(vk, tampered)).rejects.toMatchObject({ code: 'decrypt-failed' });
  });

  it('flipped auth-tag byte → decrypt-failed', async () => {
    const { vk, payload } = await encryptedFixture();
    const tampered = { ...payload, ciphertext: payload.ciphertext.slice() };
    tampered.ciphertext[tampered.ciphertext.length - 1] ^= 0x80; // tag is the trailing 16 bytes
    await expect(decryptEntry(vk, tampered)).rejects.toMatchObject({ code: 'decrypt-failed' });
  });

  it('flipped nonce byte → decrypt-failed', async () => {
    const { vk, payload } = await encryptedFixture();
    const tampered = { ...payload, nonce: payload.nonce.slice() };
    tampered.nonce[5] ^= 0xff;
    await expect(decryptEntry(vk, tampered)).rejects.toMatchObject({ code: 'decrypt-failed' });
  });

  it('truncated ciphertext → decrypt-failed', async () => {
    const { vk, payload } = await encryptedFixture();
    const tampered = { ...payload, ciphertext: payload.ciphertext.slice(0, payload.ciphertext.length - 1) };
    await expect(decryptEntry(vk, tampered)).rejects.toMatchObject({ code: 'decrypt-failed' });
  });

  it('tampered wrapped vault key → unwrap-failed', async () => {
    const uk = await new PassphraseUnlockKeySource('pw', lightKdf()).deriveUnlockKey();
    const wrapped = await wrapVaultKey(await generateVaultKey(), uk);
    const tampered = { ...wrapped, ciphertext: wrapped.ciphertext.slice() };
    tampered.ciphertext[10] ^= 0x10;
    await expect(unwrapVaultKey(tampered, uk)).rejects.toMatchObject({ code: 'unwrap-failed' });
  });
});

describe('unlock key source parity (PRF and passphrase are interchangeable UK producers)', () => {
  it('every source kind produces a UK that drives the same wrap/unwrap API', async () => {
    const words = await generateRecoveryCode();
    const sources: UnlockKeySource[] = [
      new PassphraseUnlockKeySource('a passphrase', lightKdf()),
      new PrfUnlockKeySource(async () => new Uint8Array(32).fill(42)),
      new RecoveryCodeUnlockKeySource(words),
    ];
    expect(sources.map((s) => s.kind)).toEqual(['passphrase', 'passkey-prf', 'recovery-code']);

    for (const source of sources) {
      const vk = await generateVaultKey();
      const wrapped = await wrapVaultKey(vk, await source.deriveUnlockKey());
      // a fresh derivation from the same source material must unwrap
      const again = await source.deriveUnlockKey();
      const unlocked = await unwrapVaultKey(wrapped, again);
      const blob = await encryptEntry(unlocked, SAMPLE_ENTRY);
      expect(toHex(await decryptEntry(unlocked, blob))).toBe(toHex(SAMPLE_ENTRY));
    }
  });

  it('PRF derivation is deterministic for identical PRF output', async () => {
    const prf = Uint8Array.from({ length: 32 }, (_, i) => i * 3);
    const uk1 = await new PrfUnlockKeySource(async () => prf.slice()).deriveUnlockKey();
    const uk2 = await new PrfUnlockKeySource(async () => prf.slice()).deriveUnlockKey();
    const wrapped = await wrapVaultKey(await generateVaultKey(), uk1);
    await expect(unwrapVaultKey(wrapped, uk2)).resolves.toBeDefined();
  });
});

describe('signup helper: no extractable VK handle outlives signup', () => {
  it('createVault returns both wraps and a non-extractable session VK that rejects exportKey', async () => {
    const uk = await new PassphraseUnlockKeySource('pw', lightKdf()).deriveUnlockKey();
    const recoveryUk = await new RecoveryCodeUnlockKeySource(await generateRecoveryCode()).deriveUnlockKey();

    const { sessionVaultKey, wrappedVaultKey, recoveryWrappedVaultKey } = await createVault(uk, recoveryUk);

    expect(sessionVaultKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', sessionVaultKey)).rejects.toThrow();

    // both wrapped forms open the same vault the session key writes to
    const blob = await encryptEntry(sessionVaultKey, SAMPLE_ENTRY);
    const viaPassphrase = await unwrapVaultKey(wrappedVaultKey, uk);
    expect(toHex(await decryptEntry(viaPassphrase, blob))).toBe(toHex(SAMPLE_ENTRY));
    const viaRecovery = await unwrapVaultKey(recoveryWrappedVaultKey, recoveryUk);
    expect(toHex(await decryptEntry(viaRecovery, blob))).toBe(toHex(SAMPLE_ENTRY));
  });
});

describe('recovery lookup key (slice 24 — account recovery)', () => {
  // Vectors generated with an independent HKDF implementation (node:crypto
  // hkdfSync), pinning the derivation AND the parameter mapping:
  //   L = HKDF-SHA256(ikm = recovery entropy, salt = "klarsend/v1/recovery-lookup",
  //                   info = "lookup-key", len = 32)
  const ZERO_ENTROPY = new Uint8Array(32);
  const COUNTING_ENTROPY = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const ZERO_L_HEX = '83e9fbee261d2462dc758b8babbac8657ff71281cdfbc06351d05c5130a24731';
  const COUNTING_L_HEX = 'fb1b534cde52a5b1f5f77b02858cf6584bac4dccb3893f2f97c58b7cd33bbd04';
  const ZERO_L_SHA256_HEX = '41e61224c6190688b6bd614878a7a0cb0aec2b70d7e000851b458a13a8d8d7f5';
  // Raw output of the SIBLING branch (salt "klarsend/v1/recovery", info
  // "unlock-key") for the same all-zero entropy — must differ from L.
  const ZERO_UK_BRANCH_HEX = 'dc3786c960d29002e57a0153d3093dc02e0dee1cf2ab4a91f818b40173f445ea';

  it('known-answer vectors: entropy → L', async () => {
    expect(toHex(await deriveLookupKeyFromEntropy(ZERO_ENTROPY.slice()))).toBe(ZERO_L_HEX);
    expect(toHex(await deriveLookupKeyFromEntropy(COUNTING_ENTROPY.slice()))).toBe(COUNTING_L_HEX);
  });

  it('known-answer vector: enrollment hash = SHA-256(L)', async () => {
    const L = await deriveLookupKeyFromEntropy(ZERO_ENTROPY.slice());
    expect(toHex(await hashLookupKey(L))).toBe(ZERO_L_SHA256_HEX);
  });

  it('words path ties BIP39 decode to the derivation (abandon×23 + art → all-zero entropy L)', async () => {
    const words = [...Array(23).fill('abandon'), 'art'];
    expect(toHex(await lookupKeyFromRecoveryCode(words))).toBe(ZERO_L_HEX);
  });

  it('domain separation: L is unrelated to the unlock-key branch of the same entropy', async () => {
    // Derive the sibling branch raw (test-only; production UKs are non-extractable)
    // and pin it, proving the two HKDF contexts diverge on identical entropy.
    const ikm = await crypto.subtle.importKey('raw', ZERO_ENTROPY, 'HKDF', false, ['deriveBits']);
    const ukBits = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: utf8Encode('klarsend/v1/recovery'),
          info: utf8Encode('unlock-key'),
        },
        ikm,
        256,
      ),
    );
    expect(toHex(ukBits)).toBe(ZERO_UK_BRANCH_HEX);
    expect(ZERO_UK_BRANCH_HEX).not.toBe(ZERO_L_HEX);
  });

  it('the pinned unlock-key branch bytes ARE what RecoveryCodeUnlockKeySource derives', async () => {
    // The UK is non-extractable, so prove byte-equality behaviorally: a key
    // imported from the pinned hex must unwrap what the derived UK wrapped.
    const words = [...Array(23).fill('abandon'), 'art'];
    const derivedUk = await new RecoveryCodeUnlockKeySource(words).deriveUnlockKey();
    const wrapped = await wrapVaultKey(await generateVaultKey(), derivedUk);

    const pinnedUk = await crypto.subtle.importKey('raw', fromHex(ZERO_UK_BRANCH_HEX), { name: 'AES-GCM' }, false, [
      'wrapKey',
      'unwrapKey',
    ]);
    await expect(unwrapVaultKey(wrapped, pinnedUk)).resolves.toBeDefined();
  });

  it('rejects invalid words with the slice-1 BIP39 error paths (no derivation happens)', async () => {
    const words = await generateRecoveryCode();
    const tampered = [...words];
    tampered[7] = tampered[7] === 'abandon' ? 'ability' : 'abandon';
    await expect(lookupKeyFromRecoveryCode(tampered)).rejects.toMatchObject({ code: 'invalid-recovery-code' });
    await expect(lookupKeyFromRecoveryCode(words.slice(0, 23))).rejects.toMatchObject({
      code: 'invalid-recovery-code',
    });
  });

  it('same words → same L; different words → different L (deterministic, collision-free in practice)', async () => {
    const a = await generateRecoveryCode();
    const b = await generateRecoveryCode();
    expect(toHex(await lookupKeyFromRecoveryCode([...a]))).toBe(toHex(await lookupKeyFromRecoveryCode([...a])));
    expect(toHex(await lookupKeyFromRecoveryCode(a))).not.toBe(toHex(await lookupKeyFromRecoveryCode(b)));
  });
});

describe('rewrapVault (slice 24 — the recovery/credential-change twin of createVault)', () => {
  async function establishedVault() {
    const oldUk = await new PassphraseUnlockKeySource('old pw', lightKdf()).deriveUnlockKey();
    const oldWords = await generateRecoveryCode();
    const oldRecoveryUk = await new RecoveryCodeUnlockKeySource(oldWords).deriveUnlockKey();
    const vault = await createVault(oldUk, oldRecoveryUk);
    const blob = await encryptEntry(vault.sessionVaultKey, SAMPLE_ENTRY);
    return { oldUk, oldRecoveryUk, oldWords, vault, blob };
  }

  it('round-trip: recovery rewrap preserves the VK — both new wraps open the existing vault', async () => {
    const { oldRecoveryUk, vault, blob } = await establishedVault();

    const newUk = await new PassphraseUnlockKeySource('new pw', lightKdf()).deriveUnlockKey();
    const newRecoveryUk = await new RecoveryCodeUnlockKeySource(await generateRecoveryCode()).deriveUnlockKey();
    const rewrapped = await rewrapVault(vault.recoveryWrappedVaultKey, oldRecoveryUk, newUk, newRecoveryUk);

    // the session key handed back decrypts pre-existing data
    expect(toHex(await decryptEntry(rewrapped.sessionVaultKey, blob))).toBe(toHex(SAMPLE_ENTRY));
    // and both new wraps unwrap to the same VK
    const viaNewUk = await unwrapVaultKey(rewrapped.wrappedVaultKey, newUk);
    expect(toHex(await decryptEntry(viaNewUk, blob))).toBe(toHex(SAMPLE_ENTRY));
    const viaNewRecovery = await unwrapVaultKey(rewrapped.recoveryWrappedVaultKey, newRecoveryUk);
    expect(toHex(await decryptEntry(viaNewRecovery, blob))).toBe(toHex(SAMPLE_ENTRY));
  });

  it('no extractable VK handle outlives the rewrap (createVault discipline)', async () => {
    const { oldRecoveryUk, vault } = await establishedVault();
    const newUk = await new PassphraseUnlockKeySource('new pw', lightKdf()).deriveUnlockKey();
    const newRecoveryUk = await new RecoveryCodeUnlockKeySource(await generateRecoveryCode()).deriveUnlockKey();
    const rewrapped = await rewrapVault(vault.recoveryWrappedVaultKey, oldRecoveryUk, newUk, newRecoveryUk);

    expect(rewrapped.sessionVaultKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', rewrapped.sessionVaultKey)).rejects.toThrow();
  });

  it('wrong old unlock key → unwrap-failed, nothing produced', async () => {
    const { vault } = await establishedVault();
    const wrongUk = await new RecoveryCodeUnlockKeySource(await generateRecoveryCode()).deriveUnlockKey();
    const newUk = await new PassphraseUnlockKeySource('new pw', lightKdf()).deriveUnlockKey();
    await expect(rewrapVault(vault.recoveryWrappedVaultKey, wrongUk, newUk, newUk)).rejects.toMatchObject({
      code: 'unwrap-failed',
    });
  });

  it('rewrap does not mutate its inputs: the OLD wraps still work afterwards (lockout safety)', async () => {
    const { oldUk, oldRecoveryUk, vault, blob } = await establishedVault();
    const newUk = await new PassphraseUnlockKeySource('new pw', lightKdf()).deriveUnlockKey();
    const newRecoveryUk = await new RecoveryCodeUnlockKeySource(await generateRecoveryCode()).deriveUnlockKey();
    await rewrapVault(vault.recoveryWrappedVaultKey, oldRecoveryUk, newUk, newRecoveryUk);

    const viaOldUk = await unwrapVaultKey(vault.wrappedVaultKey, oldUk);
    expect(toHex(await decryptEntry(viaOldUk, blob))).toBe(toHex(SAMPLE_ENTRY));
    const viaOldRecovery = await unwrapVaultKey(vault.recoveryWrappedVaultKey, oldRecoveryUk);
    expect(toHex(await decryptEntry(viaOldRecovery, blob))).toBe(toHex(SAMPLE_ENTRY));
  });
});

describe('wire serialization (sync API shapes)', () => {
  it('wrapped key, vault blob, and kdf config survive their JSON wire shapes', async () => {
    const kdf = generateKdfConfig(LIGHT_PARAMS);
    const uk = await new PassphraseUnlockKeySource('pw', kdf).deriveUnlockKey();
    const { sessionVaultKey, wrappedVaultKey } = await createVault(uk, uk);
    const blob = await encryptEntry(sessionVaultKey, SAMPLE_ENTRY);

    const wireWrapped: SerializedWrappedKey = JSON.parse(JSON.stringify(serializeWrappedKey(wrappedVaultKey)));
    const wireBlob: SerializedVaultBlob = JSON.parse(JSON.stringify(serializeVaultBlob(blob, 1)));
    const wireKdf = JSON.parse(JSON.stringify(serializeKdfConfig(kdf)));

    // every field is a JSON-native scalar (base64 strings / numbers), no byte arrays
    expect(typeof wireWrapped.ciphertext).toBe('string');
    expect(typeof wireWrapped.nonce).toBe('string');
    expect(typeof wireBlob.ciphertext).toBe('string');
    expect(wireBlob.version).toBe(1);
    expect(typeof wireKdf.salt).toBe('string');

    const vk = await unwrapVaultKey(deserializeWrappedKey(wireWrapped), uk);
    const { payload, version } = deserializeVaultBlob(wireBlob);
    expect(version).toBe(1);
    expect(toHex(await decryptEntry(vk, payload))).toBe(toHex(SAMPLE_ENTRY));

    const kdfBack = deserializeKdfConfig(wireKdf);
    expect(toHex(kdfBack.salt)).toBe(toHex(kdf.salt));
    expect(kdfBack.params).toEqual(kdf.params);
  });

  it('device B: a completely fresh module instance opens what device A serialized', async () => {
    const passphrase = 'correct horse battery staple';

    // ── device A: signup + one encrypted vault write, everything to wire JSON
    const kdf = generateKdfConfig(LIGHT_PARAMS);
    const ukA = await new PassphraseUnlockKeySource(passphrase, kdf).deriveUnlockKey();
    const recoveryWords = await generateRecoveryCode();
    const recoveryUkA = await new RecoveryCodeUnlockKeySource(recoveryWords).deriveUnlockKey();
    const { sessionVaultKey, wrappedVaultKey, recoveryWrappedVaultKey } = await createVault(ukA, recoveryUkA);
    const blob = await encryptEntry(sessionVaultKey, SAMPLE_ENTRY);

    const wire = JSON.stringify({
      kdf: serializeKdfConfig(kdf),
      wrappedVaultKey: serializeWrappedKey(wrappedVaultKey),
      recoveryWrappedVaultKey: serializeWrappedKey(recoveryWrappedVaultKey),
      vaultBlob: serializeVaultBlob(blob, 1),
    });

    // ── device B: a fresh module registry — nothing shared with device A's imports
    vi.resetModules();
    const fresh = await import('./index');

    const stored = JSON.parse(wire);
    const kdfB = fresh.deserializeKdfConfig(stored.kdf);
    const ukB = await new fresh.PassphraseUnlockKeySource(passphrase, kdfB).deriveUnlockKey();
    const vkB = await fresh.unwrapVaultKey(fresh.deserializeWrappedKey(stored.wrappedVaultKey), ukB);
    const { payload } = fresh.deserializeVaultBlob(stored.vaultBlob);
    expect(toHex(await fresh.decryptEntry(vkB, payload))).toBe(toHex(SAMPLE_ENTRY));

    // recovery wrap also crosses the wire intact
    const recoveryUkB = await new fresh.RecoveryCodeUnlockKeySource(recoveryWords).deriveUnlockKey();
    const vkViaRecovery = await fresh.unwrapVaultKey(
      fresh.deserializeWrappedKey(stored.recoveryWrappedVaultKey),
      recoveryUkB,
    );
    expect(toHex(await fresh.decryptEntry(vkViaRecovery, payload))).toBe(toHex(SAMPLE_ENTRY));
  });
});
