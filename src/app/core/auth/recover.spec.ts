/**
 * Account-recovery flow tests (slice 24). Cover the frozen ordering (local
 * BIP39 validation → probe → slow new-code ceremony OUTSIDE the challenge
 * window → enrollment → atomic commit), both credential outcomes, the abort
 * paths that leave the account untouched, and the zero-knowledge canary: the
 * words (old and new) and every secret derivative stay off the wire in any
 * encoding, with the two DECLARED exceptions (old L in recoverOptions bodies,
 * SHA-256 of new L in the commit) pinned exactly.
 */
import { describe, expect, it } from 'vitest';

import {
  PassphraseUnlockKeySource,
  PrfUnlockKeySource,
  RecoveryCodeUnlockKeySource,
  createVault,
  decryptEntry,
  deserializeKdfConfig,
  deserializeWrappedKey,
  encryptEntry,
  entropyFromRecoveryCode,
  generateRecoveryCode,
  hashLookupKey,
  lookupKeyFromRecoveryCode,
  serializeWrappedKey,
  toBase64,
  unwrapVaultKey,
} from '../vault-crypto';
import { toHex, utf8Decode, utf8Encode } from '../vault-crypto/encoding';
import { recover } from './recover';
import type {
  AuthApi,
  AuthenticationResult,
  RecoverRequestBody,
  RegistrationResult,
  WebAuthnClient,
} from './wire';

const PRF_OUTPUT = Uint8Array.from({ length: 32 }, (_, i) => 100 + i);

function registrationResult(prf?: { enabled: boolean; first?: ArrayBuffer }): RegistrationResult {
  return {
    id: 'bmV3LWNyZWQ',
    rawId: 'bmV3LWNyZWQ',
    type: 'public-key',
    response: { attestationObject: 'b64url-attobj', clientDataJSON: 'b64url-cdj' },
    clientExtensionResults: prf
      ? { prf: { enabled: prf.enabled, ...(prf.first ? { results: { first: prf.first } } : {}) } }
      : {},
  } as RegistrationResult;
}

function assertionResult(prfFirst?: ArrayBuffer): AuthenticationResult {
  return {
    id: 'bmV3LWNyZWQ',
    rawId: 'bmV3LWNyZWQ',
    type: 'public-key',
    response: { authenticatorData: 'ad', clientDataJSON: 'cdj', signature: 'sig' },
    clientExtensionResults: prfFirst ? { prf: { results: { first: prfFirst } } } : {},
  } as AuthenticationResult;
}

/** An established account: signup-time words, VK, recovery wrap, and one vault blob. */
async function establishedAccount() {
  const oldWords = await generateRecoveryCode();
  const oldRecoveryUk = await new RecoveryCodeUnlockKeySource(oldWords).deriveUnlockKey();
  const vault = await createVault(oldRecoveryUk, oldRecoveryUk);
  const blob = await encryptEntry(vault.sessionVaultKey, utf8Encode('vault-contents'));
  return { oldWords, recoveryWrappedVaultKey: vault.recoveryWrappedVaultKey, blob };
}

interface Harness {
  api: AuthApi;
  webauthn: WebAuthnClient;
  events: string[];
  optionsLookupKeys: string[];
  recoverBodies: RecoverRequestBody[];
  newCodes: string[][];
}

function harness(config: {
  registration: RegistrationResult;
  assertion?: AuthenticationResult;
  recoveryWrappedVaultKey: Awaited<ReturnType<typeof establishedAccount>>['recoveryWrappedVaultKey'];
  failOptions?: boolean;
}): Harness {
  const events: string[] = [];
  const optionsLookupKeys: string[] = [];
  const recoverBodies: RecoverRequestBody[] = [];
  const newCodes: string[][] = [];
  let challengeCounter = 0;

  const api: AuthApi = {
    registerOptions: async () => {
      throw new Error('registerOptions must not be called during recovery');
    },
    register: async () => {
      throw new Error('register must not be called during recovery');
    },
    loginOptions: async () => {
      throw new Error('loginOptions must not be called during recovery');
    },
    login: async () => {
      throw new Error('login must not be called during recovery');
    },
    recoverOptions: async (lookupKey) => {
      events.push('recoverOptions');
      optionsLookupKeys.push(lookupKey);
      if (config.failOptions) throw new Error('recovery failed');
      challengeCounter++;
      return {
        challengeId: `chal-${challengeCounter}`,
        recoveryWrappedVaultKey: serializeWrappedKey(config.recoveryWrappedVaultKey),
        options: { challenge: 'cmVjb3Zlci1jaGFsbGVuZ2U', rp: { id: 'localhost', name: 'Klarsend' } },
      };
    },
    recover: async (body) => {
      events.push('recover');
      recoverBodies.push(body);
      return { userId: 'user-1', accessToken: 'jwt', expiresInSeconds: 900 };
    },
    enrollRecoveryLookup: async () => {
      throw new Error('enrollRecoveryLookup must not be called during recovery');
    },
  };

  const webauthn: WebAuthnClient = {
    startRegistration: async () => {
      events.push('startRegistration');
      return config.registration;
    },
    startAuthentication: async () => {
      events.push('startAuthentication');
      if (!config.assertion) throw new Error('assertion not configured');
      return config.assertion;
    },
  };

  return { api, webauthn, events, optionsLookupKeys, recoverBodies, newCodes };
}

function callbacks(h: Harness, passphrase?: string) {
  return {
    confirmRecoveryCode: async (words: string[]) => {
      h.events.push('confirmRecoveryCode');
      h.newCodes.push(words);
    },
    getPassphrase: async () => {
      h.events.push('getPassphrase');
      if (passphrase === undefined) throw new Error('passphrase requested unexpectedly');
      return passphrase;
    },
  };
}

describe('recover: PRF-capable new authenticator', () => {
  it('full ceremony: new wraps open the SAME vault, new code works, old code fails against the new wrap', async () => {
    const account = await establishedAccount();
    const h = harness({
      registration: registrationResult({ enabled: true, first: PRF_OUTPUT.slice().buffer }),
      recoveryWrappedVaultKey: account.recoveryWrappedVaultKey,
    });

    const result = await recover(
      { api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) },
      { words: account.oldWords },
    );

    expect(result.unlockMethod).toBe('passkey-prf');
    expect(result.userId).toBe('user-1');
    // the session key handed back opens the pre-existing vault
    expect(utf8Decode(await decryptEntry(result.sessionVaultKey, account.blob))).toBe('vault-contents');

    const body = h.recoverBodies[0];
    expect(body.kdf).toBeNull();

    // committed wrap opens under the new PRF output → same vault contents
    const prfUk = await new PrfUnlockKeySource(async () => PRF_OUTPUT.slice()).deriveUnlockKey();
    const vkViaPasskey = await unwrapVaultKey(deserializeWrappedKey(body.wrappedVaultKey), prfUk);
    expect(utf8Decode(await decryptEntry(vkViaPasskey, account.blob))).toBe('vault-contents');

    // committed recovery wrap opens under the NEW code shown to the user
    const newUk = await new RecoveryCodeUnlockKeySource(h.newCodes[0]).deriveUnlockKey();
    const vkViaNewCode = await unwrapVaultKey(deserializeWrappedKey(body.recoveryWrappedVaultKey), newUk);
    expect(utf8Decode(await decryptEntry(vkViaNewCode, account.blob))).toBe('vault-contents');

    // burn semantics client-side: the OLD code cannot open the NEW recovery wrap
    const oldUk = await new RecoveryCodeUnlockKeySource(account.oldWords).deriveUnlockKey();
    await expect(
      unwrapVaultKey(deserializeWrappedKey(body.recoveryWrappedVaultKey), oldUk),
    ).rejects.toMatchObject({ code: 'unwrap-failed' });

    // the commit's hash is the NEW code's (enrolls the new L for its future redemption)
    const newLookupKey = await lookupKeyFromRecoveryCode(h.newCodes[0]);
    expect(body.recoveryLookupHash).toBe(toBase64(await hashLookupKey(newLookupKey)));
  });
});

describe('recover: passphrase fallback (no PRF)', () => {
  it('prompts for a NEW passphrase, posts a FRESH argon2id config, wrap opens under it', async () => {
    const account = await establishedAccount();
    const h = harness({
      registration: registrationResult(),
      recoveryWrappedVaultKey: account.recoveryWrappedVaultKey,
    });

    const result = await recover(
      { api: h.api, webauthn: h.webauthn, callbacks: callbacks(h, 'a brand new passphrase') },
      { words: account.oldWords },
    );

    expect(result.unlockMethod).toBe('passphrase');
    expect(h.events).toContain('getPassphrase');

    const body = h.recoverBodies[0];
    expect(body.kdf).not.toBeNull();
    expect(body.kdf!.algorithm).toBe('argon2id');

    const uk = await new PassphraseUnlockKeySource(
      'a brand new passphrase',
      deserializeKdfConfig(body.kdf!),
    ).deriveUnlockKey();
    const vk = await unwrapVaultKey(deserializeWrappedKey(body.wrappedVaultKey), uk);
    expect(utf8Decode(await decryptEntry(vk, account.blob))).toBe('vault-contents');
  });
});

describe('recover: frozen ordering', () => {
  it('probe → confirm (slow, outside window) → second options → ceremony → commit', async () => {
    const account = await establishedAccount();
    const h = harness({
      registration: registrationResult({ enabled: true, first: PRF_OUTPUT.slice().buffer }),
      recoveryWrappedVaultKey: account.recoveryWrappedVaultKey,
    });

    await recover({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }, { words: account.oldWords });

    // exactly two options calls: the validating probe, then the challenge fetch
    expect(h.events.filter((e) => e === 'recoverOptions')).toHaveLength(2);
    const [probeAt, optionsAt] = h.events
      .map((e, i) => (e === 'recoverOptions' ? i : -1))
      .filter((i) => i >= 0);
    const confirmAt = h.events.indexOf('confirmRecoveryCode');
    const ceremonyAt = h.events.indexOf('startRegistration');
    const commitAt = h.events.indexOf('recover');

    expect(probeAt).toBeLessThan(confirmAt); // fail fast: claim validated before the slow step
    expect(confirmAt).toBeLessThan(optionsAt); // slow step fully outside the challenge window
    expect(optionsAt).toBeLessThan(ceremonyAt);
    expect(ceremonyAt).toBeLessThan(commitAt);

    // the commit rides the SECOND challenge (the probe's is abandoned to the TTL)
    expect(h.recoverBodies[0].challengeId).toBe('chal-2');
  });

  it('a slow confirmation never overlaps the challenge fetch', async () => {
    const account = await establishedAccount();
    const h = harness({
      registration: registrationResult({ enabled: true, first: PRF_OUTPUT.slice().buffer }),
      recoveryWrappedVaultKey: account.recoveryWrappedVaultKey,
    });
    let optionsCallsDuringConfirm = 0;
    const slow = {
      confirmRecoveryCode: async (words: string[]) => {
        await new Promise((r) => setTimeout(r, 20));
        optionsCallsDuringConfirm = h.events.filter((e) => e === 'recoverOptions').length;
        h.events.push('confirmRecoveryCode');
        h.newCodes.push(words);
      },
      getPassphrase: async () => 'unused',
    };

    await recover({ api: h.api, webauthn: h.webauthn, callbacks: slow }, { words: account.oldWords });

    expect(optionsCallsDuringConfirm).toBe(1); // only the probe existed while the user transcribed
  });

  it('burn-before-commit: the new code is confirmed before anything can invalidate the old one', async () => {
    const account = await establishedAccount();
    const h = harness({
      registration: registrationResult({ enabled: true, first: PRF_OUTPUT.slice().buffer }),
      recoveryWrappedVaultKey: account.recoveryWrappedVaultKey,
    });

    await recover({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }, { words: account.oldWords });

    expect(h.events.indexOf('confirmRecoveryCode')).toBeLessThan(h.events.indexOf('recover'));
    expect(h.newCodes[0]).toHaveLength(24);
    expect(h.newCodes[0].join(' ')).not.toBe(account.oldWords.join(' '));
  });
});

describe('recover: abort paths leave the account untouched', () => {
  it('invalid words (checksum) die locally: NO network call of any kind', async () => {
    const account = await establishedAccount();
    const h = harness({
      registration: registrationResult(),
      recoveryWrappedVaultKey: account.recoveryWrappedVaultKey,
    });
    const tampered = [...account.oldWords];
    tampered[3] = tampered[3] === 'abandon' ? 'ability' : 'abandon';

    await expect(
      recover({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }, { words: tampered }),
    ).rejects.toMatchObject({ code: 'invalid-recovery-code' });

    expect(h.events).toHaveLength(0);
  });

  it('unknown/burned code: the probe fails generically BEFORE the user transcribes a new code', async () => {
    const account = await establishedAccount();
    const h = harness({
      registration: registrationResult(),
      recoveryWrappedVaultKey: account.recoveryWrappedVaultKey,
      failOptions: true,
    });
    const strangerWords = await generateRecoveryCode();

    await expect(
      recover({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }, { words: strangerWords }),
    ).rejects.toThrow('recovery failed');

    expect(h.events).not.toContain('confirmRecoveryCode');
    expect(h.events).not.toContain('startRegistration');
    expect(h.recoverBodies).toHaveLength(0);
  });

  it('user abandons the new-code confirm: nothing was committed, no ceremony ran', async () => {
    const account = await establishedAccount();
    const h = harness({
      registration: registrationResult(),
      recoveryWrappedVaultKey: account.recoveryWrappedVaultKey,
    });
    const aborting = {
      confirmRecoveryCode: async () => {
        throw new Error('user cancelled');
      },
      getPassphrase: async () => 'pw',
    };

    await expect(
      recover({ api: h.api, webauthn: h.webauthn, callbacks: aborting }, { words: account.oldWords }),
    ).rejects.toThrow('user cancelled');

    expect(h.events).not.toContain('startRegistration');
    expect(h.recoverBodies).toHaveLength(0); // the account's material was never replaced
  });
});

describe('SECURITY canary: recovery wire accounting (CLAUDE.md invariants 1–2)', () => {
  // Non-vacuity for the word scan itself. The canary above draws RANDOM codes, so the
  // collision that broke it (a BIP39 word that is also one of our JSON keys) only
  // surfaces ~4.6% of runs — which is exactly how it survived slice 24, went red on
  // main during slice 27, and looked like a leak. These cases are deterministic: they
  // pin both directions on the two words that actually collide, so the fix cannot be
  // "simplified" back into a 1-in-22 false alarm.
  it('the word scan ignores JSON KEYS but still catches a word in VALUE position', () => {
    const realPayloadShape =
      '{"attestationResponse":{"type":"public-key","response":{"clientDataJSON":"x"}}}';
    const scan = (word: string) => new RegExp(`"${word}"(?!\s*:)`);

    // "type" and "response" are BIP39 words AND keys in the WebAuthn payload. As keys
    // they are our own schema — never a leak.
    for (const collidingWord of ['type', 'response']) {
      expect(realPayloadShape).not.toMatch(scan(collidingWord));
    }

    // The same words in value position ARE a leak, and must still fail.
    for (const word of ['type', 'response', 'abandon']) {
      expect(`{"words":"${word}"}`).toMatch(scan(word));
      expect(`{"a":["${word}"]}`).toMatch(scan(word));
    }
  });

  it('words, entropy, and unlock-key material appear on the wire in NO encoding; the two declared exceptions are exact', async () => {
    const account = await establishedAccount();
    const h = harness({
      registration: registrationResult({ enabled: true, first: PRF_OUTPUT.slice().buffer }),
      recoveryWrappedVaultKey: account.recoveryWrappedVaultKey,
    });

    await recover({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }, { words: account.oldWords });

    // Everything that crossed the wire, serialized:
    const wire = JSON.stringify({ options: h.optionsLookupKeys, commits: h.recoverBodies });

    // 1) no word of EITHER code appears as text — in a VALUE position.
    //
    // The `(?!\s*:)` is load-bearing, and this is why: a quoted token followed by a
    // colon is a JSON KEY, i.e. one of OUR OWN field names, fixed by our DTOs at
    // compile time. It can never be a user's recovery word. A quoted token anywhere
    // else is a VALUE — and a word there IS a leak.
    //
    // Without the lookahead this canary fails ~4.6% of the time on nothing at all:
    // BIP39's wordlist contains "type" and "response", and the WebAuthn attestation
    // payload has `"type"` and `"response"` as keys. When a randomly generated code
    // happens to include either word — 48 words drawn per run, two colliding keys —
    // the canary reports a leak that did not happen. It cost a red CI on main and an
    // hour of looking for a breach that was our own schema.
    //
    // The claim is UNWEAKENED: a word in value position is still a hard failure. The
    // honest limit is that a word used as an object KEY would now be invisible — which
    // would require building an object keyed by user data, something no code here does
    // and nothing plausibly would.
    for (const word of [...account.oldWords, ...h.newCodes[0]]) {
      expect(wire).not.toMatch(new RegExp(`"${word}"(?!\s*:)`));
    }
    expect(wire).not.toContain(account.oldWords.join(' '));
    expect(wire).not.toContain(h.newCodes[0].join(' '));

    // 2) neither code's raw ENTROPY appears in hex or base64
    const oldEntropy = await entropyFromRecoveryCode(account.oldWords);
    const newEntropy = await entropyFromRecoveryCode(h.newCodes[0]);
    for (const entropy of [oldEntropy, newEntropy]) {
      expect(wire).not.toContain(toHex(entropy).slice(4, 28));
      expect(wire).not.toContain(toBase64(entropy).slice(4, 28));
    }

    // 3) the NEW code's lookup key never travels — only its SHA-256 does
    const newLookupKey = await lookupKeyFromRecoveryCode(h.newCodes[0]);
    expect(wire).not.toContain(toBase64(newLookupKey).slice(4, 28));
    expect(h.recoverBodies[0].recoveryLookupHash).toBe(toBase64(await hashLookupKey(newLookupKey)));

    // 4) the OLD code's L appears EXACTLY where declared: the two options
    //    requests — the endpoint whose ceremony burns it — and nowhere else
    const oldLookupKey = toBase64(await lookupKeyFromRecoveryCode(account.oldWords));
    expect(h.optionsLookupKeys).toEqual([oldLookupKey, oldLookupKey]);
    expect(JSON.stringify(h.recoverBodies)).not.toContain(oldLookupKey.slice(4, 28));

    // 5) the PRF output (new unlock-key seed) stays off the wire, as at signup
    expect(wire).not.toContain(toBase64(PRF_OUTPUT).slice(4, 28));
    expect(wire).not.toContain('results');
  });

  it('sanity: the scan would CATCH a planted leak', async () => {
    const words = await generateRecoveryCode();
    const planted = JSON.stringify({ note: `leak ${words.join(' ')}` });
    expect(planted).toContain(`${words[0]} ${words[1]}`);
    // and an entropy leak in base64 would be caught by the same slice check
    const entropy = await entropyFromRecoveryCode(words);
    const plantedB64 = JSON.stringify({ blob: toBase64(entropy) });
    expect(plantedB64).toContain(toBase64(entropy).slice(4, 28));
  });
});
