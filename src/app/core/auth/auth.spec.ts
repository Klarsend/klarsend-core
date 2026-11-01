/**
 * Client auth-core tests — written before the implementation. Cover PRF-vs-
 * passphrase unlock source selection, the signup wiring into vault-crypto
 * (spec §2.1), the exact register POST body, and login vault unlock.
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
  generateKdfConfig,
  hashLookupKey,
  lookupKeyFromRecoveryCode,
  serializeKdfConfig,
  serializeWrappedKey,
  toBase64,
  unwrapVaultKey,
} from '../vault-crypto';
import { utf8Decode, utf8Encode } from '../vault-crypto/encoding';
import { fromBase64Url, toBase64Url } from './base64url';
import { login } from './login';
import { prfEvalInput } from './prf';
import { signup } from './signup';
import { CURRENT_TERMS_VERSION } from '../legal';
import type {
  AuthApi,
  AuthenticationResult,
  LoginRequestBody,
  LoginResponseBody,
  RegisterRequestBody,
  RegistrationResult,
  WebAuthnClient,
} from './wire';

const PRF_OUTPUT = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);

function registrationResult(prf?: { enabled: boolean; first?: ArrayBuffer }): RegistrationResult {
  return {
    id: 'Y3JlZC1pZA',
    rawId: 'Y3JlZC1pZA',
    type: 'public-key',
    response: { attestationObject: 'b64url-attobj', clientDataJSON: 'b64url-cdj' },
    clientExtensionResults: prf
      ? { prf: { enabled: prf.enabled, ...(prf.first ? { results: { first: prf.first } } : {}) } }
      : {},
  } as RegistrationResult;
}

function assertionResult(prfFirst?: ArrayBuffer): AuthenticationResult {
  return {
    id: 'Y3JlZC1pZA',
    rawId: 'Y3JlZC1pZA',
    type: 'public-key',
    response: { authenticatorData: 'ad', clientDataJSON: 'cdj', signature: 'sig' },
    clientExtensionResults: prfFirst ? { prf: { results: { first: prfFirst } } } : {},
  } as AuthenticationResult;
}

interface Harness {
  api: AuthApi;
  webauthn: WebAuthnClient;
  events: string[];
  registerBodies: RegisterRequestBody[];
  loginBodies: LoginRequestBody[];
  recoveryCodes: string[][];
  startAuthenticationCalls: Record<string, unknown>[];
}

function harness(overrides: {
  registration: RegistrationResult;
  assertion?: AuthenticationResult;
  loginResponse?: LoginResponseBody;
}): Harness {
  const events: string[] = [];
  const registerBodies: RegisterRequestBody[] = [];
  const loginBodies: LoginRequestBody[] = [];
  const recoveryCodes: string[][] = [];
  const startAuthenticationCalls: Record<string, unknown>[] = [];

  const api: AuthApi = {
    registerOptions: async () => {
      events.push('registerOptions');
      return {
        challengeId: 'chal-1',
        options: { challenge: 'c2VydmVyLWNoYWxsZW5nZQ', rp: { id: 'localhost', name: 'Klarsend' } },
      };
    },
    register: async (body) => {
      events.push('register');
      registerBodies.push(body);
      return { userId: 'user-1', accessToken: 'jwt', expiresInSeconds: 900 };
    },
    loginOptions: async () => ({
      challengeId: 'chal-2',
      options: { challenge: 'bG9naW4tY2hhbGxlbmdl', rpId: 'localhost' },
    }),
    login: async (body) => {
      events.push('login');
      loginBodies.push(body);
      if (!overrides.loginResponse) throw new Error('login not configured');
      return overrides.loginResponse;
    },
    // slice 24: not exercised by signup/login tests — recover has its own spec
    recoverOptions: async () => {
      throw new Error('recoverOptions not configured in this harness');
    },
    recover: async () => {
      throw new Error('recover not configured in this harness');
    },
    enrollRecoveryLookup: async () => {
      throw new Error('enrollRecoveryLookup not configured in this harness');
    },
  };

  const webauthn: WebAuthnClient = {
    startRegistration: async () => {
      events.push('startRegistration');
      return overrides.registration;
    },
    startAuthentication: async (options) => {
      events.push('startAuthentication');
      startAuthenticationCalls.push(options);
      if (!overrides.assertion) throw new Error('assertion not configured');
      return overrides.assertion;
    },
  };

  return { api, webauthn, events, registerBodies, loginBodies, recoveryCodes, startAuthenticationCalls };
}

function callbacks(h: Harness, passphrase?: string) {
  return {
    confirmRecoveryCode: async (words: string[]) => {
      h.events.push('confirmRecoveryCode');
      h.recoveryCodes.push(words);
    },
    getPassphrase: async () => {
      h.events.push('getPassphrase');
      if (passphrase === undefined) throw new Error('passphrase requested unexpectedly');
      return passphrase;
    },
  };
}

describe('signup: PRF-capable authenticator', () => {
  it('derives the UK from PRF, POSTs kdf: null, and the posted wraps really open the vault', async () => {
    const h = harness({
      registration: registrationResult({ enabled: true, first: PRF_OUTPUT.slice().buffer }),
    });

    const result = await signup({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }, { termsAccepted: true });

    expect(result.unlockMethod).toBe('passkey-prf');
    const body = h.registerBodies[0];
    expect(body.challengeId).toBe('chal-1');
    expect(body.kdf).toBeNull(); // §2.1: with PRF, no master password exists at all
    expect(body.attestationResponse).toMatchObject({ id: 'Y3JlZC1pZA', type: 'public-key' });
    expect(typeof body.wrappedVaultKey.ciphertext).toBe('string');
    expect(typeof body.recoveryWrappedVaultKey.nonce).toBe('string');

    // the wrapped key that crossed the wire unwraps under the same PRF output
    const uk = await new PrfUnlockKeySource(async () => PRF_OUTPUT.slice()).deriveUnlockKey();
    const vk = await unwrapVaultKey(deserializeWrappedKey(body.wrappedVaultKey), uk);
    const blob = await encryptEntry(result.sessionVaultKey, utf8Encode('cross-check'));
    expect(utf8Decode(await decryptEntry(vk, blob))).toBe('cross-check');

    // and the recovery wrap opens under the code shown to the user
    const recoveryUk = await new RecoveryCodeUnlockKeySource(h.recoveryCodes[0]).deriveUnlockKey();
    const vkRecovery = await unwrapVaultKey(deserializeWrappedKey(body.recoveryWrappedVaultKey), recoveryUk);
    expect(utf8Decode(await decryptEntry(vkRecovery, blob))).toBe('cross-check');

    // slice 24: the body carries SHA-256(L) of the code shown — and never L itself
    const lookupKey = await lookupKeyFromRecoveryCode(h.recoveryCodes[0]);
    expect(body.recoveryLookupHash).toBe(toBase64(await hashLookupKey(lookupKey)));
    expect(body.termsAccepted).toBe(true);
    expect(body.termsVersion).toBe(CURRENT_TERMS_VERSION);
    expect(JSON.stringify(body)).not.toContain(toBase64(lookupKey).slice(0, 24));

    expect(h.events).not.toContain('getPassphrase');
  });

  it('SECURITY: the PRF output (unlock-key seed) never crosses the wire', async () => {
    const h = harness({
      registration: registrationResult({ enabled: true, first: PRF_OUTPUT.slice().buffer }),
    });

    await signup({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }, { termsAccepted: true });

    const sentPrf = h.registerBodies[0].attestationResponse.clientExtensionResults?.prf;
    expect(sentPrf).toEqual({ enabled: true }); // allowlist copies only prf.enabled, nothing else
    expect(JSON.stringify(h.registerBodies[0])).not.toContain('results');
  });

  it('when PRF output is only available via assertion, performs one local ceremony to get it', async () => {
    const h = harness({
      registration: registrationResult({ enabled: true }), // enabled, but no results at creation
      assertion: assertionResult(PRF_OUTPUT.slice().buffer),
    });

    const result = await signup({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }, { termsAccepted: true });

    expect(result.unlockMethod).toBe('passkey-prf');
    expect(h.events).toContain('startAuthentication');
    const call = h.startAuthenticationCalls[0] as {
      allowCredentials: { id: string }[];
      extensions: { prf: { eval: { first: unknown } } };
    };
    expect(call.allowCredentials).toEqual([{ id: 'Y3JlZC1pZA', type: 'public-key' }]);
    expect(call.extensions.prf.eval.first).toBeInstanceOf(Uint8Array);
    expect(h.registerBodies[0].kdf).toBeNull();
  });

  it('sends the PRF eval input (fixed app-wide salt) with the registration options', async () => {
    const h = harness({
      registration: registrationResult({ enabled: true, first: PRF_OUTPUT.slice().buffer }),
    });
    let seenOptions: Record<string, unknown> | undefined;
    const spied: WebAuthnClient = {
      startRegistration: async (options) => {
        seenOptions = options;
        return h.webauthn.startRegistration(options);
      },
      startAuthentication: h.webauthn.startAuthentication,
    };

    await signup({ api: h.api, webauthn: spied, callbacks: callbacks(h) }, { termsAccepted: true });

    const ext = (seenOptions as { extensions: { prf: { eval: { first: Uint8Array } } } }).extensions;
    expect(new Uint8Array(ext.prf.eval.first)).toEqual(await prfEvalInput());
  });
});

describe('signup: Terms gate', () => {
  it('refuses before generating recovery material or opening a server ceremony', async () => {
    const h = harness({ registration: registrationResult() });

    await expect(
      signup({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }),
    ).rejects.toThrow('terms acceptance required');

    expect(h.events).toEqual([]);
    expect(h.registerBodies).toEqual([]);
  });
});

describe('signup: passphrase fallback (no PRF)', () => {
  it('prompts for a passphrase and POSTs a full argon2id kdf config', async () => {
    const h = harness({ registration: registrationResult() });

    const result = await signup(
      { api: h.api, webauthn: h.webauthn, callbacks: callbacks(h, 'correct horse battery staple') },
      { displayName: 'Pedro', termsAccepted: true },
    );

    expect(result.unlockMethod).toBe('passphrase');
    expect(h.events).toContain('getPassphrase');

    const body = h.registerBodies[0];
    expect(body.kdf).not.toBeNull();
    expect(body.kdf!.algorithm).toBe('argon2id');
    expect(body.kdf!.memoryKiB).toBe(65536);
    expect(body.kdf!.iterations).toBe(3);
    expect(body.kdf!.parallelism).toBe(4);
    expect(typeof body.kdf!.salt).toBe('string');

    // the posted wrap opens with the same passphrase + posted kdf config
    const uk = await new PassphraseUnlockKeySource(
      'correct horse battery staple',
      deserializeKdfConfig(body.kdf!),
    ).deriveUnlockKey();
    const vk = await unwrapVaultKey(deserializeWrappedKey(body.wrappedVaultKey), uk);
    const blob = await encryptEntry(result.sessionVaultKey, utf8Encode('fallback'));
    expect(utf8Decode(await decryptEntry(vk, blob))).toBe('fallback');
  });

  it('shows the recovery code exactly once, and only before the register POST', async () => {
    const h = harness({ registration: registrationResult() });
    await signup({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h, 'pw') }, { termsAccepted: true });

    expect(h.events.filter((e) => e === 'confirmRecoveryCode')).toHaveLength(1);
    expect(h.events.indexOf('confirmRecoveryCode')).toBeLessThan(h.events.indexOf('register'));
    expect(h.recoveryCodes[0]).toHaveLength(24);
  });

  it('aborts the whole signup if the user never confirms the recovery code — before any challenge is fetched', async () => {
    const h = harness({ registration: registrationResult() });
    const aborting = {
      confirmRecoveryCode: async () => {
        throw new Error('user cancelled');
      },
      getPassphrase: async () => 'pw',
    };
    await expect(signup({ api: h.api, webauthn: h.webauthn, callbacks: aborting }, { termsAccepted: true })).rejects.toThrow(
      'user cancelled',
    );
    expect(h.registerBodies).toHaveLength(0);
    // reorder guarantee: no challenge was ever requested (nothing touched the server)
    expect(h.events).not.toContain('registerOptions');
    expect(h.events).not.toContain('startRegistration');
  });
});

describe('challenge-window ordering (TTL-expiry prevention)', () => {
  // The slow human step (recovery-code confirmation) must sit OUTSIDE the
  // WebAuthn challenge window: it has to complete before registerOptions
  // fetches the challenge, so the short server-side TTL cannot expire while
  // the user is writing down 24 words. See signup.ts ordering note.

  it('PRF path: confirmRecoveryCode fully precedes registerOptions, which precedes register', async () => {
    const h = harness({
      registration: registrationResult({ enabled: true, first: PRF_OUTPUT.slice().buffer }),
    });

    await signup({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }, { termsAccepted: true });

    const confirmAt = h.events.indexOf('confirmRecoveryCode');
    const optionsAt = h.events.indexOf('registerOptions');
    const registerAt = h.events.indexOf('register');
    expect(confirmAt).toBeGreaterThanOrEqual(0);
    expect(confirmAt).toBeLessThan(optionsAt); // slow step done before the challenge exists
    expect(optionsAt).toBeLessThan(registerAt); // window: options → … → register
  });

  it('passphrase path: same ordering — recovery confirmed before the challenge is issued', async () => {
    const h = harness({ registration: registrationResult() });

    await signup({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h, 'a passphrase') }, { termsAccepted: true });

    expect(h.events.indexOf('confirmRecoveryCode')).toBeLessThan(h.events.indexOf('registerOptions'));
    expect(h.events.indexOf('registerOptions')).toBeLessThan(h.events.indexOf('register'));
  });

  it('a slow recovery confirmation does not sit between registerOptions and register', async () => {
    const h = harness({
      registration: registrationResult({ enabled: true, first: PRF_OUTPUT.slice().buffer }),
    });
    // Model a user who takes "a long time" on the recovery screen: the delay
    // must resolve before registerOptions is ever called.
    let optionsCalledDuringConfirm = false;
    const slow = {
      confirmRecoveryCode: async () => {
        await new Promise((r) => setTimeout(r, 20));
        optionsCalledDuringConfirm = h.events.includes('registerOptions');
        h.events.push('confirmRecoveryCode');
      },
      getPassphrase: async () => 'unused',
    };

    await signup({ api: h.api, webauthn: h.webauthn, callbacks: slow }, { termsAccepted: true });

    // the challenge was NOT fetched at any point while the recovery step was still running
    expect(optionsCalledDuringConfirm).toBe(false);
    expect(h.events.indexOf('confirmRecoveryCode')).toBeLessThan(h.events.indexOf('registerOptions'));
  });
});

describe('login', () => {
  async function storedVaultFor(source: 'prf' | 'passphrase') {
    const kdf = generateKdfConfig({ memoryKiB: 1024, iterations: 3, parallelism: 4 });
    const uk =
      source === 'prf'
        ? await new PrfUnlockKeySource(async () => PRF_OUTPUT.slice()).deriveUnlockKey()
        : await new PassphraseUnlockKeySource('login pw', kdf).deriveUnlockKey();
    const { sessionVaultKey, wrappedVaultKey } = await createVault(uk, uk);
    const probe = await encryptEntry(sessionVaultKey, utf8Encode('vault-contents'));
    return { kdf, wrappedVaultKey, probe };
  }

  it('PRF path: assertion PRF output unwraps the wrapped VK returned by the server', async () => {
    const stored = await storedVaultFor('prf');
    const h = harness({
      registration: registrationResult(),
      assertion: assertionResult(PRF_OUTPUT.slice().buffer),
      loginResponse: {
        userId: 'user-1',
        accessToken: 'jwt',
        expiresInSeconds: 900,
        kdf: null,
        wrappedVaultKey: serializeWrappedKey(stored.wrappedVaultKey),
        recoveryWrappedVaultKey: serializeWrappedKey(stored.wrappedVaultKey),
        recoveryEnrolled: true,
      },
    });

    const result = await login({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) });

    expect(result.userId).toBe('user-1');
    expect(utf8Decode(await decryptEntry(result.sessionVaultKey, stored.probe))).toBe('vault-contents');
    expect(h.events).not.toContain('getPassphrase');

    // SECURITY: login sends no clientExtensionResults at all (allowlist), so
    // the PRF output can't ride along — the wire assertion has no such field.
    expect('clientExtensionResults' in h.loginBodies[0].assertionResponse).toBe(false);
    expect(JSON.stringify(h.loginBodies[0].assertionResponse)).not.toContain('prf');
  });

  it('passphrase path: uses the server-returned kdf config when PRF gives no output', async () => {
    const stored = await storedVaultFor('passphrase');
    const h = harness({
      registration: registrationResult(),
      assertion: assertionResult(), // no PRF results
      loginResponse: {
        userId: 'user-1',
        accessToken: 'jwt',
        expiresInSeconds: 900,
        kdf: serializeKdfConfig(stored.kdf),
        wrappedVaultKey: serializeWrappedKey(stored.wrappedVaultKey),
        recoveryWrappedVaultKey: serializeWrappedKey(stored.wrappedVaultKey),
        recoveryEnrolled: true,
      },
    });

    const result = await login({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h, 'login pw') });

    expect(h.events).toContain('getPassphrase');
    expect(utf8Decode(await decryptEntry(result.sessionVaultKey, stored.probe))).toBe('vault-contents');
  });
});

describe('SECURITY boundary: the PRF output never crosses the wire (register OR login)', () => {
  // A distinctive PRF output so a byte-level scan of the serialized payload
  // cannot collide by accident with unrelated random bytes (nonces, ciphertext).
  const MARKER_PRF = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + (i % 32));

  const toHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  const toBase64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));

  /**
   * Asserts the PRF output appears in NO encoding anywhere in the JSON the
   * client sends, and that the `results` key is absent entirely. This is the
   * pinned boundary check — not a walkthrough — for CLAUDE.md invariant 1.
   */
  function assertNoPrfLeak(serializedBody: string): void {
    // full-window base64/base64url can be broken across JSON escaping, so also
    // scan for any 24-byte contiguous run of the marker in each encoding
    const encodings = [
      toHex(MARKER_PRF),
      toBase64(MARKER_PRF).replace(/=+$/, ''),
      toBase64Url(MARKER_PRF),
    ];
    for (const enc of encodings) {
      // check a generous substring (survives base64 phase/alignment shifts)
      expect(serializedBody).not.toContain(enc.slice(4, 28));
    }
    expect(serializedBody).not.toContain('"results"');
    expect(serializedBody).not.toContain('results');
  }

  it('register (PRF path): serialized POST body contains no PRF output and no results key', async () => {
    const h = harness({
      registration: registrationResult({ enabled: true, first: MARKER_PRF.slice().buffer }),
    });

    await signup({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) }, { termsAccepted: true });

    const body = JSON.stringify(h.registerBodies[0]);
    assertNoPrfLeak(body);
    // prf.enabled (a non-secret capability hint) may remain; results must be gone
    expect(h.registerBodies[0].attestationResponse.clientExtensionResults?.prf).toEqual({ enabled: true });
  });

  it('login (PRF path): serialized POST body contains no PRF output and no results key', async () => {
    const kdf = generateKdfConfig({ memoryKiB: 1024, iterations: 3, parallelism: 4 });
    const uk = await new PrfUnlockKeySource(async () => MARKER_PRF.slice()).deriveUnlockKey();
    const { wrappedVaultKey } = await createVault(uk, uk);

    const h = harness({
      registration: registrationResult(),
      assertion: assertionResult(MARKER_PRF.slice().buffer),
      loginResponse: {
        userId: 'user-1',
        accessToken: 'jwt',
        expiresInSeconds: 900,
        kdf: null,
        wrappedVaultKey: serializeWrappedKey(wrappedVaultKey),
        recoveryWrappedVaultKey: serializeWrappedKey(wrappedVaultKey),
        recoveryEnrolled: true,
      },
    });

    await login({ api: h.api, webauthn: h.webauthn, callbacks: callbacks(h) });

    assertNoPrfLeak(JSON.stringify(h.loginBodies[0]));
  });

  it('sanity: the scan would CATCH a leak (guards against a vacuous assertion)', () => {
    const leaked = JSON.stringify({ assertionResponse: { clientExtensionResults: { prf: { results: { first: toBase64Url(MARKER_PRF) } } } } });
    expect(() => assertNoPrfLeak(leaked)).toThrow();
  });
});

describe('base64url helpers', () => {
  it('round-trips and matches WebAuthn JSON conventions (no padding, url alphabet)', () => {
    const bytes = Uint8Array.from({ length: 33 }, (_, i) => 250 - i);
    const encoded = toBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(fromBase64Url(encoded)).toEqual(bytes);
  });
});
