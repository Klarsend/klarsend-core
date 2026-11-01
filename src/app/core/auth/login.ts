/**
 * Login flow: WebAuthn assertion (with PRF eval) → JWT + wrapped vault
 * material from the server → derive UK (PRF output, or passphrase + the
 * server-stored KDF config) → unwrap the session vault key locally.
 */
import {
  PassphraseUnlockKeySource,
  PrfUnlockKeySource,
  deserializeKdfConfig,
  deserializeWrappedKey,
  unwrapVaultKey,
  type SerializedWrappedKey,
} from '../vault-crypto';
import { prfEvalInput, prfOutput } from './prf';
import { toWireAssertion } from './wire-response';
import type { AuthApi, WebAuthnClient } from './wire';

export interface LoginDeps {
  api: AuthApi;
  webauthn: WebAuthnClient;
  callbacks: { getPassphrase(): Promise<string> };
}

export interface LoginResult {
  userId: string;
  accessToken: string;
  expiresInSeconds: number;
  sessionVaultKey: CryptoKey;
  /** Slice 24: the recovery wrap (ciphertext) — fuels the pure-local settings verifier. */
  recoveryWrappedVaultKey: SerializedWrappedKey;
  /** Slice 24: whether a recovery lookup hash is on file (drives the migration banner). */
  recoveryEnrolled: boolean;
}

export async function login(deps: LoginDeps): Promise<LoginResult> {
  const { api, webauthn, callbacks } = deps;
  const { challengeId, options } = await api.loginOptions();

  const assertion = await webauthn.startAuthentication({
    ...options,
    extensions: {
      ...(options['extensions'] as Record<string, unknown> | undefined),
      prf: { eval: { first: await prfEvalInput() } },
    },
  });

  // toWireAssertion: allowlist copy — no clientExtensionResults, so the PRF
  // output extracted below never reaches the wire
  const response = await api.login({ challengeId, assertionResponse: toWireAssertion(assertion) });

  const output = prfOutput(assertion);
  const unlockKey = output
    ? await new PrfUnlockKeySource(async () => output.slice()).deriveUnlockKey()
    : await derivePassphraseKey(response.kdf, callbacks);

  const sessionVaultKey = await unwrapVaultKey(deserializeWrappedKey(response.wrappedVaultKey), unlockKey);
  return {
    userId: response.userId,
    accessToken: response.accessToken,
    expiresInSeconds: response.expiresInSeconds,
    sessionVaultKey,
    recoveryWrappedVaultKey: response.recoveryWrappedVaultKey,
    recoveryEnrolled: response.recoveryEnrolled,
  };
}

async function derivePassphraseKey(
  kdf: Parameters<typeof deserializeKdfConfig>[0] | null,
  callbacks: LoginDeps['callbacks'],
): Promise<CryptoKey> {
  if (!kdf) {
    throw new Error('no passphrase configured for this account and the passkey returned no PRF output');
  }
  return new PassphraseUnlockKeySource(await callbacks.getPassphrase(), deserializeKdfConfig(kdf)).deriveUnlockKey();
}
