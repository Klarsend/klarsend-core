/**
 * The credential-enrollment ceremony shared by signup (slice 2) and account
 * recovery (slice 24): run WebAuthn registration with PRF eval, detect PRF
 * support (only knowable from the create result), and produce the Unlock Key
 * source — PRF-derived, or passphrase + fresh Argon2id config on the fallback
 * path. One source of truth so the two flows cannot drift.
 */
import {
  PassphraseUnlockKeySource,
  PrfUnlockKeySource,
  generateKdfConfig,
  type KdfConfig,
  type UnlockKeySource,
} from '../vault-crypto';
import { toBase64Url } from './base64url';
import { prfEnabled, prfEvalInput, prfOutput } from './prf';
import type { RegistrationResult, WebAuthnClient } from './wire';

export interface EnrollmentCeremonyResult {
  attestation: RegistrationResult;
  /** null on the PRF path — no passphrase exists at all (§2.1). */
  kdf: KdfConfig | null;
  source: UnlockKeySource;
}

export async function performEnrollmentCeremony(
  webauthn: WebAuthnClient,
  options: { challenge: string; rp: { id?: string; name?: string }; [key: string]: unknown },
  getPassphrase: () => Promise<string>,
): Promise<EnrollmentCeremonyResult> {
  const evalInput = await prfEvalInput();

  const attestation = await webauthn.startRegistration({
    ...options,
    extensions: {
      ...(options['extensions'] as Record<string, unknown> | undefined),
      prf: { eval: { first: evalInput } },
    },
  });

  // PRF support is only knowable from the create ceremony, so the Unlock Key
  // (and, on the fallback path, the passphrase prompt) necessarily resolve
  // inside the challenge window — both are sub-second / seconds.
  if (prfEnabled(attestation)) {
    const output = await obtainPrfOutput(webauthn, attestation, evalInput, options.rp.id);
    return { attestation, kdf: null, source: new PrfUnlockKeySource(async () => output.slice()) };
  }

  const passphrase = await getPassphrase();
  const kdf = generateKdfConfig();
  return { attestation, kdf, source: new PassphraseUnlockKeySource(passphrase, kdf) };
}

/**
 * Some authenticators return the PRF output with the registration result;
 * others only evaluate PRF on assertions — for those, run one local ceremony
 * (no server challenge needed: we only want the extension output).
 */
async function obtainPrfOutput(
  webauthn: WebAuthnClient,
  attestation: RegistrationResult,
  evalInput: Uint8Array,
  rpId: string | undefined,
): Promise<Uint8Array> {
  const fromRegistration = prfOutput(attestation);
  if (fromRegistration) {
    return fromRegistration;
  }

  const assertion = await webauthn.startAuthentication({
    challenge: toBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    rpId,
    allowCredentials: [{ id: attestation.id, type: 'public-key' }],
    userVerification: 'required',
    extensions: { prf: { eval: { first: evalInput } } },
  });
  const fromAssertion = prfOutput(assertion);
  if (!fromAssertion) {
    throw new Error('authenticator reported PRF support but returned no PRF output');
  }
  return fromAssertion;
}
