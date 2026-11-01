/**
 * Wire contracts for /auth plus the seams (WebAuthn client, API client)
 * injected into the flows so tests can fake both sides.
 */
import type { SerializedKdfConfig, SerializedWrappedKey } from '../vault-crypto';

/** PRF extension outputs as browsers actually return them (binary values, not JSON). */
export interface PrfExtensionOutputs {
  enabled?: boolean;
  results?: { first?: unknown; second?: unknown };
}

export interface CeremonyExtensionResults {
  prf?: PrfExtensionOutputs;
  [key: string]: unknown;
}

/** Result of navigator.credentials.create() as surfaced by @simplewebauthn/browser. */
export interface RegistrationResult {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string;
  response: Record<string, unknown>;
  clientExtensionResults?: CeremonyExtensionResults;
  [key: string]: unknown;
}

/** Result of navigator.credentials.get(). */
export interface AuthenticationResult {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string;
  response: Record<string, unknown>;
  clientExtensionResults?: CeremonyExtensionResults;
  [key: string]: unknown;
}

/**
 * What actually goes on the wire for registration — built field-by-field from
 * the ceremony result (see toWireAttestation), NOT spread from it. Only the
 * fields the server reads appear here. `clientExtensionResults` carries at most
 * `prf.enabled` (a non-secret capability hint); the PRF *output* is key
 * material and is never a field of any wire type (CLAUDE.md invariant 1).
 */
export interface WireAttestationResponse {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string;
  response: {
    attestationObject: string;
    clientDataJSON: string;
    transports?: string[];
  };
  clientExtensionResults?: { prf?: { enabled: boolean } };
}

/**
 * What goes on the wire for login. No `clientExtensionResults` field exists at
 * all: the only client extension we use is PRF, whose output must never leave
 * the device, so login sends nothing in that slot.
 */
export interface WireAssertionResponse {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string;
  response: {
    authenticatorData: string;
    signature: string;
    clientDataJSON: string;
    userHandle?: string;
  };
}

export interface WebAuthnClient {
  startRegistration(options: Record<string, unknown>): Promise<RegistrationResult>;
  startAuthentication(options: Record<string, unknown>): Promise<AuthenticationResult>;
}

// ── /auth request/response bodies ─────────────────────────────────────────

export interface RegisterOptionsResponse {
  challengeId: string;
  options: { challenge: string; rp: { id?: string; name?: string }; [key: string]: unknown };
}

export interface RegisterRequestBody {
  challengeId: string;
  attestationResponse: WireAttestationResponse;
  /** null when the passkey supports PRF — no passphrase exists at all (§2.1). */
  kdf: SerializedKdfConfig | null;
  wrappedVaultKey: SerializedWrappedKey;
  recoveryWrappedVaultKey: SerializedWrappedKey;
  /**
   * Slice 24: SHA-256 (base64) of the recovery lookup key L — a one-way
   * fingerprint of a derived key. Neither the words, the recovery unlock key,
   * nor L itself ever appear in this body (canary-pinned).
   */
  recoveryLookupHash: string;
  termsAccepted: true;
  termsVersion: string;
}

export interface AuthTokenResponse {
  userId: string;
  accessToken: string;
  expiresInSeconds: number;
}

export interface LoginOptionsResponse {
  challengeId: string;
  options: { challenge: string; rpId?: string; [key: string]: unknown };
}

export interface LoginRequestBody {
  challengeId: string;
  assertionResponse: WireAssertionResponse;
}

export interface LoginResponseBody extends AuthTokenResponse {
  kdf: SerializedKdfConfig | null;
  wrappedVaultKey: SerializedWrappedKey;
  /**
   * Slice 24: the recovery wrap (ciphertext, same trust class as
   * `wrappedVaultKey`) — lets the settings verifier run with zero further
   * network — plus the non-secret enrolled flag for the migration banner.
   */
  recoveryWrappedVaultKey: SerializedWrappedKey;
  recoveryEnrolled: boolean;
}

// ── account recovery (slice 24) ─────────────────────────────────────────────

export interface RecoverOptionsResponseBody {
  challengeId: string;
  recoveryWrappedVaultKey: SerializedWrappedKey;
  options: { challenge: string; rp: { id?: string; name?: string }; [key: string]: unknown };
}

/**
 * The recovery commit. Same zero-knowledge accounting as registration: only
 * ciphertext, public KDF config, and the one-way hash of the NEW code's
 * lookup key. The OLD code's L appears solely in RecoverOptions requests.
 */
export interface RecoverRequestBody {
  challengeId: string;
  attestationResponse: WireAttestationResponse;
  kdf: SerializedKdfConfig | null;
  wrappedVaultKey: SerializedWrappedKey;
  recoveryWrappedVaultKey: SerializedWrappedKey;
  recoveryLookupHash: string;
}

export interface AuthApi {
  registerOptions(displayName?: string): Promise<RegisterOptionsResponse>;
  register(body: RegisterRequestBody): Promise<AuthTokenResponse>;
  loginOptions(): Promise<LoginOptionsResponse>;
  login(body: LoginRequestBody): Promise<LoginResponseBody>;
  /** Slice 24: `lookupKey` is L (base64) — presented to be burned by the ceremony it opens. */
  recoverOptions(lookupKey: string): Promise<RecoverOptionsResponseBody>;
  recover(body: RecoverRequestBody): Promise<AuthTokenResponse>;
  /** Slice 24 migration: authed upload of an existing code's lookup hash. */
  enrollRecoveryLookup(recoveryLookupHash: string, accessToken: string): Promise<void>;
}
