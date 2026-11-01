/**
 * Build the wire form of a WebAuthn ceremony result by an ALLOWLIST: every
 * field is named and copied explicitly, so anything the server doesn't read —
 * and, critically, the PRF output (the unlock-key seed, CLAUDE.md invariant 1)
 * — is structurally incapable of reaching the network. This is deliberately
 * NOT a spread/denylist: a new extension output added by the browser can never
 * leak by default, because it simply isn't one of the fields we copy.
 */
import type {
  AuthenticationResult,
  RegistrationResult,
  WireAssertionResponse,
  WireAttestationResponse,
} from './wire';

export function toWireAttestation(result: RegistrationResult): WireAttestationResponse {
  const response = result.response as {
    attestationObject?: unknown;
    clientDataJSON?: unknown;
    transports?: unknown;
  };

  const wireResponse: WireAttestationResponse['response'] = {
    attestationObject: String(response.attestationObject ?? ''),
    clientDataJSON: String(response.clientDataJSON ?? ''),
  };
  if (Array.isArray(response.transports)) {
    wireResponse.transports = response.transports.map(String);
  }

  const wire: WireAttestationResponse = {
    id: result.id,
    rawId: result.rawId,
    type: result.type,
    response: wireResponse,
  };
  if (typeof result.authenticatorAttachment === 'string') {
    wire.authenticatorAttachment = result.authenticatorAttachment;
  }

  // Copy ONLY prf.enabled (a boolean capability hint) — never prf.results.
  const enabled = result.clientExtensionResults?.prf?.enabled;
  if (typeof enabled === 'boolean') {
    wire.clientExtensionResults = { prf: { enabled } };
  }

  return wire;
}

export function toWireAssertion(result: AuthenticationResult): WireAssertionResponse {
  const response = result.response as {
    authenticatorData?: unknown;
    signature?: unknown;
    clientDataJSON?: unknown;
    userHandle?: unknown;
  };

  const wireResponse: WireAssertionResponse['response'] = {
    authenticatorData: String(response.authenticatorData ?? ''),
    signature: String(response.signature ?? ''),
    clientDataJSON: String(response.clientDataJSON ?? ''),
  };
  if (typeof response.userHandle === 'string') {
    wireResponse.userHandle = response.userHandle;
  }

  const wire: WireAssertionResponse = {
    id: result.id,
    rawId: result.rawId,
    type: result.type,
    response: wireResponse,
  };
  if (typeof result.authenticatorAttachment === 'string') {
    wire.authenticatorAttachment = result.authenticatorAttachment;
  }

  // No clientExtensionResults: PRF output is the only extension we consume and
  // it stays on the device.
  return wire;
}
