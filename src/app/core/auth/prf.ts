/**
 * Passkey PRF extension plumbing (§2.1). The PRF eval input is a fixed
 * app-wide constant: the unlock key's uniqueness comes from the credential's
 * internal key, not from this salt.
 */
import { utf8Encode } from '../vault-crypto/encoding';
import { fromBase64Url } from './base64url';
import type { AuthenticationResult, RegistrationResult } from './wire';

const PRF_EVAL_CONTEXT = 'klarsend/v1/prf-eval';

export async function prfEvalInput(): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', utf8Encode(PRF_EVAL_CONTEXT)));
}

export function prfEnabled(registration: RegistrationResult): boolean {
  return registration.clientExtensionResults?.prf?.enabled === true;
}

/**
 * Extracts `prf.results.first`, tolerating every shape seen in the wild:
 * ArrayBuffer/TypedArray (real browsers) or base64url string (JSON'd results).
 */
export function prfOutput(result: RegistrationResult | AuthenticationResult): Uint8Array | null {
  const first = result.clientExtensionResults?.prf?.results?.first;
  if (first instanceof Uint8Array) {
    return first.slice();
  }
  if (first instanceof ArrayBuffer) {
    return new Uint8Array(first.slice(0));
  }
  if (typeof first === 'string' && first.length > 0) {
    return fromBase64Url(first);
  }
  return null;
}
