/**
 * Auth core (§2.1 auth model): WebAuthn ceremonies via @simplewebauthn/browser,
 * PRF-first Unlock Key selection with passphrase fallback, signup/login flows
 * wired into the vault-crypto module. No UI in here.
 */
export { fromBase64Url, toBase64Url } from './base64url';
export { HttpAuthApi } from './http-auth-api';
export { login, type LoginDeps, type LoginResult } from './login';
export { prfEnabled, prfEvalInput, prfOutput } from './prf';
export { recover, type RecoverCallbacks, type RecoverDeps, type RecoverResult } from './recover';
export { signup, type SignupCallbacks, type SignupDeps, type SignupResult } from './signup';
export { browserWebAuthnClient } from './webauthn-client';
export { toWireAssertion, toWireAttestation } from './wire-response';
export type {
  AuthApi,
  AuthTokenResponse,
  AuthenticationResult,
  LoginOptionsResponse,
  LoginRequestBody,
  LoginResponseBody,
  RecoverOptionsResponseBody,
  RecoverRequestBody,
  RegisterOptionsResponse,
  RegisterRequestBody,
  RegistrationResult,
  WebAuthnClient,
  WireAssertionResponse,
  WireAttestationResponse,
} from './wire';
