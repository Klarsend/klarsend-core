/** Thin adapter over @simplewebauthn/browser satisfying the WebAuthnClient seam. */
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

import type { AuthenticationResult, RegistrationResult, WebAuthnClient } from './wire';

export const browserWebAuthnClient: WebAuthnClient = {
  async startRegistration(options: Record<string, unknown>): Promise<RegistrationResult> {
    // optionsJSON is structurally the server's PublicKeyCredentialCreationOptionsJSON
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (await startRegistration({ optionsJSON: options as any })) as unknown as RegistrationResult;
  },
  async startAuthentication(options: Record<string, unknown>): Promise<AuthenticationResult> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (await startAuthentication({ optionsJSON: options as any })) as unknown as AuthenticationResult;
  },
};
