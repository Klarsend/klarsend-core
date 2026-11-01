/** fetch-based AuthApi against the Klarsend API. */
import type {
  AuthApi,
  AuthTokenResponse,
  LoginOptionsResponse,
  LoginRequestBody,
  LoginResponseBody,
  RecoverOptionsResponseBody,
  RecoverRequestBody,
  RegisterOptionsResponse,
  RegisterRequestBody,
} from './wire';

export class HttpAuthApi implements AuthApi {
  constructor(private readonly baseUrl: string) {}

  registerOptions(displayName?: string): Promise<RegisterOptionsResponse> {
    return this.post('/auth/register/options', { displayName: displayName ?? null });
  }

  register(body: RegisterRequestBody): Promise<AuthTokenResponse> {
    return this.post('/auth/register', body);
  }

  loginOptions(): Promise<LoginOptionsResponse> {
    return this.post('/auth/login/options', {});
  }

  login(body: LoginRequestBody): Promise<LoginResponseBody> {
    return this.post('/auth/login', body);
  }

  recoverOptions(lookupKey: string): Promise<RecoverOptionsResponseBody> {
    return this.post('/auth/recover/options', { lookupKey });
  }

  recover(body: RecoverRequestBody): Promise<AuthTokenResponse> {
    return this.post('/auth/recover', body);
  }

  async enrollRecoveryLookup(recoveryLookupHash: string, accessToken: string): Promise<void> {
    const response = await fetch(this.baseUrl + '/auth/recovery-lookup', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ recoveryLookupHash }),
    });
    if (!response.ok) {
      throw new Error(`enrollment failed (${response.status})`);
    }
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const response = await fetch(this.baseUrl + path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      // problem+json bodies carry no secrets by design; surface the title only
      const title = await response
        .json()
        .then((p: { title?: string }) => p.title)
        .catch(() => undefined);
      throw new Error(title ?? `request failed (${response.status})`);
    }
    return (await response.json()) as T;
  }
}
