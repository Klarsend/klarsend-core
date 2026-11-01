/** fetch-based VaultApi against the Klarsend API (GET/PUT /vault, Bearer JWT). */
import type { PutVaultBody, PutVaultResult, SerializedVaultBlob, VaultApi } from './wire';
import { VaultConflictError, VaultUnauthorizedError } from './wire';

export class HttpVaultApi implements VaultApi {
  constructor(
    private readonly baseUrl: string,
    /** Supplies the current vault-scoped access token (15-min JWT from login). */
    private readonly getAccessToken: () => string,
  ) {}

  async getVault(): Promise<SerializedVaultBlob | null> {
    const response = await fetch(`${this.baseUrl}/vault`, {
      headers: { authorization: `Bearer ${this.getAccessToken()}` },
    });
    if (response.status === 204) {
      return null; // fresh account: nothing pushed yet
    }
    if (response.status === 401) {
      throw new VaultUnauthorizedError();
    }
    if (!response.ok) {
      throw await toError(response);
    }
    return (await response.json()) as SerializedVaultBlob;
  }

  async putVault(body: PutVaultBody): Promise<PutVaultResult> {
    const response = await fetch(`${this.baseUrl}/vault`, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${this.getAccessToken()}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    if (response.status === 401) {
      throw new VaultUnauthorizedError();
    }
    if (response.status === 409) {
      const problem = (await response.json().catch(() => ({}))) as { currentVersion?: number };
      throw new VaultConflictError(problem.currentVersion ?? -1);
    }
    if (!response.ok) {
      throw await toError(response);
    }
    return (await response.json()) as PutVaultResult;
  }
}

async function toError(response: Response): Promise<Error> {
  // problem+json bodies carry no secrets by design; surface the title only
  const title = await response
    .json()
    .then((p: { title?: string }) => p.title)
    .catch(() => undefined);
  return new Error(title ?? `request failed (${response.status})`);
}
