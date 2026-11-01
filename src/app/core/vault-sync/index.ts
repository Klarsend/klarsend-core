/**
 * Vault sync core (spec §3.1 #2) — standalone like auth core: plain TS with
 * injected seams, no Angular dependencies. Pull on unlock, push on change,
 * 409 → re-fetch → retry. Only ciphertext and version metadata cross the wire.
 */
export { HttpVaultApi } from './http-vault-api';
export { VaultSync, type PulledVault, type VaultSyncDeps } from './vault-sync';
export {
  VaultConflictError,
  VaultUnauthorizedError,
  type PutVaultBody,
  type PutVaultResult,
  type SerializedVaultBlob,
  type VaultApi,
} from './wire';
