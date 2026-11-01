/**
 * App-facing SAS minting for account-key connections (spec §3.1 #4/#6). Two uses:
 * a short-lived container read+list SAS so an account-key connection can be
 * BROWSED (it holds no pasted SAS to put in the URL), and a read-only single-blob
 * SAS for the "generate link" action. Both sign entirely client-side via
 * {@link signServiceSasToken}; the account key never leaves the device.
 *
 * `st` (start) is deliberately omitted so the token is valid immediately without
 * risking clock-skew "not yet valid" failures; the token is bounded by `se`.
 */
// Deep import, not the azure-blob barrel: the barrel re-exports the upload engine and
// the rename/delete provider, and the published security core (tools/core-mirror) is
// the import closure of this module — the barrel would drag product code into it.
import { blobUrl } from '../azure-blob/azure-urls';
import { signServiceSasToken } from './sign-service-sas';

/** How long a browse SAS an account-key connection self-mints stays valid. */
export const BROWSE_SAS_TTL_MS = 60 * 60 * 1000; // 1 hour — a browse session

/** How long a self-minted upload SAS stays valid before the provider re-mints. */
export const UPLOAD_SAS_TTL_MS = 60 * 60 * 1000; // 1 hour

/** Re-mint threshold: don't start a request on a token this close to expiry. */
export const UPLOAD_SAS_REMINT_MARGIN_MS = 5 * 60 * 1000;

/** Mint a container read+list SAS token (no leading `?`) for browsing. */
export function mintContainerBrowseSas(
  accountName: string,
  containerName: string,
  accountKey: string,
  now: Date = new Date(),
): Promise<string> {
  return signServiceSasToken(
    { accountName, containerName, permissions: 'rl', expiresOn: new Date(now.getTime() + BROWSE_SAS_TTL_MS) },
    accountKey,
  );
}

/**
 * Mint a container upload SAS token (no leading `?`) — slice 19. Permissions
 * `rcw`: read for the overwrite HEAD check, create+write to stage and commit
 * blocks. Signed entirely client-side; the key never leaves the device.
 */
export function mintContainerUploadSas(
  accountName: string,
  containerName: string,
  accountKey: string,
  now: Date = new Date(),
): Promise<string> {
  return signServiceSasToken(
    { accountName, containerName, permissions: 'rcw', expiresOn: new Date(now.getTime() + UPLOAD_SAS_TTL_MS) },
    accountKey,
  );
}

/**
 * A per-request SAS provider for an account-key connection's uploads: re-mints
 * transparently once the current token is within
 * {@link UPLOAD_SAS_REMINT_MARGIN_MS} of its expiry — the advantage only this
 * credential type has: a 6-hour master upload never dies on a 1-hour token.
 * (A pasted-SAS connection has no such recourse; its mid-upload expiry surfaces
 * as the honest specific failure instead.)
 */
export function uploadSasProvider(
  accountName: string,
  containerName: string,
  accountKey: string,
  now: () => Date = () => new Date(),
): () => Promise<string> {
  let current: { token: string; expiresAt: number } | null = null;
  return async () => {
    const at = now();
    if (!current || current.expiresAt - at.getTime() < UPLOAD_SAS_REMINT_MARGIN_MS) {
      const token = await mintContainerUploadSas(accountName, containerName, accountKey, at);
      current = { token, expiresAt: at.getTime() + UPLOAD_SAS_TTL_MS };
    }
    return current.token;
  };
}

/**
 * Management SAS TTL (slice 22) — deliberately shorter than browse/upload: a
 * delete token is the sharpest credential this app ever mints, so it lives only
 * as long as one operation plausibly runs. Long folder deletes survive via
 * {@link manageSasProvider}'s transparent re-mint, not a longer token.
 */
export const MANAGE_SAS_TTL_MS = 15 * 60 * 1000;

/** Re-mint threshold for management tokens (mirrors the upload provider's). */
export const MANAGE_SAS_REMINT_MARGIN_MS = 5 * 60 * 1000;

/** Permission letters minted per management operation — never a standing `racwdl`. */
export const DELETE_SAS_PERMISSIONS = 'd';
export const RENAME_SAS_PERMISSIONS = 'rcwd'; // read source+verify, create/write dest, delete original
/**
 * Set Blob Tier / rehydrate: Azure gates it on `w` alone. The browse token an
 * account-key connection self-mints is `rl`, which Set Blob Tier refuses — so a
 * tier change mints these letters for the one operation instead of widening the
 * browse token.
 */
export const TIER_SAS_PERMISSIONS = 'w';

/** The closed set of per-operation letter strings — no other string can be minted here. */
export type ManageSasPermissions =
  | typeof DELETE_SAS_PERMISSIONS
  | typeof RENAME_SAS_PERMISSIONS
  | typeof TIER_SAS_PERMISSIONS;

/** Mint a container management SAS token (no leading `?`) for ONE operation kind. */
export function mintContainerManageSas(
  accountName: string,
  containerName: string,
  accountKey: string,
  permissions: ManageSasPermissions,
  now: Date = new Date(),
): Promise<string> {
  return signServiceSasToken(
    { accountName, containerName, permissions, expiresOn: new Date(now.getTime() + MANAGE_SAS_TTL_MS) },
    accountKey,
  );
}

/**
 * A per-request SAS provider for an account-key connection's management
 * operations (slice 22) — the {@link uploadSasProvider} pattern with the
 * shorter management TTL: a folder delete that outlives one token re-mints
 * transparently instead of dying mid-batch, while each minted token stays
 * narrow (only this operation's letters) and short-lived.
 */
export function manageSasProvider(
  accountName: string,
  containerName: string,
  accountKey: string,
  permissions: ManageSasPermissions,
  now: () => Date = () => new Date(),
): () => Promise<string> {
  let current: { token: string; expiresAt: number } | null = null;
  return async () => {
    const at = now();
    if (!current || current.expiresAt - at.getTime() < MANAGE_SAS_REMINT_MARGIN_MS) {
      const token = await mintContainerManageSas(accountName, containerName, accountKey, permissions, at);
      current = { token, expiresAt: at.getTime() + MANAGE_SAS_TTL_MS };
    }
    return current.token;
  };
}

/**
 * Mint a read-only single-blob SAS and return the full RAW Azure blob URL. This
 * is the direct download link (§3.1 #6) — long-lived as configured, with no
 * revocation until the resolver slice wraps it.
 */
export async function mintBlobReadSasUrl(
  accountName: string,
  containerName: string,
  blobName: string,
  accountKey: string,
  expiresOn: Date,
  contentDisposition?: string,
): Promise<string> {
  const token = await signServiceSasToken(
    {
      accountName,
      containerName,
      blobName,
      permissions: 'r',
      expiresOn,
      ...(contentDisposition ? { contentDisposition } : {}),
    },
    accountKey,
  );
  return blobUrl(accountName, containerName, blobName, token);
}
