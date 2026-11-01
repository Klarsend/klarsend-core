/**
 * Azure Blob REST URL construction (spec §3.3). These URLs are hit **directly
 * from the browser against the customer's own storage account** — never through
 * the Klarsend API. That direct-to-Azure traffic is the intended architecture
 * (§4): our server never sees the SAS credential, only its ciphertext in the
 * synced vault blob.
 *
 * The wizard collects account name and container name as their own fields, so
 * the path is built from those; from the pasted SAS we take ONLY the query
 * string (the signature and its parameters). A SAS may be pasted either as a
 * full URL (`https://acct.blob.core.windows.net/container?sv=…`) or as a bare
 * token (`?sv=…` or `sv=…`); both reduce to the same query parameters.
 */

/** Extract the SAS query parameters from either a full SAS URL or a bare token. */
export function sasQueryParams(sas: string): URLSearchParams {
  const trimmed = sas.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return new URLSearchParams(new URL(trimmed).search);
  }
  return new URLSearchParams(trimmed.replace(/^\?/, ''));
}

/** `https://{account}.blob.core.windows.net/{container}` — the container resource. */
export function containerBaseUrl(accountName: string, containerName: string): string {
  const account = encodeURIComponent(accountName.trim());
  const container = encodeURIComponent(containerName.trim());
  return `https://${account}.blob.core.windows.net/${container}`;
}

/**
 * List-blobs URL scoped to a single result (`maxresults=1`) — the lightest real
 * operation that still proves both CORS reachability and a working credential
 * (§3.3: "list with maxresults=1"). The SAS query is merged with the list
 * parameters; the list params win on any collision.
 */
export function containerListUrl(accountName: string, containerName: string, sas: string): string {
  const params = sasQueryParams(sas);
  params.set('restype', 'container');
  params.set('comp', 'list');
  params.set('maxresults', '1');
  return `${containerBaseUrl(accountName, containerName)}?${params.toString()}`;
}

/** Azure's own max (and default) page size for List Blobs. */
export const LIST_BLOBS_MAX_PAGE = 5000;

export interface ListBlobsParams {
  accountName: string;
  containerName: string;
  sas: string;
  /** Folder prefix to list within (`''` = container root). */
  prefix?: string;
  /** Continuation marker from a previous page's `NextMarker`. */
  marker?: string;
  /** `/` gives virtual folders (BlobPrefix). Default `/`. */
  delimiter?: string;
  /** Page size; Azure caps at {@link LIST_BLOBS_MAX_PAGE}. Default that cap. */
  maxResults?: number;
}

/**
 * The real browse List Blobs URL (spec §3.1 #4): `?restype=container&comp=list`
 * with `delimiter=/` for virtual folders, an optional `prefix` for navigation,
 * and a `marker` for continuation. Deliberately built to be a *simple* GET (no
 * custom request headers at the call site) so the browser makes no CORS
 * preflight for listing — the same reason the probe stays header-free.
 */
export function listBlobsUrl(p: ListBlobsParams): string {
  const params = sasQueryParams(p.sas);
  params.set('restype', 'container');
  params.set('comp', 'list');
  params.set('delimiter', p.delimiter ?? '/');
  params.set('maxresults', String(p.maxResults ?? LIST_BLOBS_MAX_PAGE));
  if (p.prefix) {
    params.set('prefix', p.prefix);
  }
  if (p.marker) {
    params.set('marker', p.marker);
  }
  return `${containerBaseUrl(p.accountName, p.containerName)}?${params.toString()}`;
}

/**
 * Put Block URL (`comp=block&blockid=…`) — stages one block of an upload
 * (slice 19). Staged blocks are INVISIBLE until a Put Block List commits them;
 * Azure discards uncommitted blocks after ~7 days.
 */
export function putBlockUrl(
  accountName: string,
  containerName: string,
  blobName: string,
  sas: string,
  blockId: string,
): string {
  const params = sasQueryParams(sas);
  params.set('comp', 'block');
  params.set('blockid', blockId);
  return `${containerBaseUrl(accountName, containerName)}/${encodeBlobPath(blobName)}?${params.toString()}`;
}

/**
 * Put Block List URL (`comp=blocklist`) — the commit that brings the blob into
 * existence (or replaces it; the engine's conditional headers gate which).
 */
export function putBlockListUrl(
  accountName: string,
  containerName: string,
  blobName: string,
  sas: string,
): string {
  const params = sasQueryParams(sas);
  params.set('comp', 'blocklist');
  return `${containerBaseUrl(accountName, containerName)}/${encodeBlobPath(blobName)}?${params.toString()}`;
}

/** Percent-encode each path segment of a blob name, preserving the `/` separators. */
function encodeBlobPath(blobName: string): string {
  return blobName
    .split('/')
    .map((seg) => encodeURIComponent(seg))
    .join('/');
}

/** `https://{account}.blob.core.windows.net/{container}/{blob}?{sas}` — one blob resource. */
export function blobUrl(
  accountName: string,
  containerName: string,
  blobName: string,
  sas: string,
): string {
  const params = sasQueryParams(sas);
  return `${containerBaseUrl(accountName, containerName)}/${encodeBlobPath(blobName)}?${params.toString()}`;
}

/**
 * Set Blob Tier URL (`comp=tier`) for a single blob (spec §3.1 #5). The tier and
 * (for archive rehydration) the priority ride in request HEADERS, not the URL —
 * see {@link buildSetTierHeaders}. This is the PUT the wizard's CORS rule was
 * provisioned for.
 */
export function setBlobTierUrl(
  accountName: string,
  containerName: string,
  blobName: string,
  sas: string,
): string {
  const params = sasQueryParams(sas);
  params.set('comp', 'tier');
  return `${containerBaseUrl(accountName, containerName)}/${encodeBlobPath(blobName)}?${params.toString()}`;
}
