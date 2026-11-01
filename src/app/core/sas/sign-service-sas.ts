/**
 * Client-side Azure **service SAS** signer (spec §3.1 #6, build plan Week 3).
 * Mints a read-only, single-blob (or read+list container) SAS **entirely in the
 * browser** by HMAC-SHA256'ing the Azure string-to-sign with the storage account
 * key, via WebCrypto (CLAUDE.md invariant 4 — no home-rolled primitives).
 *
 * SECURITY (CLAUDE.md invariants 1, 2, 7): the account key and every token this
 * produces are key-material. They are used only here, only client-side; they must
 * never reach our API and never be logged. The canary/byte-scan suite pins that.
 *
 * PINNED VERSION. We implement the string-to-sign for service version
 * `2026-06-06` ({@link SIGNED_SAS_VERSION}). For a shared-key credential the Azure
 * SDK routes every version ≥ 2020-12-06 through the same construction, so this
 * layout is stable across that band. The byte-for-byte equality matrix in
 * sign-service-sas.equality.spec is the source of truth; do not change the field
 * order, the empty-field newlines, or the query encoding without re-running it.
 *
 * The SDK is a **dev-only test oracle**; this module depends on nothing but the
 * shared encoding helpers and ships in the bundle. `@azure/storage-blob` does not
 * (proven by sign-service-sas.bundle.spec).
 */
import { fromBase64, toBase64, utf8Encode } from '../vault-crypto/encoding';

/** The Azure storage service version whose SAS layout this signer implements. */
export const SIGNED_SAS_VERSION = '2026-06-06';

export interface SasIpRange {
  start: string;
  end?: string;
}

export interface ServiceSasInput {
  accountName: string;
  containerName: string;
  /** Present → object (blob) SAS (`sr=b`); absent → container SAS (`sr=c`). */
  blobName?: string;
  /** Permission letters (any order/case); canonicalised to match Azure. */
  permissions: string;
  /** Mandatory — a service SAS must expire (spec: default 7-day, picker to 1 h). */
  expiresOn: Date;
  startsOn?: Date;
  /** `spr` — restrict to https, or https+http. */
  protocol?: 'https' | 'https,http';
  /** `sip` — restrict to a client IP or IP range. */
  ipRange?: SasIpRange;
  /** `rscd` — Content-Disposition override (e.g. force download with a filename). */
  contentDisposition?: string;
  /** `rscc` — Cache-Control override. */
  cacheControl?: string;
  /** `rsce` — Content-Encoding override. */
  contentEncoding?: string;
  /** `rscl` — Content-Language override. */
  contentLanguage?: string;
  /** `rsct` — Content-Type override. */
  contentType?: string;
}

// Canonical permission letter order Azure enforces (SDK: {Blob,Container}
// SASPermissions.parse().toString()). Blob has no `l`/`f`; container inserts `l`
// after `x`. We reorder the caller's letters into this order so `wr` → `rw`, etc.
const PERMISSION_ORDER = {
  b: 'racwdxtmeiy',
  c: 'racwdxltmeiyf',
} as const;

function canonicalPermissions(permissions: string, resource: 'b' | 'c'): string {
  const order = PERMISSION_ORDER[resource];
  const present = new Set(permissions.toLowerCase().split(''));
  return order
    .split('')
    .filter((ch) => present.has(ch))
    .join('');
}

/** `date.toISOString()` truncated to seconds with a `Z` — Azure's SAS date form. */
function truncatedIso(date: Date): string {
  const s = date.toISOString(); // 2027-03-14T18:30:00.000Z
  return s.substring(0, s.length - 5) + 'Z'; // 2027-03-14T18:30:00Z
}

function ipRangeToString(range: SasIpRange): string {
  return range.end ? `${range.start}-${range.end}` : range.start;
}

/**
 * The service-SAS string-to-sign for {@link SIGNED_SAS_VERSION} (shared-key).
 * Field order and the empty-string placeholders for unset fields are load-bearing
 * — each participates as its own `\n`-separated line even when blank.
 */
function stringToSign(input: ServiceSasInput, resource: 'b' | 'c', permissions: string): string {
  const canonicalizedResource =
    `/blob/${input.accountName}/${input.containerName}` +
    (input.blobName ? `/${input.blobName}` : '');

  return [
    permissions,
    input.startsOn ? truncatedIso(input.startsOn) : '',
    truncatedIso(input.expiresOn),
    canonicalizedResource,
    '', // signedIdentifier (stored access policy) — never set here
    input.ipRange ? ipRangeToString(input.ipRange) : '',
    input.protocol ?? '',
    SIGNED_SAS_VERSION,
    resource,
    '', // signedSnapshotTime
    '', // signedEncryptionScope
    input.cacheControl ?? '',
    input.contentDisposition ?? '',
    input.contentEncoding ?? '',
    input.contentLanguage ?? '',
    input.contentType ?? '',
  ].join('\n');
}

async function hmacSha256Base64(keyBase64: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    fromBase64(keyBase64) as unknown as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, utf8Encode(message) as unknown as ArrayBuffer);
  return toBase64(new Uint8Array(mac));
}

/**
 * Build the SAS query string in Azure's exact field order, percent-encoding each
 * value and omitting empty ones (mirrors the SDK's `SASQueryParameters.toString`).
 */
function buildQuery(
  input: ServiceSasInput,
  resource: 'b' | 'c',
  permissions: string,
  signature: string,
): string {
  const parts: string[] = [];
  const push = (key: string, value: string | undefined): void => {
    if (value) {
      parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
    }
  };
  push('sv', SIGNED_SAS_VERSION);
  push('spr', input.protocol);
  push('st', input.startsOn ? truncatedIso(input.startsOn) : undefined);
  push('se', truncatedIso(input.expiresOn));
  push('sip', input.ipRange ? ipRangeToString(input.ipRange) : undefined);
  push('sr', resource);
  push('sp', permissions);
  push('rscc', input.cacheControl);
  push('rscd', input.contentDisposition);
  push('rsce', input.contentEncoding);
  push('rscl', input.contentLanguage);
  push('rsct', input.contentType);
  push('sig', signature);
  return parts.join('&');
}

/**
 * Sign a service SAS token (the `sv=…&sig=…` query, no leading `?`) for the given
 * blob/container, byte-for-byte compatible with `@azure/storage-blob`. `key` is
 * the base64 account key — key material; never log it or the returned token.
 */
export async function signServiceSasToken(input: ServiceSasInput, key: string): Promise<string> {
  const resource: 'b' | 'c' = input.blobName ? 'b' : 'c';
  const permissions = canonicalPermissions(input.permissions, resource);
  const signature = await hmacSha256Base64(key, stringToSign(input, resource, permissions));
  return buildQuery(input, resource, permissions, signature);
}
