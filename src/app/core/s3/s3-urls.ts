/**
 * S3 REST URL construction (slice 14, browse). These URLs are hit **directly from
 * the browser against the customer's bucket** — never through the Klarsend API
 * (same architecture as the Azure path, §4). Virtual-hosted-style by default
 * (`{bucket}.s3.{region}.amazonaws.com`), which works for every region including
 * us-east-1 and is required for buckets created after 2020.
 *
 * PROVIDER SEAM (the promised GCS-interop prep): the host is endpoint-configurable
 * — `endpoint` overrides the AWS host so an S3-compatible endpoint (GCS, Wasabi,
 * MinIO) drops in without touching this module's callers. No `amazonaws.com` is
 * hardcoded outside {@link awsHost}. Region still drives SigV4 signing.
 *
 * Unlike Azure (SAS in the query → simple GET, no preflight), S3 browse uses
 * SigV4 **header** auth, so the browser DOES issue a CORS preflight — the S3 CORS
 * remediation panel accounts for that (it must allow the `authorization` /
 * `x-amz-*` headers).
 */

/** RFC-3986 encoding (matches the SigV4 canonicaliser so signed URLs round-trip). */
function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/** Percent-encode an object key path once, per segment (never touching `/`). */
export function encodeKeyPath(key: string): string {
  return key
    .split('/')
    .map((seg) => encodeRfc3986(seg))
    .join('/');
}

export interface S3Target {
  region: string;
  bucket: string;
  /** S3-compatible endpoint host override (GCS-interop seam); absent ⇒ AWS default. */
  endpoint?: string;
}

/** S3's max page size for ListObjectsV2 (Azure's is 5000; S3 caps at 1000). */
export const LIST_OBJECTS_MAX_KEYS = 1000;

/** The default AWS virtual-hosted host for a bucket + region. */
function awsHost(bucket: string, region: string): string {
  return `${bucket}.s3.${region}.amazonaws.com`;
}

/** The request host for a target: the endpoint override (virtual-hosted) or AWS default. */
export function s3Host(target: S3Target): string {
  const bucket = target.bucket.trim();
  if (target.endpoint) {
    // Virtual-hosted against the override host, e.g. `bucket.storage.googleapis.com`.
    return `${bucket}.${target.endpoint.trim().replace(/^https?:\/\//i, '').replace(/\/$/, '')}`;
  }
  return awsHost(bucket, target.region.trim());
}

export function bucketBaseUrl(target: S3Target): string {
  return `https://${s3Host(target)}`;
}

export interface ListObjectsParams {
  prefix?: string;
  /** Opaque `NextContinuationToken` from the previous page. */
  continuationToken?: string;
  /** `/` gives virtual folders (CommonPrefixes). Default `/`. */
  delimiter?: string;
  maxKeys?: number;
}

/** Build a query string with RFC-3986 encoding + sorted keys (avoids `+`-for-space). */
function buildQuery(params: Record<string, string>): string {
  return Object.keys(params)
    .sort()
    .map((k) => `${encodeRfc3986(k)}=${encodeRfc3986(params[k])}`)
    .join('&');
}

/**
 * ListObjectsV2 URL (slice 14 browse). `list-type=2` selects V2; folders come
 * from `delimiter=/`. Auth is NOT in the query (SigV4 header auth) — the signer
 * adds the `Authorization` / `x-amz-*` headers.
 */
export function listObjectsV2Url(target: S3Target, params: ListObjectsParams = {}): string {
  const query: Record<string, string> = {
    'list-type': '2',
    delimiter: params.delimiter ?? '/',
    'max-keys': String(params.maxKeys ?? LIST_OBJECTS_MAX_KEYS),
  };
  if (params.prefix) {
    query['prefix'] = params.prefix;
  }
  if (params.continuationToken) {
    query['continuation-token'] = params.continuationToken;
  }
  return `${bucketBaseUrl(target)}/?${buildQuery(query)}`;
}

/** `https://{host}/{key}` — one object resource (HEAD / GET). */
export function objectUrl(target: S3Target, key: string): string {
  return `${bucketBaseUrl(target)}/${encodeKeyPath(key)}`;
}

/** `https://{host}/{key}?restore` — the RestoreObject (rehydrate) POST target. */
export function restoreObjectUrl(target: S3Target, key: string): string {
  return `${objectUrl(target, key)}?restore`;
}
