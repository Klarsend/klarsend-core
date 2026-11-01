/**
 * S3 multipart REST URL construction (slice 21). These URLs are hit **directly
 * from the browser against the customer's bucket** — never through the Klarsend
 * API (the slice's posture: zero new API surface). Auth is SigV4 HEADER auth
 * exactly as browse (slice 14) — nothing sensitive ever rides in these URLs;
 * the `uploadId` is not a credential (it is useless without a signature).
 *
 * Query keys are RFC-3986-encoded and sorted, matching the SigV4 canonicaliser
 * AND the AWS SDK's own querystring builder — the SDK-equality spec pins our
 * URLs byte-for-byte against captured `@aws-sdk/client-s3` requests (modulo the
 * SDK's non-protocol `x-id` marker).
 */
import { objectUrl, type S3Target } from '../s3-urls';

/** ListParts' server-side page cap; reconciliation pages with `part-number-marker`. */
export const LIST_PARTS_MAX_PARTS = 1000;

/** RFC-3986 encoding (matches the SigV4 canonicaliser so signed URLs round-trip). */
function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/** Sorted, RFC-3986-encoded query — `''` values keep a bare `key=` (SDK-identical). */
function buildQuery(params: Record<string, string>): string {
  return Object.keys(params)
    .sort()
    .map((k) => `${encodeRfc3986(k)}=${encodeRfc3986(params[k])}`)
    .join('&');
}

/** `POST {key}?uploads=` — CreateMultipartUpload. */
export function createMultipartUploadUrl(target: S3Target, key: string): string {
  return `${objectUrl(target, key)}?${buildQuery({ uploads: '' })}`;
}

/** `PUT {key}?partNumber=N&uploadId=…` — UploadPart. */
export function uploadPartUrl(
  target: S3Target,
  key: string,
  partNumber: number,
  uploadId: string,
): string {
  return `${objectUrl(target, key)}?${buildQuery({ partNumber: String(partNumber), uploadId })}`;
}

/** `POST {key}?uploadId=…` — CompleteMultipartUpload. */
export function completeMultipartUploadUrl(
  target: S3Target,
  key: string,
  uploadId: string,
): string {
  return `${objectUrl(target, key)}?${buildQuery({ uploadId })}`;
}

/** `DELETE {key}?uploadId=…` — AbortMultipartUpload. */
export function abortMultipartUploadUrl(target: S3Target, key: string, uploadId: string): string {
  return `${objectUrl(target, key)}?${buildQuery({ uploadId })}`;
}

/** `GET {key}?uploadId=…&max-parts=…[&part-number-marker=…]` — ListParts. */
export function listPartsUrl(
  target: S3Target,
  key: string,
  uploadId: string,
  partNumberMarker?: string,
): string {
  const params: Record<string, string> = {
    uploadId,
    'max-parts': String(LIST_PARTS_MAX_PARTS),
  };
  if (partNumberMarker) {
    params['part-number-marker'] = partNumberMarker;
  }
  return `${objectUrl(target, key)}?${buildQuery(params)}`;
}
