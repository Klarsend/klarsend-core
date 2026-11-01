/**
 * Client-side AWS **Signature Version 4** signer (slice 14, S3 connect + browse).
 * Signs S3 REST requests **entirely in the browser** by HMAC-SHA256'ing the SigV4
 * string-to-sign with a signing key derived from the secret access key, via
 * WebCrypto (CLAUDE.md invariant 4 — no home-rolled primitives; this is key
 * *management* around published primitives, the same posture as the Azure SAS
 * signer in core/sas).
 *
 * SECURITY (CLAUDE.md invariants 1, 2, 7): the secret access key and the derived
 * signing key are key material. They are used only here, only client-side; they
 * never reach our API and are never logged. The request carries only the derived
 * `Authorization` signature — never the secret (an STS `sessionToken` is a
 * separate, non-secret-in-the-same-sense token AWS itself puts on the wire). The
 * canary suite (sigv4.canary.spec) pins that the secret never appears in output.
 *
 * CORRECTNESS. SigV4 canonical-request construction is notoriously fiddly (URI
 * encoding, header lowercasing/trimming/ordering, query sorting, payload hashing,
 * the key-derivation chain). The KAT suite (sigv4.equality.spec) is the source of
 * truth: it pins the published AWS `get-vanilla` vector AND byte-compares against
 * the reference `@smithy/signature-v4` SDK across a real ListObjectsV2 / object
 * matrix. Do not change encoding, field order, or the signed-header set without
 * re-running it.
 *
 * S3 vs generic AWS. S3 is the documented exception to two canonicalisation rules:
 * it URI-encodes the path only ONCE (generic AWS double-encodes) and does NOT
 * normalise dot-segments. `uriEscapePath: false` selects the S3 behaviour; the
 * default (true) is the generic behaviour the published test vectors use.
 *
 * SLICE SCOPE: this signs API requests via the `Authorization` header (what
 * ListObjectsV2 / HeadObject / RestoreObject need). Presigned-URL query signing
 * (slice 15) reuses the same {@link deriveSigningKey} + canonical core; it is not
 * built here, but the primitives are factored so it can be.
 */
import { toHex, utf8Encode } from '../vault-crypto/encoding';

/** The empty-payload SHA-256, the payload hash for a body-less request (e.g. a GET). */
export const EMPTY_PAYLOAD_SHA256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const ALGORITHM = 'AWS4-HMAC-SHA256';

export interface SigV4Credentials {
  accessKeyId: string;
  /** Secret access key — KEY MATERIAL. Used only to derive the signing key here. */
  secretAccessKey: string;
  /** STS session token, when the credentials are temporary. Signed + sent as-is. */
  sessionToken?: string;
}

export interface SigV4Request {
  method: string;
  /** Absolute URL: protocol + host + path + query. */
  url: string;
  /** Extra headers to sign (host/x-amz-* are added here). Names are case-insensitive. */
  headers?: Record<string, string>;
  /** Raw request body for the payload hash; absent ⇒ empty payload. */
  body?: Uint8Array;
}

export interface SigV4Options {
  region: string;
  service: string;
  credentials: SigV4Credentials;
  /** The signing instant (`x-amz-date`); injected so signing is deterministic/testable. */
  signingDate: Date;
  /**
   * `false` ⇒ S3 rules: encode the path once, no dot-segment normalisation.
   * `true` (default) ⇒ generic AWS rules (double-encode + normalise).
   */
  uriEscapePath?: boolean;
  /**
   * Add and sign `x-amz-content-sha256` (S3 requires it). Default `true`. The
   * published generic vectors (get-vanilla) do not include it, so they set `false`.
   */
  addContentSha256Header?: boolean;
}

/** RFC-3986 encoding: percent-encode everything `encodeURIComponent` leaves (`!'()*`) too. */
function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/** Encode a URI path segment-by-segment (never touching `/`), once or twice. */
function canonicalUri(pathname: string, uriEscapePath: boolean): string {
  if (pathname === '' || pathname === '/') {
    return '/';
  }
  const encodeSegment = (seg: string): string => {
    // Decode first so encoding is idempotent regardless of whether the caller's
    // URL already percent-encoded the segment (a browser `URL` always does): we
    // re-encode from the raw value, exactly as the AWS SDK canonicalises.
    const once = encodeRfc3986(decodeURIComponent(seg));
    // Generic AWS double-encodes each segment; S3 encodes once.
    return uriEscapePath ? encodeRfc3986(once) : once;
  };
  return pathname
    .split('/')
    .map(encodeSegment)
    .join('/');
}

/** Sorted, RFC-3986-encoded `k=v&k=v` query string (SigV4 canonical query). */
function canonicalQuery(search: string): string {
  const raw = search.startsWith('?') ? search.slice(1) : search;
  if (!raw) {
    return '';
  }
  const pairs: Array<[string, string]> = [];
  for (const part of raw.split('&')) {
    if (!part) {
      continue;
    }
    const eq = part.indexOf('=');
    const key = eq < 0 ? part : part.slice(0, eq);
    const val = eq < 0 ? '' : part.slice(eq + 1);
    // Re-encode from the decoded form so our encoding is canonical regardless of
    // how the caller encoded it. `+` in a query is a literal plus for SigV4.
    pairs.push([encodeRfc3986(decodeURIComponent(key)), encodeRfc3986(decodeURIComponent(val))]);
  }
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
}

interface CanonicalHeaders {
  canonical: string;
  signed: string;
}

/** Lowercase names, trim values, sort by name → the canonical headers block + signed list. */
function canonicalHeaders(headers: Record<string, string>): CanonicalHeaders {
  const entries = Object.entries(headers).map(
    ([name, value]) => [name.toLowerCase(), value.trim().replace(/\s+/g, ' ')] as const,
  );
  entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const canonical = entries.map(([name, value]) => `${name}:${value}\n`).join('');
  const signed = entries.map(([name]) => name).join(';');
  return { canonical, signed };
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data as unknown as ArrayBuffer);
  return toHex(new Uint8Array(digest));
}

async function hmac(key: Uint8Array, message: string): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as unknown as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', cryptoKey, utf8Encode(message) as unknown as ArrayBuffer);
  return new Uint8Array(mac);
}

/**
 * The SigV4 key-derivation chain (shared with presigning, slice 15):
 * `kDate = HMAC("AWS4"+secret, date)` → region → service → `"aws4_request"`.
 * The secret access key enters only here and only as HMAC key material.
 */
export async function deriveSigningKey(
  secretAccessKey: string,
  dateStamp: string,
  region: string,
  service: string,
): Promise<Uint8Array> {
  const kDate = await hmac(utf8Encode(`AWS4${secretAccessKey}`), dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

/** `YYYYMMDDTHHMMSSZ` (x-amz-date); its first 8 chars are the credential-scope date. */
export function amzDate(date: Date): string {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

export interface CanonicalParts {
  canonicalRequest: string;
  signedHeaders: string;
  stringToSign: string;
  credentialScope: string;
  amzDate: string;
  headers: Record<string, string>;
  payloadHash: string;
}

/**
 * Build every SigV4 intermediate for a request, short of the final signature —
 * exported so the KAT suite can pin the canonical request and string-to-sign
 * directly (the fiddly bits), independent of the signature.
 */
export async function canonicalParts(
  req: SigV4Request,
  opts: SigV4Options,
): Promise<CanonicalParts> {
  const url = new URL(req.url);
  const uriEscapePath = opts.uriEscapePath ?? true;
  const addContentSha = opts.addContentSha256Header ?? true;
  const stamp = amzDate(opts.signingDate);
  const dateStamp = stamp.slice(0, 8);
  const credentialScope = `${dateStamp}/${opts.region}/${opts.service}/aws4_request`;

  const payloadHash = req.body ? await sha256Hex(req.body) : EMPTY_PAYLOAD_SHA256;

  // Assemble the headers we sign: caller headers + host + x-amz-date (+ content
  // hash for S3, + security token for STS). All are signed.
  const headers: Record<string, string> = { ...req.headers, host: url.host, 'x-amz-date': stamp };
  if (addContentSha) {
    headers['x-amz-content-sha256'] = payloadHash;
  }
  if (opts.credentials.sessionToken) {
    headers['x-amz-security-token'] = opts.credentials.sessionToken;
  }

  const { canonical, signed } = canonicalHeaders(headers);
  const canonicalRequest = [
    req.method.toUpperCase(),
    canonicalUri(url.pathname, uriEscapePath),
    canonicalQuery(url.search),
    canonical,
    signed,
    payloadHash,
  ].join('\n');

  const stringToSign = [
    ALGORITHM,
    stamp,
    credentialScope,
    await sha256Hex(utf8Encode(canonicalRequest)),
  ].join('\n');

  return {
    canonicalRequest,
    signedHeaders: signed,
    stringToSign,
    credentialScope,
    amzDate: stamp,
    headers,
    payloadHash,
  };
}

/**
 * Sign a request and return the headers to ADD to it: `Authorization`,
 * `x-amz-date`, `x-amz-content-sha256` (S3), and `x-amz-security-token` (STS).
 * The caller merges these into the outbound request. Byte-for-byte compatible
 * with `@smithy/signature-v4` in the matching mode (pinned by the KAT suite).
 */
export async function signSigV4(
  req: SigV4Request,
  opts: SigV4Options,
): Promise<Record<string, string>> {
  const parts = await canonicalParts(req, opts);
  const dateStamp = parts.amzDate.slice(0, 8);
  const signingKey = await deriveSigningKey(
    opts.credentials.secretAccessKey,
    dateStamp,
    opts.region,
    opts.service,
  );
  const signature = toHex(await hmac(signingKey, parts.stringToSign));
  const authorization =
    `${ALGORITHM} Credential=${opts.credentials.accessKeyId}/${parts.credentialScope}, ` +
    `SignedHeaders=${parts.signedHeaders}, Signature=${signature}`;

  const out: Record<string, string> = {
    Authorization: authorization,
    'x-amz-date': parts.amzDate,
  };
  if (parts.headers['x-amz-content-sha256']) {
    out['x-amz-content-sha256'] = parts.headers['x-amz-content-sha256'];
  }
  if (opts.credentials.sessionToken) {
    out['x-amz-security-token'] = opts.credentials.sessionToken;
  }
  return out;
}

// ── Query-parameter presigning (slice 15, S3 presigned GET links) ─────────────
//
// A DISTINCT construction from the header-auth path above, sharing this module's
// key-derivation chain and canonicalisers. Differences an S3 presigned GET makes:
//   • the auth travels as `X-Amz-*` QUERY parameters, not an `Authorization`
//     header — so the URL alone is a bearer credential (that's the point);
//   • `SignedHeaders=host` ONLY (the recipient's browser sends nothing else we
//     control), so the canonical-headers block is just `host:…`;
//   • the payload hash is the literal {@link UNSIGNED_PAYLOAD} sentinel, never a
//     body digest (the signer never sees the object bytes);
//   • lifetime is `X-Amz-Expires` seconds from `X-Amz-Date`, capped by AWS at 7
//     days — the cap is enforced by the S3 wrapper, not here.
// Every query param present at signing time is folded into the signature; S3
// REJECTS `response-*` overrides that aren't signed, so the caller's extras
// (e.g. `response-content-disposition`) go in BEFORE we sign. `X-Amz-Signature`
// is the sole param not in the canonical query — it is appended last.
//
// Byte-for-byte compatible with `@smithy/signature-v4`'s `.presign()` (pinned by
// sigv4.presign.equality.spec). `@aws-sdk/s3-request-presigner` is that same call
// plus a non-signing `x-id=GetObject` marker added by client middleware.

/** The S3 presign payload-hash sentinel — the signer never hashes object bytes. */
export const UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD';

export interface PresignOptions {
  region: string;
  service: string;
  credentials: SigV4Credentials;
  /** The signing instant (`X-Amz-Date`); injected so signing is deterministic/testable. */
  signingDate: Date;
  /** Link lifetime in seconds (`X-Amz-Expires`). The caller enforces any max. */
  expiresInSeconds: number;
  /** `false` ⇒ S3 rules (single-encode path, no dot-segment normalise). Default `true`. */
  uriEscapePath?: boolean;
  /** Extra query params folded INTO the signature (e.g. `response-content-disposition`). */
  extraQuery?: Record<string, string>;
}

export interface PresignParts {
  canonicalRequest: string;
  stringToSign: string;
  credentialScope: string;
  amzDate: string;
  signature: string;
  /** The full signed URL: base + canonical query + `&X-Amz-Signature=…`. */
  url: string;
}

/**
 * Build every presign intermediate for `baseUrl` (a bare object URL, no query),
 * short of nothing — exported so the KAT suite can pin the canonical request and
 * string-to-sign directly (the fiddly bits) against the published AWS vector.
 */
export async function presignParts(baseUrl: string, opts: PresignOptions): Promise<PresignParts> {
  const url = new URL(baseUrl);
  const uriEscapePath = opts.uriEscapePath ?? true;
  const stamp = amzDate(opts.signingDate);
  const dateStamp = stamp.slice(0, 8);
  const credentialScope = `${dateStamp}/${opts.region}/${opts.service}/aws4_request`;

  // Only `host` is signed for a presigned GET.
  const { canonical: headerBlock, signed: signedHeaders } = canonicalHeaders({ host: url.host });

  const queryParams: Record<string, string> = {
    'X-Amz-Algorithm': ALGORITHM,
    'X-Amz-Credential': `${opts.credentials.accessKeyId}/${credentialScope}`,
    'X-Amz-Date': stamp,
    'X-Amz-Expires': String(opts.expiresInSeconds),
    'X-Amz-SignedHeaders': signedHeaders,
    ...opts.extraQuery,
  };
  if (opts.credentials.sessionToken) {
    queryParams['X-Amz-Security-Token'] = opts.credentials.sessionToken;
  }

  // Pre-encode each pair (so values carrying `=`/`&`/spaces survive the split),
  // then run it through the shared canonicaliser: sort + RFC-3986 exactly as the
  // signed-header path does. The result is the canonical query AND the query we
  // put on the wire (minus the signature).
  const preEncoded = Object.entries(queryParams)
    .map(([k, v]) => `${encodeRfc3986(k)}=${encodeRfc3986(v)}`)
    .join('&');
  const canonicalQs = canonicalQuery(preEncoded);

  const canonicalRequest = [
    'GET',
    canonicalUri(url.pathname, uriEscapePath),
    canonicalQs,
    headerBlock,
    signedHeaders,
    UNSIGNED_PAYLOAD,
  ].join('\n');

  const stringToSign = [
    ALGORITHM,
    stamp,
    credentialScope,
    await sha256Hex(utf8Encode(canonicalRequest)),
  ].join('\n');

  const signingKey = await deriveSigningKey(
    opts.credentials.secretAccessKey,
    dateStamp,
    opts.region,
    opts.service,
  );
  const signature = toHex(await hmac(signingKey, stringToSign));

  return {
    canonicalRequest,
    stringToSign,
    credentialScope,
    amzDate: stamp,
    signature,
    url: `${url.origin}${url.pathname}?${canonicalQs}&X-Amz-Signature=${signature}`,
  };
}

/**
 * Presign `baseUrl` (a bare object URL) into a query-authenticated, time-limited
 * GET URL. The secret access key enters only the key-derivation chain and never
 * reaches the URL — only the derived `X-Amz-Signature` does (an STS
 * `X-Amz-Security-Token` AWS itself puts on the wire is the one non-secret token).
 * The presign canary suite pins that the secret never appears in the output.
 */
export async function presignQueryUrl(baseUrl: string, opts: PresignOptions): Promise<string> {
  return (await presignParts(baseUrl, opts)).url;
}
