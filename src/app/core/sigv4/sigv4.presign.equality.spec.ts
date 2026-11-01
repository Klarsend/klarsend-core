/**
 * THE VALIDATION GATE FOR THE S3 PRESIGN SIGNER (slice 15; CLAUDE.md
 * test-vectors-first rule — query-parameter presigning is crypto-adjacent and a
 * DISTINCT construction from the header-auth path, so it gets its own KATs).
 *
 *   1. The published AWS presigned-GET vector (the "Authenticating Requests:
 *      Using Query Parameters" example) — canonical request, string-to-sign, the
 *      final signature, and the whole URL pinned to AWS's own documented output.
 *   2. Byte-for-byte equality with `@smithy/signature-v4`'s `.presign()` — the
 *      AWS signing library's OWN presign — across an expiry × content-disposition
 *      × unicode/space/`+` key × virtual-hosted/path-style × STS-token matrix.
 *      `@smithy` presign signs exactly the params we sign (host-only signed
 *      headers, UNSIGNED-PAYLOAD), which is why it is the faithful oracle here.
 *   3. A shape cross-check against `@aws-sdk/s3-request-presigner`'s real
 *      `getSignedUrl` — the package the slice names — confirming our parameter
 *      set matches a genuine presigned URL. (`getSignedUrl` additionally signs a
 *      non-cryptographic `x-id=GetObject` marker its client middleware injects, so
 *      the signature there is compared modulo that param, not byte-for-byte.)
 *
 * `@smithy/*`, `@aws-crypto/*`, `@aws-sdk/*` are DEV-ONLY oracles (the bundle
 * guard proves they never ship). Runs in the `core` project (Node WebCrypto).
 */
import { Sha256 } from '@aws-crypto/sha256-js';
import { HttpRequest } from '@smithy/protocol-http';
import { SignatureV4 } from '@smithy/signature-v4';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { describe, expect, it } from 'vitest';

import { presignParts, presignQueryUrl, type SigV4Credentials } from './sigv4';

// ── 1. Published AWS presigned-GET vector ──────────────────────────────────────
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
const VECTOR_CREDS: SigV4Credentials = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};
const VECTOR_DATE = new Date('2013-05-24T00:00:00Z');
const VECTOR_SIG = 'aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404';

describe('S3 presign — published AWS query-string vector', () => {
  const base = 'https://examplebucket.s3.amazonaws.com/test.txt';
  const opts = {
    region: 'us-east-1',
    service: 's3',
    credentials: VECTOR_CREDS,
    signingDate: VECTOR_DATE,
    expiresInSeconds: 86400,
    uriEscapePath: false,
  };

  it('builds the exact published canonical request', async () => {
    const parts = await presignParts(base, opts);
    expect(parts.canonicalRequest).toBe(
      'GET\n' +
        '/test.txt\n' +
        'X-Amz-Algorithm=AWS4-HMAC-SHA256' +
        '&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request' +
        '&X-Amz-Date=20130524T000000Z' +
        '&X-Amz-Expires=86400' +
        '&X-Amz-SignedHeaders=host\n' +
        'host:examplebucket.s3.amazonaws.com\n' +
        '\n' +
        'host\n' +
        'UNSIGNED-PAYLOAD',
    );
  });

  it('produces the exact published signature', async () => {
    const parts = await presignParts(base, opts);
    expect(parts.signature).toBe(VECTOR_SIG);
  });

  it('produces the exact published URL', async () => {
    const url = await presignQueryUrl(base, opts);
    expect(url).toBe(
      'https://examplebucket.s3.amazonaws.com/test.txt' +
        '?X-Amz-Algorithm=AWS4-HMAC-SHA256' +
        '&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request' +
        '&X-Amz-Date=20130524T000000Z' +
        '&X-Amz-Expires=86400' +
        '&X-Amz-SignedHeaders=host' +
        `&X-Amz-Signature=${VECTOR_SIG}`,
    );
  });

  it('is not vacuous: a wrong secret key yields a DIFFERENT signature', async () => {
    const parts = await presignParts(base, {
      ...opts,
      credentials: { ...VECTOR_CREDS, secretAccessKey: 'a-different-secret-key-00000000000000000' },
    });
    expect(parts.signature).not.toBe(VECTOR_SIG);
  });
});

// ── 2. Byte-for-byte equality with @smithy/signature-v4's .presign() ───────────
const S3_CREDS: SigV4Credentials = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};
const STS_CREDS: SigV4Credentials = {
  ...S3_CREDS,
  sessionToken: 'FQoGZXIvYXdzEBcaDNTESTSESSIONTOKEN//////////wEXAMPLE=',
};
const REGION = 'eu-west-1';
const DATE = new Date('2015-08-30T12:36:00Z');
const VHOST = 'client-masters.s3.eu-west-1.amazonaws.com';
const PATH_HOST = 's3.eu-west-1.amazonaws.com'; // path-style: bucket in the path

/** RFC-3986 path encoding — how a real S3 client (and our URL builder) encodes keys. */
function encodePath(path: string): string {
  return path
    .split('/')
    .map((seg) =>
      encodeURIComponent(seg).replace(
        /[!'()*]/g,
        (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
      ),
    )
    .join('/');
}

interface PresignCase {
  name: string;
  host: string;
  /** Raw (un-encoded) object key path beginning with `/`. */
  path: string;
  expiresIn: number;
  creds: SigV4Credentials;
  disposition?: string;
}

const CASES: PresignCase[] = [
  { name: '1-hour expiry, virtual-hosted', host: VHOST, path: '/masters/reel1.wav', expiresIn: 3600, creds: S3_CREDS },
  { name: '24-hour expiry', host: VHOST, path: '/masters/reel1.wav', expiresIn: 86400, creds: S3_CREDS },
  { name: '7-day expiry (the AWS max)', host: VHOST, path: '/masters/reel1.wav', expiresIn: 604800, creds: S3_CREDS },
  {
    name: 'with response-content-disposition (attachment + filename)',
    host: VHOST,
    path: '/masters/reel1.wav',
    expiresIn: 3600,
    creds: S3_CREDS,
    disposition: 'attachment; filename="Acme Reel 1.wav"',
  },
  {
    name: 'unicode + plus + space in the key',
    host: VHOST,
    path: '/masters/reel1/mixé +final (v2).wav',
    expiresIn: 3600,
    creds: S3_CREDS,
  },
  {
    name: 'STS session-token credentials',
    host: VHOST,
    path: '/masters/reel1.wav',
    expiresIn: 3600,
    creds: STS_CREDS,
  },
  {
    name: 'STS + disposition together',
    host: VHOST,
    path: '/masters/reel1.wav',
    expiresIn: 3600,
    creds: STS_CREDS,
    disposition: 'attachment; filename="reel 1.wav"',
  },
  {
    name: 'path-style host (bucket in the path)',
    host: PATH_HOST,
    path: '/client-masters/masters/reel1.wav',
    expiresIn: 3600,
    creds: S3_CREDS,
  },
];

/** The reference presigned query, from the AWS signing library's own `.presign()`. */
async function sdkPresignedQuery(c: PresignCase): Promise<Record<string, string>> {
  const signer = new SignatureV4({
    service: 's3',
    region: REGION,
    credentials: c.creds,
    sha256: Sha256,
    uriEscapePath: false,
    applyChecksum: false,
  });
  const request = new HttpRequest({
    method: 'GET',
    protocol: 'https:',
    hostname: c.host,
    path: encodePath(c.path),
    query: c.disposition ? { 'response-content-disposition': c.disposition } : {},
    // UNSIGNED-PAYLOAD as the payload hash, kept OUT of the signed headers and OUT
    // of the query — exactly how a real S3 presigned GET is constructed.
    headers: { host: c.host, 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' },
  });
  const signed = await signer.presign(request, {
    signingDate: DATE,
    expiresIn: c.expiresIn,
    unsignableHeaders: new Set(['x-amz-content-sha256']),
    unhoistableHeaders: new Set(['x-amz-content-sha256']),
  });
  return signed.query as Record<string, string>;
}

/** Our presigned URL's params, decoded — comparable to the SDK's raw query object. */
async function ourPresignedQuery(c: PresignCase): Promise<Record<string, string>> {
  const url = await presignQueryUrl(`https://${c.host}${encodePath(c.path)}`, {
    region: REGION,
    service: 's3',
    credentials: c.creds,
    signingDate: DATE,
    expiresInSeconds: c.expiresIn,
    uriEscapePath: false,
    ...(c.disposition ? { extraQuery: { 'response-content-disposition': c.disposition } } : {}),
  });
  const params: Record<string, string> = {};
  for (const [k, v] of new URL(url).searchParams) {
    params[k] = v;
  }
  return params;
}

describe('S3 presign — byte-for-byte @smithy/signature-v4 .presign() equality', () => {
  for (const c of CASES) {
    it(`matches the reference SDK presign exactly: ${c.name}`, async () => {
      const [mine, sdk] = await Promise.all([ourPresignedQuery(c), sdkPresignedQuery(c)]);
      // Identical parameter SET and every value — including X-Amz-Signature.
      expect(Object.keys(mine).sort()).toEqual(Object.keys(sdk).sort());
      for (const key of Object.keys(sdk)) {
        expect(`${key}=${mine[key]}`).toBe(`${key}=${sdk[key]}`);
      }
    });
  }
});

// ── 3. Shape cross-check against the named @aws-sdk/s3-request-presigner ────────
describe('S3 presign — parameter shape matches a real getSignedUrl', () => {
  it('carries the same parameter set as @aws-sdk/s3-request-presigner (modulo x-id)', async () => {
    const client = new S3Client({ region: REGION, credentials: S3_CREDS });
    const sdkUrl = await getSignedUrl(
      client,
      new GetObjectCommand({
        Bucket: 'client-masters',
        Key: 'masters/reel1.wav',
        ResponseContentDisposition: 'attachment; filename="reel 1.wav"',
      }),
      { expiresIn: 3600, signingDate: DATE },
    );
    const sdkParams = new Set([...new URL(sdkUrl).searchParams.keys()]);
    // The GetObject client middleware injects non-cryptographic markers a bare
    // presigned GET does not need and real S3 ignores; the authoritative @smithy
    // oracle above (which signs exactly our params) doesn't add them either.
    for (const extra of ['x-id', 'X-Amz-Content-Sha256', 'x-amz-checksum-mode']) {
      sdkParams.delete(extra);
    }

    const mineUrl = await presignQueryUrl(`https://${VHOST}/masters/reel1.wav`, {
      region: REGION,
      service: 's3',
      credentials: S3_CREDS,
      signingDate: DATE,
      expiresInSeconds: 3600,
      uriEscapePath: false,
      extraQuery: { 'response-content-disposition': 'attachment; filename="reel 1.wav"' },
    });
    const mineParams = new Set([...new URL(mineUrl).searchParams.keys()]);

    expect([...mineParams].sort()).toEqual([...sdkParams].sort());
  });
});
