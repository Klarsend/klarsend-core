/**
 * THE VALIDATION GATE FOR THE SIGV4 SIGNER (slice 14; CLAUDE.md test-vectors-first
 * rule — this signer is crypto-adjacent). SigV4 canonical-request construction is
 * fiddly (URI encoding, header ordering, query sorting, payload hashing, the
 * key-derivation chain), so these are the KATs, written with the implementation:
 *
 *   1. The published AWS `get-vanilla` test-suite vector — canonical request and
 *      final Authorization pinned to AWS's own documented expected output.
 *   2. Byte-for-byte equality with the reference `@smithy/signature-v4` SDK (what
 *      the AWS SDK signs with) across a real S3 ListObjectsV2 / object matrix,
 *      including spaces / unicode / `+` keys and STS session-token credentials.
 *
 * `@smithy/*` and `@aws-crypto/*` are DEV-ONLY test oracles (sigv4.bundle.spec
 * proves they never ship). This file runs in the `core` project (Node WebCrypto).
 */
import { Sha256 } from '@aws-crypto/sha256-js';
import { HttpRequest } from '@smithy/protocol-http';
import { SignatureV4 } from '@smithy/signature-v4';
import { describe, expect, it } from 'vitest';

import { canonicalParts, signSigV4, type SigV4Credentials } from './sigv4';

// ── 1. Published AWS test-suite vector: get-vanilla ────────────────────────────
// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
const SUITE_CREDS: SigV4Credentials = {
  accessKeyId: 'AKIDEXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
};
const SUITE_DATE = new Date('2015-08-30T12:36:00Z');

describe('SigV4 — published AWS get-vanilla vector', () => {
  const req = { method: 'GET', url: 'https://example.amazonaws.com/' };
  const opts = {
    region: 'us-east-1',
    service: 'service',
    credentials: SUITE_CREDS,
    signingDate: SUITE_DATE,
    addContentSha256Header: false, // get-vanilla signs only host + x-amz-date
  };

  it('builds the exact published canonical request', async () => {
    const parts = await canonicalParts(req, opts);
    expect(parts.canonicalRequest).toBe(
      'GET\n' +
        '/\n' +
        '\n' +
        'host:example.amazonaws.com\n' +
        'x-amz-date:20150830T123600Z\n' +
        '\n' +
        'host;x-amz-date\n' +
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('produces the exact published Authorization header', async () => {
    const headers = await signSigV4(req, opts);
    expect(headers['Authorization']).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ' +
        'SignedHeaders=host;x-amz-date, ' +
        'Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31',
    );
  });

  it('is not vacuous: a wrong secret key yields a DIFFERENT signature', async () => {
    const headers = await signSigV4(req, {
      ...opts,
      credentials: { ...SUITE_CREDS, secretAccessKey: 'a-different-secret-key-00000000000000000' },
    });
    expect(headers['Authorization']).not.toContain(
      '5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31',
    );
  });
});

// ── 2. Byte-for-byte equality with the reference SDK, in S3 mode ───────────────
const S3_CREDS: SigV4Credentials = {
  // Well-formed but throwaway — NOT real credentials.
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};
const STS_CREDS: SigV4Credentials = {
  ...S3_CREDS,
  sessionToken: 'FQoGZXIvYXdzEBcaDNTESTSESSIONTOKEN//////////wEXAMPLE=',
};
const REGION = 'eu-west-1';
const HOST = 'client-masters.s3.eu-west-1.amazonaws.com';

/** RFC-3986 query encoding (must match the signer + the real S3 URL builder). */
function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/** Percent-encode a raw key path once, per segment — how a real S3 client does it. */
function encodePath(path: string): string {
  return path
    .split('/')
    .map((seg) => encodeRfc3986(seg))
    .join('/');
}

function buildUrl(path: string, query: Record<string, string>): string {
  const qs = Object.entries(query)
    .map(([k, v]) => `${encodeRfc3986(k)}=${encodeRfc3986(v)}`)
    .join('&');
  return `https://${HOST}${encodePath(path)}${qs ? `?${qs}` : ''}`;
}

interface S3Case {
  name: string;
  method: string;
  path: string;
  query: Record<string, string>;
  creds: SigV4Credentials;
}

const S3_CASES: S3Case[] = [
  {
    name: 'ListObjectsV2 at root',
    method: 'GET',
    path: '/',
    query: { 'list-type': '2', delimiter: '/', 'max-keys': '5000' },
    creds: S3_CREDS,
  },
  {
    name: 'ListObjectsV2 with a prefix containing a space',
    method: 'GET',
    path: '/',
    query: { 'list-type': '2', delimiter: '/', prefix: 'reel 1/', 'max-keys': '1000' },
    creds: S3_CREDS,
  },
  {
    name: 'ListObjectsV2 with a continuation token (unsorted params)',
    method: 'GET',
    path: '/',
    query: {
      prefix: 'masters/',
      'list-type': '2',
      'continuation-token': '1ueGcxLPRx1Tr/XYExAmpLe+token==',
      delimiter: '/',
    },
    creds: S3_CREDS,
  },
  {
    name: 'ListObjectsV2 with STS session-token credentials',
    method: 'GET',
    path: '/',
    query: { 'list-type': '2', delimiter: '/' },
    creds: STS_CREDS,
  },
  {
    name: 'HeadObject on a key with unicode + a plus',
    method: 'HEAD',
    path: '/masters/reel1/mixé+final.wav',
    query: {},
    creds: S3_CREDS,
  },
  {
    name: 'RestoreObject POST (?restore) on an archived key with spaces',
    method: 'POST',
    path: '/deep archive/reel 2/master (final).mov',
    query: { restore: '' },
    creds: S3_CREDS,
  },
];

async function sdkAuthorization(c: S3Case): Promise<Record<string, string>> {
  const signer = new SignatureV4({
    service: 's3',
    region: REGION,
    credentials: c.creds,
    sha256: Sha256,
    uriEscapePath: false, // S3: single-encode path, no normalisation
    applyChecksum: true, // S3: sign x-amz-content-sha256
  });
  const signed = await signer.sign(
    new HttpRequest({
      method: c.method,
      protocol: 'https:',
      hostname: HOST,
      // The real @aws-sdk/client-s3 pre-encodes the key into the path and signs
      // it verbatim (uriEscapePath: false); mirror that so the oracle is faithful.
      path: encodePath(c.path),
      query: c.query,
      headers: { host: HOST },
    }),
    { signingDate: SUITE_DATE },
  );
  return signed.headers;
}

async function ourHeaders(c: S3Case): Promise<Record<string, string>> {
  return signSigV4(
    { method: c.method, url: buildUrl(c.path, c.query) },
    {
      region: REGION,
      service: 's3',
      credentials: c.creds,
      signingDate: SUITE_DATE,
      uriEscapePath: false,
      addContentSha256Header: true,
    },
  );
}

describe('signSigV4 — byte-for-byte @smithy/signature-v4 equality (S3 mode)', () => {
  for (const c of S3_CASES) {
    it(`matches the reference SDK exactly: ${c.name}`, async () => {
      const [mine, sdk] = await Promise.all([ourHeaders(c), sdkAuthorization(c)]);
      // Smithy lowercases header names; compare the values.
      expect(mine['Authorization']).toBe(sdk['authorization']);
      expect(mine['x-amz-date']).toBe(sdk['x-amz-date']);
      expect(mine['x-amz-content-sha256']).toBe(sdk['x-amz-content-sha256']);
      if (c.creds.sessionToken) {
        expect(mine['x-amz-security-token']).toBe(sdk['x-amz-security-token']);
      }
    });
  }
});
