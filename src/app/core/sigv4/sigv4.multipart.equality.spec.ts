/**
 * THE VALIDATION GATE FOR MULTIPART-UPLOAD SIGNING (slice 21; CLAUDE.md
 * test-vectors-first rule — written before the upload client went live). The
 * slice-14 KAT matrix covered browse's GET/HEAD/POST shapes; multipart adds the
 * shapes that weren't exercised yet, each byte-compared against the reference
 * `@smithy/signature-v4` SDK:
 *
 *   • CreateMultipartUpload — the `?uploads=` EMPTY-VALUED query param;
 *   • UploadPart            — a signed REAL BODY (x-amz-content-sha256 over the
 *                             part bytes) + a signed `content-md5` header, and
 *                             the `partNumber`/`uploadId` query pair;
 *   • CompleteMultipartUpload — the fiddly one: the XML body's hash, the signed
 *                             `content-type` and conditional (`if-none-match`/
 *                             `if-match`) headers;
 *   • AbortMultipartUpload  — DELETE with `uploadId`;
 *   • ListParts             — GET with `uploadId` + paging params;
 *   plus STS session-token variants of the part/complete calls.
 *
 * URLs come from the REAL multipart-urls builders (not re-derived here), so the
 * gate covers exactly what the client signs. `@smithy/*` / `@aws-crypto/*` stay
 * DEV-ONLY oracles (sigv4.bundle.spec proves they never ship).
 */
import { Sha256 } from '@aws-crypto/sha256-js';
import { HttpRequest } from '@smithy/protocol-http';
import { SignatureV4 } from '@smithy/signature-v4';
import { describe, expect, it } from 'vitest';

import { completeMultipartXml } from '../s3/upload/complete-multipart-xml';
import {
  abortMultipartUploadUrl,
  completeMultipartUploadUrl,
  createMultipartUploadUrl,
  listPartsUrl,
  uploadPartUrl,
} from '../s3/upload/multipart-urls';
import { type S3Target } from '../s3/s3-urls';
import { signSigV4, type SigV4Credentials } from './sigv4';

const S3_CREDS: SigV4Credentials = {
  // Well-formed but throwaway — NOT real credentials.
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};
const STS_CREDS: SigV4Credentials = {
  ...S3_CREDS,
  sessionToken: 'FQoGZXIvYXdzEBcaDNTESTSESSIONTOKEN//////////wEXAMPLE=',
};
const TARGET: S3Target = { region: 'eu-west-1', bucket: 'client-masters' };
const KEY = 'masters/reel 1/mixé final.mov'; // space + unicode — encoding must agree
const UPLOAD_ID = 'VXBsb2FkSWQrd2l0aC9zcGVjaWFsPWNoYXJz.1234-abc_(final)*';
const SIGNING_DATE = new Date('2015-08-30T12:36:00Z');

const PART_BYTES = Uint8Array.from({ length: 64 }, (_, i) => (i * 7 + 3) % 251);
const PART_MD5 = 'q0Cyr9lVdNQPPvyoLZLU7g=='; // stand-in; any header value must sign identically
const COMPLETE_XML = completeMultipartXml([
  { partNumber: 1, etag: '"9bb58f26192e4ba00f01e2e7b136bbd8"' },
  { partNumber: 2, etag: '"5d41402abc4b2a76b9719d911017c592"' },
]);

interface MultipartCase {
  name: string;
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: Uint8Array;
  creds: SigV4Credentials;
}

const CASES: MultipartCase[] = [
  {
    name: 'CreateMultipartUpload (?uploads= empty-valued param, signed content-type)',
    method: 'POST',
    url: createMultipartUploadUrl(TARGET, KEY),
    headers: { 'content-type': 'video/quicktime' },
    creds: S3_CREDS,
  },
  {
    name: 'UploadPart (real body hash + signed content-md5)',
    method: 'PUT',
    url: uploadPartUrl(TARGET, KEY, 3, UPLOAD_ID),
    headers: { 'content-md5': PART_MD5 },
    body: PART_BYTES,
    creds: S3_CREDS,
  },
  {
    name: 'UploadPart with STS session-token credentials',
    method: 'PUT',
    url: uploadPartUrl(TARGET, KEY, 8941, UPLOAD_ID),
    headers: { 'content-md5': PART_MD5 },
    body: PART_BYTES,
    creds: STS_CREDS,
  },
  {
    name: 'CompleteMultipartUpload (XML body hash + if-none-match: *)',
    method: 'POST',
    url: completeMultipartUploadUrl(TARGET, KEY, UPLOAD_ID),
    headers: { 'content-type': 'application/xml', 'if-none-match': '*' },
    body: new TextEncoder().encode(COMPLETE_XML),
    creds: S3_CREDS,
  },
  {
    name: 'CompleteMultipartUpload (confirmed replace: if-match pinned ETag, STS)',
    method: 'POST',
    url: completeMultipartUploadUrl(TARGET, KEY, UPLOAD_ID),
    headers: { 'content-type': 'application/xml', 'if-match': '"0x8DD00AA11BB22CC"' },
    body: new TextEncoder().encode(COMPLETE_XML),
    creds: STS_CREDS,
  },
  {
    name: 'AbortMultipartUpload (DELETE ?uploadId)',
    method: 'DELETE',
    url: abortMultipartUploadUrl(TARGET, KEY, UPLOAD_ID),
    creds: S3_CREDS,
  },
  {
    name: 'ListParts (GET ?uploadId&max-parts, first page)',
    method: 'GET',
    url: listPartsUrl(TARGET, KEY, UPLOAD_ID),
    creds: S3_CREDS,
  },
  {
    name: 'ListParts (later page: part-number-marker)',
    method: 'GET',
    url: listPartsUrl(TARGET, KEY, UPLOAD_ID, '2000'),
    creds: S3_CREDS,
  },
];

/** Split one of OUR urls into what @smithy's HttpRequest wants (path + query map). */
function toSdkRequest(c: MultipartCase): HttpRequest {
  const url = new URL(c.url);
  const query: Record<string, string> = {};
  for (const pair of url.search.replace(/^\?/, '').split('&')) {
    if (!pair) {
      continue;
    }
    const eq = pair.indexOf('=');
    const k = decodeURIComponent(eq < 0 ? pair : pair.slice(0, eq));
    query[k] = decodeURIComponent(eq < 0 ? '' : pair.slice(eq + 1));
  }
  return new HttpRequest({
    method: c.method,
    protocol: 'https:',
    hostname: url.host,
    // The builders pre-encode the key; the SDK signs the encoded path verbatim
    // in S3 mode (uriEscapePath: false) — mirror that so the oracle is faithful.
    path: url.pathname,
    query,
    headers: { host: url.host, ...(c.headers ?? {}) },
    ...(c.body ? { body: c.body } : {}),
  });
}

async function sdkHeaders(c: MultipartCase): Promise<Record<string, string>> {
  const signer = new SignatureV4({
    service: 's3',
    region: TARGET.region,
    credentials: c.creds,
    sha256: Sha256,
    uriEscapePath: false, // S3: single-encode path, no normalisation
    applyChecksum: true, // S3: sign x-amz-content-sha256
  });
  const signed = await signer.sign(toSdkRequest(c), { signingDate: SIGNING_DATE });
  return signed.headers;
}

async function ourHeaders(c: MultipartCase): Promise<Record<string, string>> {
  return signSigV4(
    {
      method: c.method,
      url: c.url,
      ...(c.headers ? { headers: c.headers } : {}),
      ...(c.body ? { body: c.body } : {}),
    },
    {
      region: TARGET.region,
      service: 's3',
      credentials: c.creds,
      signingDate: SIGNING_DATE,
      uriEscapePath: false,
      addContentSha256Header: true,
    },
  );
}

describe('signSigV4 — multipart-upload matrix, byte-for-byte @smithy equality', () => {
  for (const c of CASES) {
    it(`matches the reference SDK exactly: ${c.name}`, async () => {
      const [mine, sdk] = await Promise.all([ourHeaders(c), sdkHeaders(c)]);
      // Smithy lowercases header names; compare the values.
      expect(mine['Authorization']).toBe(sdk['authorization']);
      expect(mine['x-amz-date']).toBe(sdk['x-amz-date']);
      expect(mine['x-amz-content-sha256']).toBe(sdk['x-amz-content-sha256']);
      if (c.creds.sessionToken) {
        expect(mine['x-amz-security-token']).toBe(sdk['x-amz-security-token']);
      }
    });
  }

  it('is not vacuous: the Complete body is INSIDE the signature (a changed body re-signs)', async () => {
    const c = CASES[3];
    const [signedA, signedB] = await Promise.all([
      ourHeaders(c),
      ourHeaders({ ...c, body: new TextEncoder().encode(`${COMPLETE_XML} `) }),
    ]);
    expect(signedA['x-amz-content-sha256']).not.toBe(signedB['x-amz-content-sha256']);
    expect(signedA['Authorization']).not.toBe(signedB['Authorization']);
  });
});
