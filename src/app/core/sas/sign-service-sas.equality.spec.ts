/**
 * THE VALIDATION GATE FOR THIS SLICE (spec §3.1 #6, build plan Week 3).
 *
 * Our client-side service-SAS signer must produce **byte-for-byte identical**
 * tokens to the official Azure SDK for the same inputs. String-to-sign
 * construction is notoriously fiddly (field order, empty-field newlines,
 * canonicalized-resource format, permission canonicalisation, date truncation,
 * query field order + percent-encoding) — so these SDK-equality assertions ARE
 * the KATs, and they are written before/with the implementation.
 *
 * `@azure/storage-blob` is a **dev dependency used only here** (a test oracle);
 * the bundle check (sign-service-sas.bundle.spec) proves it never ships. This
 * file runs in the `core` project (Node), the only place the Node-only
 * `StorageSharedKeyCredential` works.
 *
 * Matrix (per the slice's stated gate): scope (blob/container) × expiry × start
 * set/unset × permissions × content-disposition set/unset × IP-range set/unset ×
 * protocol.
 */
import {
  BlobSASPermissions,
  ContainerSASPermissions,
  generateBlobSASQueryParameters,
  SASProtocol,
  StorageSharedKeyCredential,
} from '@azure/storage-blob';
import { describe, expect, it } from 'vitest';

import { SIGNED_SAS_VERSION, signServiceSasToken, type ServiceSasInput } from './sign-service-sas';

const ACCOUNT = 'clientmasters';
// A well-formed but throwaway base64 account key — NOT a real credential.
const ACCOUNT_KEY = btoa('klarsend-sdk-equality-fixture-key-vector-00000000');

interface Case {
  name: string;
  containerName: string;
  blobName?: string;
  permissions: string;
  startsOn?: Date;
  expiresOn: Date;
  protocol?: 'https' | 'https,http';
  ipStart?: string;
  ipEnd?: string;
  contentDisposition?: string;
}

const D = (iso: string) => new Date(iso);

const CASES: Case[] = [
  {
    name: 'blob read, expiry only',
    containerName: 'deliverables',
    blobName: 'reel1/master.mov',
    permissions: 'r',
    expiresOn: D('2027-03-14T18:30:00Z'),
  },
  {
    name: 'blob read, with start time',
    containerName: 'deliverables',
    blobName: 'reel1/master.mov',
    permissions: 'r',
    startsOn: D('2026-03-14T10:30:00Z'),
    expiresOn: D('2027-03-14T18:30:00Z'),
  },
  {
    name: 'blob read, short (1h) expiry',
    containerName: 'deliverables',
    blobName: 'audio/stem-01.wav',
    permissions: 'r',
    expiresOn: D('2026-07-10T13:00:00Z'),
  },
  {
    name: 'blob read, https+http protocol',
    containerName: 'deliverables',
    blobName: 'reel1/master.mov',
    permissions: 'r',
    expiresOn: D('2027-03-14T18:30:00Z'),
    protocol: 'https,http',
  },
  {
    name: 'blob read, content-disposition (attachment filename)',
    containerName: 'deliverables',
    blobName: 'reel1/master.mov',
    permissions: 'r',
    expiresOn: D('2027-03-14T18:30:00Z'),
    contentDisposition: 'attachment; filename="Acme Master v2.mov"',
  },
  {
    name: 'blob read, single-IP range',
    containerName: 'deliverables',
    blobName: 'reel1/master.mov',
    permissions: 'r',
    expiresOn: D('2027-03-14T18:30:00Z'),
    ipStart: '203.0.113.5',
  },
  {
    name: 'blob read, IP range span',
    containerName: 'deliverables',
    blobName: 'reel1/master.mov',
    permissions: 'r',
    expiresOn: D('2027-03-14T18:30:00Z'),
    ipStart: '203.0.113.0',
    ipEnd: '203.0.113.255',
  },
  {
    name: 'blob read, everything at once (start+proto+ip+disposition)',
    containerName: 'deliverables',
    blobName: 'reel1/deep/nested path/master (final).mov',
    permissions: 'r',
    startsOn: D('2026-07-10T12:00:00Z'),
    expiresOn: D('2026-07-17T12:00:00Z'),
    protocol: 'https',
    ipStart: '198.51.100.10',
    ipEnd: '198.51.100.20',
    contentDisposition: 'attachment; filename="master.mov"',
  },
  {
    name: 'blob read+write permissions (canonicalisation, non-alpha-order input)',
    containerName: 'deliverables',
    blobName: 'reel1/master.mov',
    permissions: 'wr',
    expiresOn: D('2027-03-14T18:30:00Z'),
  },
  {
    name: 'container read+list (the browse SAS the app self-mints)',
    containerName: 'deliverables',
    permissions: 'rl',
    expiresOn: D('2026-07-10T13:00:00Z'),
  },
  {
    name: 'container read+list, permissions given out of canonical order (lr)',
    containerName: 'deliverables',
    permissions: 'lr',
    startsOn: D('2026-07-10T12:00:00Z'),
    expiresOn: D('2026-07-10T13:00:00Z'),
  },
];

function sdkToken(c: Case): string {
  const cred = new StorageSharedKeyCredential(ACCOUNT, ACCOUNT_KEY);
  const permissions = c.blobName
    ? BlobSASPermissions.parse(c.permissions)
    : ContainerSASPermissions.parse(c.permissions);
  return generateBlobSASQueryParameters(
    {
      version: SIGNED_SAS_VERSION,
      containerName: c.containerName,
      blobName: c.blobName,
      permissions,
      startsOn: c.startsOn,
      expiresOn: c.expiresOn,
      protocol: c.protocol as SASProtocol | undefined,
      ipRange: c.ipStart ? { start: c.ipStart, end: c.ipEnd } : undefined,
      contentDisposition: c.contentDisposition,
    },
    cred,
  ).toString();
}

function ourToken(c: Case): Promise<string> {
  const input: ServiceSasInput = {
    accountName: ACCOUNT,
    containerName: c.containerName,
    blobName: c.blobName,
    permissions: c.permissions,
    startsOn: c.startsOn,
    expiresOn: c.expiresOn,
    protocol: c.protocol,
    ipRange: c.ipStart ? { start: c.ipStart, end: c.ipEnd } : undefined,
    contentDisposition: c.contentDisposition,
  };
  return signServiceSasToken(input, ACCOUNT_KEY);
}

describe('signServiceSasToken — byte-for-byte SDK equality', () => {
  it('pins the service version we implement', () => {
    expect(SIGNED_SAS_VERSION).toBe('2026-06-06');
  });

  for (const c of CASES) {
    it(`matches @azure/storage-blob exactly: ${c.name}`, async () => {
      const [mine, sdk] = await Promise.all([ourToken(c), Promise.resolve(sdkToken(c))]);
      expect(mine).toBe(sdk);
    });
  }

  it('is not vacuous: a wrong key produces a DIFFERENT token', async () => {
    const c = CASES[0];
    const wrong = await signServiceSasToken(
      { accountName: ACCOUNT, containerName: c.containerName, blobName: c.blobName, permissions: c.permissions, expiresOn: c.expiresOn },
      btoa('a-different-fixture-key-000000000000000000000000'),
    );
    expect(wrong).not.toBe(sdkToken(c));
  });
});
