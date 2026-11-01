/**
 * KATs for the consolidated SAS parser (slice 9, Part A). These are the
 * substrate for every expiry/permission surface in the app, so the fixtures are
 * REAL shapes captured from the Azure portal ("Shared access signature" blade
 * and container-SAS dialog) and from `az storage {container,blob} generate-sas`.
 * Account SAS and service SAS differ materially (`srt`+`ss` vs `sr`); az emits a
 * bare token with percent-encoded colons in `se`. Both must parse identically.
 *
 * KATs before implementation (CLAUDE.md invariant 3 posture — this slice is
 * crypto-adjacent): this file pins the contract; the module satisfies it.
 */
import { describe, expect, it } from 'vitest';

import { parseSasUrl } from './parse-sas-url';

// ── Real captured shapes ─────────────────────────────────────────────────────

// Portal → Storage account → Shared access signature (account SAS). Root resource
// `/`, carries `ss` (services) + `srt` (resource types); NO `sr`.
const ACCOUNT_SAS_URL =
  'https://clientmasters.blob.core.windows.net/?sv=2022-11-02&ss=bfqt&srt=sco' +
  '&sp=rwdlacupiytfx&se=2027-03-14T18:30:00Z&st=2026-03-14T10:30:00Z&spr=https' +
  '&sig=Yy%2Fabc123DEF456ghi789%3D';

// Portal → container → Generate SAS (service SAS, container-scoped). `sr=c`, no `srt`.
const CONTAINER_SAS_URL =
  'https://clientmasters.blob.core.windows.net/deliverables?sp=racwdl' +
  '&st=2026-03-14T10:30:00Z&se=2027-03-14T18:30:00Z&spr=https&sv=2022-11-02' +
  '&sr=c&sig=abcDEF123%3D';

// `az storage blob generate-sas` — bare token, no leading `?`, colons in `se`
// percent-encoded, read-only blob scope (`sr=b`).
const AZ_BLOB_SAS_TOKEN =
  'se=2027-03-14T18%3A30%3A00Z&sp=r&sv=2022-11-02&sr=b&sig=Z9x8w7v6%3D';

// Stored-access-policy service SAS: `si` names a server-side policy; `sp`/`se`/`st`
// are all absent (they live with the policy, invisible to us).
const STORED_POLICY_SAS = '?sv=2022-11-02&sr=c&si=readers-2026&sig=onlyASig%3D';

describe('parseSasUrl — account SAS (portal)', () => {
  const p = parseSasUrl(ACCOUNT_SAS_URL);

  it('extracts sv / sp / st / se', () => {
    expect(p.version).toBe('2022-11-02');
    expect(p.permissions).toBe('rwdlacupiytfx');
    expect(p.start?.toISOString()).toBe('2026-03-14T10:30:00.000Z');
    expect(p.expiry?.toISOString()).toBe('2027-03-14T18:30:00.000Z');
  });

  it('has no `sr` (account SAS is not resource-scoped) and reports kind "account"', () => {
    expect(p.resource).toBeNull();
    expect(p.kind).toBe('account');
  });

  it('detects the signature without exposing it as a parsed field', () => {
    expect(p.signaturePresent).toBe(true);
    expect((p as Record<string, unknown>)['signature']).toBeUndefined();
  });
});

describe('parseSasUrl — service SAS (container)', () => {
  const p = parseSasUrl(CONTAINER_SAS_URL);

  it('extracts sr=c and reports kind "service"', () => {
    expect(p.resource).toBe('c');
    expect(p.kind).toBe('service');
  });

  it('extracts permissions and both time bounds', () => {
    expect(p.permissions).toBe('racwdl');
    expect(p.start?.toISOString()).toBe('2026-03-14T10:30:00.000Z');
    expect(p.expiry?.toISOString()).toBe('2027-03-14T18:30:00.000Z');
  });
});

describe('parseSasUrl — az bare token (percent-encoded se)', () => {
  const p = parseSasUrl(AZ_BLOB_SAS_TOKEN);

  it('accepts a token with no leading `?`', () => {
    expect(p.signaturePresent).toBe(true);
    expect(p.version).toBe('2022-11-02');
  });

  it('decodes the percent-encoded colons in `se`', () => {
    expect(p.expiry?.toISOString()).toBe('2027-03-14T18:30:00.000Z');
  });

  it('reads the single read permission and blob resource', () => {
    expect(p.permissions).toBe('r');
    expect(p.resource).toBe('b');
    expect(p.kind).toBe('service');
  });
});

describe('parseSasUrl — stored-access-policy SAS (permissions server-side)', () => {
  const p = parseSasUrl(STORED_POLICY_SAS);

  it('yields null sp/se/st — we truthfully cannot see them', () => {
    expect(p.permissions).toBeNull();
    expect(p.expiry).toBeNull();
    expect(p.start).toBeNull();
  });

  it('still detects sr and the signature', () => {
    expect(p.resource).toBe('c');
    expect(p.signaturePresent).toBe(true);
  });
});

describe('parseSasUrl — malformed / graceful degradation', () => {
  it('empty string → everything null, no signature, kind unknown', () => {
    const p = parseSasUrl('');
    expect(p.version).toBeNull();
    expect(p.permissions).toBeNull();
    expect(p.resource).toBeNull();
    expect(p.start).toBeNull();
    expect(p.expiry).toBeNull();
    expect(p.signaturePresent).toBe(false);
    expect(p.kind).toBe('unknown');
  });

  it('a URL with no query string is handled, not thrown', () => {
    const p = parseSasUrl('https://clientmasters.blob.core.windows.net/deliverables');
    expect(p.signaturePresent).toBe(false);
    expect(p.expiry).toBeNull();
  });

  it('a non-URL, non-token string does not throw', () => {
    expect(() => parseSasUrl('this is not a sas at all')).not.toThrow();
    expect(parseSasUrl('this is not a sas at all').signaturePresent).toBe(false);
  });

  it('an empty `sig=` value counts as no signature present', () => {
    expect(parseSasUrl('?sv=2022-11-02&sr=b&sig=').signaturePresent).toBe(false);
  });

  it('an unparseable `se` degrades to null expiry (not a throw)', () => {
    const p = parseSasUrl('?sv=2022-11-02&sr=b&se=not-a-date&sig=x%3D');
    expect(p.expiry).toBeNull();
    expect(p.signaturePresent).toBe(true);
  });

  it('missing `se` on an otherwise-valid service SAS → null expiry', () => {
    const p = parseSasUrl('?sv=2022-11-02&sr=b&sp=r&sig=x%3D');
    expect(p.expiry).toBeNull();
    expect(p.permissions).toBe('r');
  });
});
