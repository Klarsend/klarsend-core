/**
 * Upload SAS minting + the re-mint provider (slice 19). The provider is what
 * lets an account-key connection outlive its own 1-hour token on a long upload:
 * a fresh mint whenever the current token is within the margin of expiry —
 * entirely client-side, the key never leaves the device (canary suite pins that).
 */
import { describe, expect, it } from 'vitest';

import { sasCanSetTier } from '../azure-blob/sas-capabilities'; // deep import: see mint-sas.ts
import { parseSasUrl } from './parse-sas-url';
import {
  DELETE_SAS_PERMISSIONS,
  MANAGE_SAS_REMINT_MARGIN_MS,
  MANAGE_SAS_TTL_MS,
  RENAME_SAS_PERMISSIONS,
  TIER_SAS_PERMISSIONS,
  UPLOAD_SAS_REMINT_MARGIN_MS,
  UPLOAD_SAS_TTL_MS,
  manageSasProvider,
  mintContainerBrowseSas,
  mintContainerManageSas,
  mintContainerUploadSas,
  uploadSasProvider,
} from './mint-sas';

const ACCOUNT_KEY = btoa('klarsend-upload-mint-fixture-key-000000000000');
const T0 = new Date('2027-03-14T12:00:00Z');

describe('mintContainerUploadSas', () => {
  it('mints a container token with exactly rcw and the upload TTL', async () => {
    const token = await mintContainerUploadSas('acct', 'cont', ACCOUNT_KEY, T0);
    const parsed = parseSasUrl(token);
    expect(parsed.permissions).toBe('rcw'); // read (HEAD check) + create + write
    expect(parsed.resource).toBe('c');
    expect(parsed.expiry?.getTime()).toBe(T0.getTime() + UPLOAD_SAS_TTL_MS);
    expect(parsed.signaturePresent).toBe(true);
  });
});

describe('mintContainerManageSas (slice 22) — per-operation letters, short TTL', () => {
  it('delete mints exactly d — never a standing racwdl', async () => {
    const token = await mintContainerManageSas('acct', 'cont', ACCOUNT_KEY, DELETE_SAS_PERMISSIONS, T0);
    const parsed = parseSasUrl(token);
    expect(parsed.permissions).toBe('d');
    expect(parsed.resource).toBe('c');
    expect(parsed.expiry?.getTime()).toBe(T0.getTime() + MANAGE_SAS_TTL_MS);
  });

  it('rename mints rcwd — the whole copy-verify-delete journey, nothing more', async () => {
    const token = await mintContainerManageSas('acct', 'cont', ACCOUNT_KEY, RENAME_SAS_PERMISSIONS, T0);
    expect(parseSasUrl(token).permissions).toBe('rcwd');
  });

  it('tier mints exactly w — Set Blob Tier / rehydrate is gated on write alone', async () => {
    const token = await mintContainerManageSas('acct', 'cont', ACCOUNT_KEY, TIER_SAS_PERMISSIONS, T0);
    const parsed = parseSasUrl(token);
    expect(parsed.permissions).toBe('w');
    expect(parsed.resource).toBe('c');
    expect(parsed.expiry?.getTime()).toBe(T0.getTime() + MANAGE_SAS_TTL_MS);
    expect(sasCanSetTier(token)).toBe(true);
  });

  it('the browse token an account-key connection self-mints CANNOT set tier — the reason tier re-mints', async () => {
    // Regression pin: tier changes on connection-string / account-key connections
    // used to PUT with this rl token and were refused with 403.
    const browse = await mintContainerBrowseSas('acct', 'cont', ACCOUNT_KEY, T0);
    expect(parseSasUrl(browse).permissions).toBe('rl');
    expect(sasCanSetTier(browse)).toBe(false);
  });

  it('management TTL is shorter than the browse/upload hour', () => {
    expect(MANAGE_SAS_TTL_MS).toBeLessThan(UPLOAD_SAS_TTL_MS);
  });
});

describe('manageSasProvider — long folder deletes outlive one short token', () => {
  it('reuses while fresh; re-mints inside the management margin', async () => {
    let now = T0;
    const provider = manageSasProvider('acct', 'cont', ACCOUNT_KEY, DELETE_SAS_PERMISSIONS, () => now);

    const first = await provider();
    expect(await provider()).toBe(first);

    now = new Date(T0.getTime() + MANAGE_SAS_TTL_MS - MANAGE_SAS_REMINT_MARGIN_MS - 1000);
    expect(await provider()).toBe(first);

    now = new Date(T0.getTime() + MANAGE_SAS_TTL_MS - MANAGE_SAS_REMINT_MARGIN_MS + 1000);
    const second = await provider();
    expect(second).not.toBe(first);
    expect(parseSasUrl(second).permissions).toBe('d');
    expect(parseSasUrl(second).expiry?.getTime()).toBe(now.getTime() + MANAGE_SAS_TTL_MS);
  });
});

describe('uploadSasProvider — transparent re-mint', () => {
  it('reuses the token while fresh; re-mints inside the expiry margin', async () => {
    let now = T0;
    const provider = uploadSasProvider('acct', 'cont', ACCOUNT_KEY, () => now);

    const first = await provider();
    expect(await provider()).toBe(first); // fresh → same token

    // Just OUTSIDE the margin: still the same token.
    now = new Date(T0.getTime() + UPLOAD_SAS_TTL_MS - UPLOAD_SAS_REMINT_MARGIN_MS - 1000);
    expect(await provider()).toBe(first);

    // INSIDE the margin: a new token, minted from the new clock.
    now = new Date(T0.getTime() + UPLOAD_SAS_TTL_MS - UPLOAD_SAS_REMINT_MARGIN_MS + 1000);
    const second = await provider();
    expect(second).not.toBe(first);
    expect(parseSasUrl(second).expiry?.getTime()).toBe(now.getTime() + UPLOAD_SAS_TTL_MS);
  });
});
