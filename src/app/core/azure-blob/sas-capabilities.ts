/**
 * SAS capability introspection (spec §3.1 #3/#4/#5). A Shared Access Signature
 * encodes what it's allowed to do in its own query — the permission set `sp`
 * (r=read, w=write, l=list, d=delete, a=add, c=create…) and, for an *account*
 * SAS, the resource types `srt` (s=service, c=container, o=object). We read those
 * from the credential we already hold so the connection wizard can tell the user
 * UP FRONT what this connection will and won't be able to do — instead of letting
 * them discover a read-only token only when a tier change 403s.
 *
 * Honesty rule: a SAS backed by a stored access policy may omit `sp` entirely
 * (its permissions live server-side, invisible to us). In that case every
 * capability is `null` = "we can't tell from here", never a false claim.
 */
import { sasQueryParams } from './azure-urls';

export type CapabilityKey = 'browse' | 'download' | 'upload' | 'tier' | 'delete' | 'rename';

export interface SasCapability {
  key: CapabilityKey;
  label: string;
  /** `true` allowed · `false` denied by the SAS · `null` unknown (no readable `sp`). */
  allowed: boolean | null;
}

function has(set: string | null, ch: string): boolean {
  return set !== null && set.toLowerCase().includes(ch);
}

/** Read `sp` (permissions) and `srt` (account-SAS resource types) from a SAS. */
function sasScopes(sas: string): { sp: string | null; srt: string | null } {
  const params = sasQueryParams(sas);
  return { sp: params.get('sp'), srt: params.get('srt') };
}

/**
 * Whether a container-scoped op (List Blobs) is permitted. `null` when `sp` is
 * absent. For an account SAS the resource types must include container (`c`).
 */
function allows(sp: string | null, srt: string | null, perm: string, resourceType: 'c' | 'o'): boolean | null {
  if (sp === null) {
    return null; // stored-access-policy SAS — permissions not visible to us
  }
  if (!has(sp, perm)) {
    return false;
  }
  // An account SAS additionally gates by resource type; a service/container SAS
  // has no `srt`, so absence means "not gated → allowed".
  return srt === null || has(srt, resourceType);
}

/** Can this SAS change a blob's tier / rehydrate? `null` = unknown, so let Azure decide. */
export function sasCanSetTier(sas: string): boolean | null {
  const { sp, srt } = sasScopes(sas);
  return allows(sp, srt, 'w', 'o');
}

/** Can this SAS list the container (browse)? */
export function sasCanBrowse(sas: string): boolean | null {
  const { sp, srt } = sasScopes(sas);
  return allows(sp, srt, 'l', 'c');
}

/** Can this SAS read blobs (download / sign share links)? */
export function sasCanDownload(sas: string): boolean | null {
  const { sp, srt } = sasScopes(sas);
  return allows(sp, srt, 'r', 'o');
}

/**
 * Can this SAS upload (stage + commit blocks)? Azure grants that via EITHER
 * `w` (write — create or replace) or `c` (create — new blobs only), so upload
 * is offered when either is present; whether an existing blob can be REPLACED
 * is {@link sasCanOverwrite}'s separate question. `null` = unknown (stored
 * policy), per the module's honesty rule.
 */
export function sasCanUpload(sas: string): boolean | null {
  const { sp, srt } = sasScopes(sas);
  const write = allows(sp, srt, 'w', 'o');
  const create = allows(sp, srt, 'c', 'o');
  if (write === null || create === null) {
    return null;
  }
  return write || create;
}

/**
 * Can this SAS REPLACE an existing blob? Only `w` grants that — a create-only
 * (`c`) token can add new files but Azure refuses it overwrite permission, and
 * the overwrite dialog says so instead of letting the user hit a 403.
 */
export function sasCanOverwrite(sas: string): boolean | null {
  const { sp, srt } = sasScopes(sas);
  return allows(sp, srt, 'w', 'o');
}

/**
 * Can this SAS delete blobs (slice 22)? `d` at object scope — Delete Blob's own
 * permission letter. Delete is the product's first irreversible operation, so
 * the affordance is gated exactly as tightly as Azure gates the call.
 */
export function sasCanDelete(sas: string): boolean | null {
  const { sp, srt } = sasScopes(sas);
  return allows(sp, srt, 'd', 'o');
}

/**
 * Can this SAS rename/move a blob (slice 22)? Neither cloud renames — it's
 * copy-then-delete, so the credential must carry the WHOLE journey: `r` (the
 * copy source must be readable and the result verifiable), `w` (Copy Blob
 * requires write on the destination), and `d` (delete the original). Any letter
 * missing → the affordance is honestly disabled naming the gap, instead of a
 * rename that strands a duplicate mid-way. `null` = unknown (stored policy).
 */
export function sasCanRename(sas: string): boolean | null {
  const { sp, srt } = sasScopes(sas);
  const legs = [allows(sp, srt, 'r', 'o'), allows(sp, srt, 'w', 'o'), allows(sp, srt, 'd', 'o')];
  if (legs.some((leg) => leg === false)) {
    return false;
  }
  return legs.some((leg) => leg === null) ? null : true;
}

/** The user-facing capability summary for the connection wizard, in display order. */
export function describeSasCapabilities(sas: string): SasCapability[] {
  return [
    { key: 'browse', label: 'Browse folders & files', allowed: sasCanBrowse(sas) },
    { key: 'download', label: 'Download files & generate share links', allowed: sasCanDownload(sas) },
    { key: 'upload', label: 'Upload files', allowed: sasCanUpload(sas) },
    { key: 'tier', label: 'Change storage tiers & rehydrate archives', allowed: sasCanSetTier(sas) },
    { key: 'rename', label: 'Rename & move files', allowed: sasCanRename(sas) },
    { key: 'delete', label: 'Delete files', allowed: sasCanDelete(sas) },
  ];
}

/** True when we can positively read `sp` from the SAS (not a stored-policy SAS). */
export function sasPermissionsVisible(sas: string): boolean {
  return sasScopes(sas).sp !== null;
}
