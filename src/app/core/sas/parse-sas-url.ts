/**
 * Consolidated SAS parser (slice 9, Part A — the shared substrate). A Shared
 * Access Signature encodes its own scope and lifetime in its query string; this
 * reads the fields every downstream surface needs (expiry badges, the wizard's
 * honesty copy, the signer's guardrails) into one typed result.
 *
 * Built ON TOP of the existing primitives so there is a single parse path:
 * `sasQueryParams` normalises URL-vs-token, and `sasExpiry` is the sole reader of
 * `se`. This module adds the remaining fields (`st`, `sp`, `sr`, `sv`) and a
 * derived account-vs-service discriminator.
 *
 * Derive-always, never store (founder decision): expiry and permissions are
 * parsed from the decrypted SAS at render time — the vault schema holds only the
 * credential itself, never a denormalised copy of these.
 *
 * The signature is DELIBERATELY not surfaced as a value — only its presence. It
 * is key-material-grade; nothing downstream needs the bytes, so we don't hand
 * them out (CLAUDE.md invariant 2 posture).
 */
// Deep imports, not the azure-blob barrel — see mint-sas.ts.
import { sasQueryParams } from '../azure-blob/azure-urls';
import { sasExpiry } from '../azure-blob/sas-expiry';

/** Which SAS family this is — they carry different scoping fields. */
export type SasKind = 'service' | 'account' | 'unknown';

export interface ParsedSas {
  /** `sv` — the service version the token was signed under. */
  version: string | null;
  /** `sp` — permission letters (r/w/l/d/a/c/…), verbatim and lowercased-as-issued. */
  permissions: string | null;
  /** `sr` — signed resource for a service SAS (b/c/bs/bv); null for an account SAS. */
  resource: string | null;
  /** `st` — start time, or null if absent/unparseable. */
  start: Date | null;
  /** `se` — expiry, or null if absent/unparseable (via {@link sasExpiry}). */
  expiry: Date | null;
  /** True only when a non-empty `sig` is present. Never the value itself. */
  signaturePresent: boolean;
  /** Derived: `srt`/`ss` present → account; `sr` present → service; else unknown. */
  kind: SasKind;
}

function toDate(value: string | null): Date | null {
  if (!value) {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * Parse a pasted SAS (full URL or bare `?…`/`sv=…` token) into its typed fields.
 * Never throws — malformed input degrades every field to null / false / unknown.
 */
export function parseSasUrl(sas: string): ParsedSas {
  const q = sasQueryParams(sas);
  const sr = q.get('sr');
  const accountScoped = q.has('srt') || q.has('ss');

  return {
    version: q.get('sv'),
    permissions: q.get('sp'),
    resource: sr,
    start: toDate(q.get('st')),
    expiry: sasExpiry(sas),
    signaturePresent: (q.get('sig') ?? '').length > 0,
    kind: accountScoped ? 'account' : sr ? 'service' : 'unknown',
  };
}
