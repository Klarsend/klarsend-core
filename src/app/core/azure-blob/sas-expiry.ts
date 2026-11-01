/**
 * SAS expiry introspection (spec §3.3, honest-failure requirement). A Shared
 * Access Signature carries its own expiry in the `se` query parameter (ISO-8601
 * UTC). We read it from the credential we ALREADY hold — never by interpreting
 * Azure's 403 body, which the spec says we must treat as auth-vs-expiry
 * indistinguishable. When `se` is in the past we can say, truthfully and
 * specifically, "this credential has expired" without guessing.
 *
 * A SAS backed by a stored access policy may omit `se` (the policy holds the
 * window server-side). We can't see that, so absence → `null` → we fall back to
 * the generic "access was refused" copy rather than claiming anything.
 */
import { sasQueryParams } from './azure-urls';

/** The SAS expiry (`se`) as a Date, or `null` if absent/unparseable. */
export function sasExpiry(sas: string): Date | null {
  const se = sasQueryParams(sas).get('se');
  if (!se) {
    return null;
  }
  const date = new Date(se);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * True only when the SAS declares an expiry that is already in the past.
 * Absence of `se` returns `false` — we don't know, so we don't claim expiry.
 */
export function isSasExpired(sas: string, now: Date = new Date()): boolean {
  const expiry = sasExpiry(sas);
  return expiry !== null && expiry.getTime() <= now.getTime();
}
