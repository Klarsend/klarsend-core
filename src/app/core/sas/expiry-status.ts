/**
 * Expiry badge/status derivation (slice 9, Part A). Turns a SAS expiry (`se`,
 * already parsed) plus "now" into a tone, a short chip label, and an honest
 * sentence for the wizard. This is the single source of the expiry UX vocabulary
 * shared by the connections list, the browse header, and the wizard.
 *
 * Tones: `danger` (past expiry — the credential is dead) · `warning` (≤14 days —
 * amber, "expires in N days") · `neutral` (further out — show the date) ·
 * `unknown` (no readable `se`; a service SAS omitting `se` is malformed, not
 * immortal — the wizard treats it as a validation warning). The `imminent` flag
 * (<7 days) drives the wizard's stronger "almost immediately" nudge.
 *
 * Formatting is hand-rolled in UTC (the `se` is UTC) so it's deterministic across
 * runners/timezones and carries no ICU dependency — a badge is day-coarse, so the
 * UTC calendar date is the honest, stable thing to show.
 */

/** ≤ this many days out → amber warning. */
export const WARNING_WINDOW_DAYS = 14;
/** < this many days out → the wizard's "expires almost immediately" nudge. */
export const IMMINENT_WINDOW_DAYS = 7;

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export type ExpiryTone = 'neutral' | 'warning' | 'danger' | 'unknown';

export interface ExpiryStatus {
  tone: ExpiryTone;
  /** Short chip text: "Expired" · "Expires in 6 days" · "Expires 14 Mar 2027" · "No expiry set". */
  badgeLabel: string;
  /** A full honest sentence for the wizard (date + distance + consequence). */
  detail: string;
  /** True when `se` present and strictly under {@link IMMINENT_WINDOW_DAYS}. */
  imminent: boolean;
  /** True when there is no readable `se` — the wizard flags this as malformed. */
  missingExpiry: boolean;
  expiry: Date | null;
}

const MONTHS = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December',
];

function absoluteLong(d: Date): string {
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

function absoluteShort(d: Date): string {
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()].slice(0, 3)} ${d.getUTCFullYear()}`;
}

const plural = (n: number, unit: string) => `${n} ${unit}${n === 1 ? '' : 's'}`;

/** The magnitude of a gap in the largest sensible unit, e.g. "8 months", "5 days". */
function magnitude(absMs: number): string {
  if (absMs < HOUR) {
    return plural(Math.max(1, Math.round(absMs / MINUTE)), 'minute');
  }
  if (absMs < DAY) {
    return plural(Math.round(absMs / HOUR), 'hour');
  }
  const days = absMs / DAY;
  if (days < 60) {
    return plural(Math.round(days), 'day');
  }
  if (days < 730) {
    return plural(Math.round(days / 30.44), 'month');
  }
  return plural(Math.round(days / 365.25), 'year');
}

/** Derive the full expiry status for a parsed `se` relative to `now`. */
export function describeExpiry(expiry: Date | null, now: Date = new Date()): ExpiryStatus {
  if (expiry === null) {
    return {
      tone: 'unknown',
      badgeLabel: 'No expiry set',
      detail:
        'This credential doesn’t declare an expiry we can read — a service SAS should always carry one.',
      imminent: false,
      missingExpiry: true,
      expiry: null,
    };
  }

  const diff = expiry.getTime() - now.getTime();

  if (diff <= 0) {
    const ago = magnitude(-diff);
    return {
      tone: 'danger',
      badgeLabel: 'Expired',
      detail: `This credential expired ${ago} ago (${absoluteLong(expiry)}). It no longer works — ask for a fresh one.`,
      imminent: false,
      missingExpiry: false,
      expiry,
    };
  }

  const rel = magnitude(diff);
  const withinWarning = diff <= WARNING_WINDOW_DAYS * DAY;
  const detail = `Expires ${absoluteLong(expiry)} — in ${rel}. The connection stops working then.`;

  return {
    tone: withinWarning ? 'warning' : 'neutral',
    badgeLabel: withinWarning ? `Expires in ${rel}` : `Expires ${absoluteShort(expiry)}`,
    detail,
    imminent: diff < IMMINENT_WINDOW_DAYS * DAY,
    missingExpiry: false,
    expiry,
  };
}
