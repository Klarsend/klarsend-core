/**
 * Boundary tests for expiry badge/status logic (slice 9, Part A). The tone
 * thresholds (expired · ≤14 days amber · else neutral · no-se unknown) and the
 * <7-day "imminent" nudge are exercised exactly at their edges — off-by-one here
 * is a user telling a client "it's fine" the day before a link dies.
 *
 * Formatting is deterministic (hand-rolled, UTC) so these KATs don't depend on
 * the runner's ICU build or timezone.
 */
import { describe, expect, it } from 'vitest';

import { describeExpiry } from './expiry-status';

const NOW = new Date('2026-07-10T12:00:00Z');
const DAY = 24 * 60 * 60 * 1000;
const at = (offsetMs: number) => new Date(NOW.getTime() + offsetMs);

describe('describeExpiry — tone thresholds', () => {
  it('past expiry → danger', () => {
    const s = describeExpiry(at(-1000), NOW);
    expect(s.tone).toBe('danger');
    expect(s.badgeLabel).toBe('Expired');
  });

  it('exactly now → danger (boundary, matches isSasExpired)', () => {
    expect(describeExpiry(at(0), NOW).tone).toBe('danger');
  });

  it('within 14 days → warning', () => {
    expect(describeExpiry(at(6 * DAY), NOW).tone).toBe('warning');
  });

  it('exactly 14 days → warning (inclusive boundary)', () => {
    const s = describeExpiry(at(14 * DAY), NOW);
    expect(s.tone).toBe('warning');
    expect(s.badgeLabel).toBe('Expires in 14 days');
  });

  it('14 days + 1ms → neutral', () => {
    const s = describeExpiry(at(14 * DAY + 1), NOW);
    expect(s.tone).toBe('neutral');
  });

  it('far future → neutral with an absolute date badge', () => {
    const s = describeExpiry(new Date('2027-03-14T18:30:00Z'), NOW);
    expect(s.tone).toBe('neutral');
    expect(s.badgeLabel).toBe('Expires 14 Mar 2027');
  });

  it('null expiry → unknown', () => {
    const s = describeExpiry(null, NOW);
    expect(s.tone).toBe('unknown');
    expect(s.badgeLabel).toBe('No expiry set');
    expect(s.missingExpiry).toBe(true);
  });
});

describe('describeExpiry — imminent (<7 day) nudge', () => {
  it('flags imminent within 7 days', () => {
    expect(describeExpiry(at(3 * DAY), NOW).imminent).toBe(true);
  });

  it('exactly 7 days is NOT imminent (strict <7)', () => {
    const s = describeExpiry(at(7 * DAY), NOW);
    expect(s.imminent).toBe(false);
    expect(s.tone).toBe('warning');
  });

  it('an already-expired credential is not "imminent"', () => {
    expect(describeExpiry(at(-DAY), NOW).imminent).toBe(false);
  });
});

describe('describeExpiry — honest copy', () => {
  it('neutral detail states the date and the relative distance and the consequence', () => {
    const s = describeExpiry(new Date('2027-03-14T18:30:00Z'), NOW);
    expect(s.detail).toContain('14 March 2027');
    expect(s.detail).toContain('8 months');
    expect(s.detail.toLowerCase()).toContain('stops working');
  });

  it('warning within days reads "in N days"', () => {
    expect(describeExpiry(at(5 * DAY), NOW).detail).toContain('5 days');
  });

  it('sub-day warning reads in hours', () => {
    const s = describeExpiry(at(5 * 60 * 60 * 1000), NOW);
    expect(s.badgeLabel).toBe('Expires in 5 hours');
  });

  it('danger detail admits it no longer works', () => {
    const s = describeExpiry(at(-2 * DAY), NOW);
    expect(s.detail.toLowerCase()).toContain('no longer works');
    expect(s.detail).toContain('2 days');
  });
});
