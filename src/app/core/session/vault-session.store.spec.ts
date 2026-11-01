/**
 * VaultSessionStore tests. The headline is a REGRESSION PIN on security
 * invariant §7 (CLAUDE.md): session secrets live only in memory — this store
 * must never write to localStorage/sessionStorage/cookies. The vault key is
 * non-extractable so a stray persist couldn't leak usable bytes, but the access
 * token is an ordinary string with no such protection, so "never persisted" is
 * the only thing guarding it. We install tracking fakes for the storage APIs and
 * assert the full unlock → read → clear lifecycle touches none of them.
 *
 * Runs in the core (node) project, so there are no real DOM storage globals; the
 * fakes below stand in and would catch any future call that reaches for them.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { VaultSessionStore } from './vault-session.store';

interface Tracked {
  ops: string[];
}

const g = globalThis as unknown as {
  localStorage?: unknown;
  sessionStorage?: unknown;
  window?: unknown;
  document?: unknown;
};
const saved = { ...g };

function fakeStorage(ops: string[], name: string): Storage {
  return {
    get length() {
      return 0;
    },
    key: () => null,
    getItem: (k: string) => {
      ops.push(`${name}.getItem(${k})`);
      return null;
    },
    setItem: (k: string, v: string) => {
      ops.push(`${name}.setItem(${k}=${v})`);
    },
    removeItem: (k: string) => {
      ops.push(`${name}.removeItem(${k})`);
    },
    clear: () => {
      ops.push(`${name}.clear()`);
    },
  } as unknown as Storage;
}

function installTracking(): Tracked {
  const ops: string[] = [];
  g.localStorage = fakeStorage(ops, 'localStorage');
  g.sessionStorage = fakeStorage(ops, 'sessionStorage');
  let cookie = '';
  g.document = {
    get cookie() {
      ops.push('document.cookie GET');
      return cookie;
    },
    set cookie(v: string) {
      ops.push(`document.cookie SET(${v})`);
      cookie = v;
    },
  };
  // Catch a `window.localStorage`-style access too (aliases the same fakes).
  g.window = g;
  return { ops };
}

afterEach(() => {
  // Restore whatever the node env had before (usually undefined).
  g.localStorage = saved.localStorage;
  g.sessionStorage = saved.sessionStorage;
  g.window = saved.window;
  g.document = saved.document;
});

/** A stand-in for the real (non-extractable) session vault key. */
function sessionKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

describe('VaultSessionStore — never persists secrets (invariant §7)', () => {
  let tracked: Tracked;

  beforeEach(() => {
    tracked = installTracking();
  });

  it('unlock → read key → read token → clear writes to NO storage API', async () => {
    const store = new VaultSessionStore();
    const key = await sessionKey();

    store.unlock({ vaultKey: key, accessToken: 'tok_MARKER_do_not_persist' });
    // Exercise every read path a feature would use.
    expect(store.requireVaultKey()).toBe(key);
    expect(store.requireAccessToken()).toBe('tok_MARKER_do_not_persist');
    store.clear();

    // The pin: not a single storage/cookie op happened across the lifecycle.
    expect(tracked.ops).toEqual([]);
  });

  it('the access token is never handed to a storage setItem, under any key', async () => {
    const store = new VaultSessionStore();
    store.unlock({ vaultKey: await sessionKey(), accessToken: 'tok_MARKER_do_not_persist' });
    store.requireAccessToken();
    store.clear();

    expect(tracked.ops.some((op) => op.includes('tok_MARKER_do_not_persist'))).toBe(false);
  });

  it('SANITY: the tracker would CATCH a persist (the spy is not vacuous)', () => {
    (g.localStorage as Storage).setItem('vaultKey', 'tok_MARKER_do_not_persist');
    expect(tracked.ops.some((op) => op.includes('tok_MARKER_do_not_persist'))).toBe(true);
  });
});

describe('VaultSessionStore — lock/unlock behaviour', () => {
  beforeEach(() => installTracking());

  it('starts locked and throws on access', () => {
    const store = new VaultSessionStore();
    expect(store.isUnlocked()).toBe(false);
    expect(() => store.requireVaultKey()).toThrow(/locked/i);
    expect(() => store.requireAccessToken()).toThrow(/locked/i);
  });

  it('clear() re-locks: reads throw again', async () => {
    const store = new VaultSessionStore();
    store.unlock({ vaultKey: await sessionKey(), accessToken: 'x' });
    expect(store.isUnlocked()).toBe(true);
    store.clear();
    expect(store.isUnlocked()).toBe(false);
    expect(() => store.requireAccessToken()).toThrow(/locked/i);
  });
});
