/** Base64url (RFC 4648 §5, unpadded) — the byte encoding of WebAuthn JSON. */
import { fromBase64, toBase64 } from '../vault-crypto/encoding';

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(text: string): Uint8Array {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '=');
  return fromBase64(padded);
}
