# klarsend-core

The encrypting core of the [Klarsend](https://klarsend.com/) client, published so that
the claims on [klarsend.com/security](https://app.klarsend.com/security) can be read
and their tests run by anyone. Apache-2.0; see [TRADEMARKS.md](TRADEMARKS.md) for what
the licence does not cover.

Klarsend Send turns Azure Blob or S3-compatible storage you already own into short,
revocable download links. The point of this repository is one sentence on that page:
**your storage credentials are encrypted on your device, and Klarsend's servers cannot
read them.** The code that makes that true is here, with the tests that prove it.

## Run the tests

```sh
npm ci
npm test
```

Pure TypeScript on Node's WebCrypto; no browser and no framework needed. Two suites
compare our signers byte-for-byte with the vendors' own SDKs, so the AWS and Azure SDKs
are development dependencies here, used only as oracles.

## The claims, and the test for each

| Claim on the security page | Test |
|---|---|
| The vault round-trips, a wrong passphrase fails, and the recovery code works | `src/app/core/vault-crypto/vault-crypto.spec.ts` |
| The client-side Azure SAS signer is byte-for-byte identical to Azure's own SDK output | `src/app/core/sas/sign-service-sas.equality.spec.ts` |
| No key, passphrase or signing secret is ever put on the wire | `src/app/core/sas/sign-service-sas.canary.spec.ts`, `src/app/core/sigv4/sigv4.canary.spec.ts` |
| Vault key material lives only in memory, never in localStorage, sessionStorage or cookies | `src/app/core/session/vault-session.store.spec.ts` |
| The SigV4 signer matches AWS's published test vector and the AWS SDK, including presigned URLs and multipart uploads | `src/app/core/sigv4/*.equality.spec.ts` |
| Signup, login and recovery send exactly the fields they say they do | `src/app/core/auth/auth.spec.ts`, `src/app/core/auth/recover.spec.ts` |

## What is here

| Module | What it is |
|---|---|
| `vault-crypto` | AES-256-GCM vault with a fresh nonce per encryption; Argon2id (hash-wasm) passphrase derivation; passkey PRF derivation; 24-word recovery codes and their lookup key |
| `session` | The in-memory session store: the unlocked vault key lives here and nowhere else |
| `vault-sync` | How the encrypted vault blob travels to and from the server, and what the wire carries |
| `auth` | WebAuthn registration and login ceremonies, recovery, and the exact request shapes |
| `sas` | Client-side Azure service-SAS minting and parsing, so the server never holds a storage key |
| `sigv4` | Client-side AWS Signature Version 4, header and query (presigned) forms |

Plus the small helpers those modules import. Nothing else: this is the import closure of
the six modules above, generated from the monorepo, not a hand-picked selection.

## What is not here, on purpose

The rest of the product: the user interface, the upload engines, storage management,
the links dashboard, the cost estimator, the API and its link resolver, infrastructure
and pipelines. None of it is needed to check the claims above, and the claims are what
this repository exists for.

## How it is published

This is a one-way mirror. Each publish replaces the tree with the current closure from
the monorepo and commits it once, stamped with the monorepo commit it came from (see
`klarsend.mirroredFrom` in `package.json`). There is no history to rewrite and nothing
to merge; the monorepo is the source of truth. Pull requests are not open; security
reports are, see [SECURITY.md](SECURITY.md).
