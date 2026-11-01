import { defineConfig } from 'vitest/config';

// Pure TypeScript on Node's WebCrypto — no framework, no DOM. The same configuration the
// monorepo runs these specs under; Argon2id at the spec's parameters is deliberately slow,
// hence the timeout.
export default defineConfig({
  test: {
    include: ['src/app/core/**/*.spec.ts'],
    exclude: ['src/app/core/**/*.dom.spec.ts', 'src/app/core/**/*.live.spec.ts'],
    environment: 'node',
    testTimeout: 30_000,
  },
});
