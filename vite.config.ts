import { configDefaults, defineConfig } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-quic-packet/
export default defineConfig({
  base: '/crypto-lab-quic-packet/',
  test: {
    // Colocated unit tests plus the RFC-text suites under tests/; the
    // Playwright specs in e2e/ are NOT unit tests and must not be collected.
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
