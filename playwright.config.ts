import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the production build served by `vite preview`, so what
 * passes here is what ships. Three kinds of spec:
 *
 *   - a11y.spec.ts             — the axe WCAG gate, Chromium only.
 *   - claims.spec.ts           — what the page SAYS, including the negative claim.
 *   - verdict-coverage.spec.ts — every rendered marker has a recorded mutation.
 *
 * Port 4248 is this lab's, taken from the catalog's `node tools/port-sync.js`
 * rather than chosen. It needs pinning in `tools/playwright-ports.json` by a
 * catalog session; until that happens `port-sync check` reports this lab as
 * unpinned, which is the right answer rather than a nuisance.
 *
 * The first port this lab took was 4245, and by the time the gate was running
 * `port-sync` reported it shared with `crypto-lab-pseudorandom-code` -- another
 * lab built in the same window, also unpinned, so neither had claimed it. That
 * is exactly the failure the registry exists to prevent and exactly why the
 * answer has to come from the tool rather than from reading siblings. Never the
 * Vite default 4173:
 * a shared port means `reuseExistingServer` can scan a different lab's
 * preview, or — during a §4.1c mutation check — an UNMUTATED checkout still
 * listening from an earlier run, which reads as "the mutation was not caught".
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 120_000, // the axe driver walks every panel and disclosure before scanning
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    baseURL: 'http://localhost:4248/crypto-lab-quic-packet/',
    colorScheme: 'dark', // dark is the only theme
  },
  projects: [
    { name: 'a11y', testMatch: /a11y\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    // Claims and coverage run in one engine: they assert what the page says
    // and which markers it renders, neither of which varies by browser.
    { name: 'claims', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    {
      name: 'coverage',
      testMatch: /verdict-coverage\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // Build before serving: `vite preview` serves whatever is already in
    // dist/, so without the build in front a run tests a stale bundle — and a
    // build that FAILS leaves the previous good bundle in place, so the whole
    // suite passes green against source that no longer compiles. That
    // silently invalidates mutation checking, which is the only thing that
    // proves a test has teeth.
    command: 'npm run build && npm run preview -- --port 4248 --strictPort',
    url: 'http://localhost:4248/crypto-lab-quic-packet/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
