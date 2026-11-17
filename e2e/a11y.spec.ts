import { expect, test } from '@playwright/test';

import {
  NARROW,
  boot,
  driveAllStates,
  expectBaselineNotStale,
  fullScanCount,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG 2.1 A/AA regression gate.
 *
 * Note the `fullScanCount()` assertion at the end of each test. `gate.ts`
 * carries a drive-only switch so `verdict-coverage.spec.ts` can walk the same
 * states without re-running every oracle, and a switch like that is exactly
 * how a gate ends up green having measured nothing. So the count of states
 * where the oracles really ran is asserted here: a degraded gate fails naming
 * the number rather than passing.
 *
 * The lab is driven along everything it teaches: the arrival state, where
 * exhibit 1 has already derived its keys and the other five tabpanels are
 * hidden and UNRENDERED; the shared skip link focused; a non-hex connection ID
 * and a too-short one, each refused behind `aria-invalid`; a connection ID of
 * the reader's own, which produces an alarm-toned verdict with nothing in the
 * RFC to compare it against; retired evidence on three different controls; the
 * header-protection stepper at all six of its states, forwards, reset, and run
 * all at once; the observer's alarm verdict and its negative claim, then the
 * same packet with one bit flipped so the verdict becomes "not opened" with no
 * server name; the server Initial, the Retry tag, the wrong-ODCID refusal and
 * the ChaCha20 packet; all seven of exhibit 6's breaks, including the two
 * refused before any decryption runs; the no-op guard; every `<details>` on
 * every panel, opened through its own `<summary>`; two hover states and a
 * focus ring. Every one of those states is scanned, at desktop and phone
 * width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * revealed from script (these panels render LAZILY, so stripping `hidden`
 * would scan five empty regions and call them accessible), why the lab's
 * defaults are asserted rather than assumed, and why `violations` is not the
 * whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    expect(
      fullScanCount(),
      'the oracles must have actually run at every driven state',
    ).toBeGreaterThan(30);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    expect(
      fullScanCount(),
      'the oracles must have actually run at every driven state',
    ).toBeGreaterThan(30);
    reportCollected();
  });
}
