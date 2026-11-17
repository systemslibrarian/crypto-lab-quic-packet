import { type Page, type TestInfo, expect } from '@playwright/test';

import { record } from './observations';

/**
 * Assert a rendered verdict or measurement, AND record that the assertion ran.
 *
 * The recording is the point. `e2e/verdict-mutations.json` names, per marker,
 * the test and the exact claim that kills each mutation — and
 * `global-teardown.ts` fails the run when a recorded kill never executed. That
 * rule can only be enforced against what actually RAN, never against the
 * spec's source text: a mention is not an assertion, and commenting out a
 * call leaves the marker id sitting in the file looking performed.
 *
 * So every assertion that a mutation record depends on goes through here.
 */

export interface VerdictExpectation {
  readonly tone: 'pass' | 'fail' | 'alarm' | 'refused' | 'retired' | 'caveat';
  /** Text the verdict must contain. */
  readonly text: string;
}

export async function expectVerdict(
  page: Page,
  info: TestInfo,
  marker: string,
  expected: VerdictExpectation,
): Promise<void> {
  const locator = page.locator(`[data-verdict="${marker}"]`);
  await expect(locator, `verdict ${marker} must be rendered`).toBeVisible();
  await expect(locator, `verdict ${marker} tone`).toHaveAttribute('data-tone', expected.tone);
  await expect(locator, `verdict ${marker} text`).toContainText(expected.text);
  record({
    test: info.title,
    marker,
    claim: { tone: expected.tone, text: expected.text, kind: 'verdict' },
  });
}

export async function expectClaim(
  page: Page,
  info: TestInfo,
  marker: string,
  expected: string,
): Promise<void> {
  const locator = page.locator(`[data-claim="${marker}"]`);
  await expect(locator, `claim ${marker} must be rendered`).toBeVisible();
  await expect(locator, `claim ${marker} text`).toContainText(expected);
  record({ test: info.title, marker, claim: { text: expected, kind: 'claim' } });
}
