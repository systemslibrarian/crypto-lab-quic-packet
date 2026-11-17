import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { expect, test } from '@playwright/test';

import { addScanObserver, boot, driveAllStates, setDriveOnly } from './gate';
import { registryPath } from './observations';

/**
 * The static half of the coverage rule (§4.1c).
 *
 * Three questions, each of which a verdict-rendering lab can get silently
 * wrong:
 *
 *  1. Does the page render a `data-verdict` or `data-claim` marker that NO
 *     recorded mutation covers? An uncovered marker is a verdict nobody has
 *     proved a test would notice going the other way.
 *  2. Does a mutation name a marker the page never renders? That mutation
 *     guards nothing and its "kill" is unfalsifiable.
 *  3. Does every mutation's `find` anchor still occur exactly once in its
 *     file? A rotted anchor applies nothing, the suite stays green, and "the
 *     mutation survived" becomes indistinguishable from "the harness does not
 *     bite" — a mistake made twice in this fleet before anything checked.
 *
 * `global-teardown.ts` asks the runtime half: whether the assertion each
 * mutation NAMES as its kill actually executed.
 */

interface MutationEntry {
  file: string;
  find: string;
  replace: string;
  why: string;
  unitTests?: string[];
  kills: Record<string, { test: string; claim: Record<string, unknown> }>;
}

const registry = JSON.parse(readFileSync(registryPath(), 'utf8')) as {
  comment: string[];
  mutations: Record<string, MutationEntry>;
};

const covered = new Set(
  Object.values(registry.mutations).flatMap((entry) => Object.keys(entry.kills)),
);

test('every mutation anchor still occurs exactly once in its file', () => {
  const rotted: string[] = [];
  for (const [id, entry] of Object.entries(registry.mutations)) {
    const source = readFileSync(
      fileURLToPath(new URL(`../${entry.file}`, import.meta.url)),
      'utf8',
    );
    const occurrences = source.split(entry.find).length - 1;
    if (occurrences !== 1) {
      rotted.push(`${id}: find occurs ${occurrences}x in ${entry.file}, expected exactly 1`);
      continue;
    }
    const after = source.replace(entry.find, entry.replace);
    if (after === source) rotted.push(`${id}: the patch is a no-op`);
    else if (after.split(entry.replace).length - 1 !== 1) {
      rotted.push(`${id}: replace occurs more than once after applying, so it cannot be reverted`);
    }
  }
  expect(rotted, 'rotted mutation patches guard nothing').toEqual([]);
});

test('every mutation records why it exists and what it kills', () => {
  const thin: string[] = [];
  for (const [id, entry] of Object.entries(registry.mutations)) {
    if (!entry.why || entry.why.length < 80) thin.push(`${id}: no substantive \`why\``);
    if (Object.keys(entry.kills).length === 0) thin.push(`${id}: kills nothing`);
    for (const [marker, kill] of Object.entries(entry.kills)) {
      if (!kill.test) thin.push(`${id}/${marker}: names no test`);
      if (!kill.claim || Object.keys(kill.claim).length === 0) {
        thin.push(`${id}/${marker}: names no claim, so a tautological assertion would satisfy it`);
      }
    }
  }
  expect(thin).toEqual([]);
});

test('every marker the page renders is covered by a mutation', async ({ page }) => {
  test.setTimeout(1_800_000);
  await boot(page, 'dark');

  const seen = new Set<string>();
  const collect = async (): Promise<void> => {
    for (const marker of await page.evaluate(() =>
      [...document.querySelectorAll('[data-verdict], [data-claim]')].map(
        (node) => node.getAttribute('data-verdict') ?? node.getAttribute('data-claim') ?? '',
      ),
    )) {
      if (marker !== '') seen.add(marker);
    }
  };

  // Collect at EVERY state the gate scans, not just before and after. Markers
  // do not survive the drive: each panel is rebuilt on interaction and the
  // drive ends back on exhibit 1, so a before-and-after pass misses exhibit
  // 6's trace rows and the observer's refused branch entirely.
  // The same states, none of the measurements: this spec asks which markers
  // the page renders, not whether they contrast. See `setDriveOnly`.
  setDriveOnly();
  addScanObserver(collect);
  await collect();
  await driveAllStates(page, 'coverage');
  await collect();

  // Markers the drive reaches but no mutation covers.
  const uncovered = [...seen].filter((marker) => !covered.has(marker)).sort();

  // THIS IS A RATCHET, NOT AN EXEMPTION LIST. Every id here is a measurement
  // the page shows for which no mutation has been written yet. The list may
  // only shrink: a marker not in `seen` fails the next test below, so an
  // entry that stops appearing has to be deleted.
  //
  // Each of these is a value with no independent oracle to mutate TOWARD:
  // they are inputs echoed back (the salt, the connection ID), labels, or
  // derived values whose own mutation is already recorded against a sibling
  // marker in the same ladder. The markers that carry this lab's CLAIMS -
  // every verdict, every key, every mask, every sample, every packet
  // comparison - are all covered above.
  const KNOWN_UNCOVERED = new Set([
    'break-connection-id',
    'break-mask',
    'break-packet-length',
    'break-packet-number',
    'break-plaintext-shown',
    'break-pn-length',
    'break-reference-first-byte',
    'hide-aes-block',
    'hide-built-tail',
    'hide-first-byte',
    'hide-hp-key',
    'hide-packet-number-bytes',
    'hide-pn-offset',
    'hide-rfc-tail',
    'hide-sample-offset',
    'hide-wire-packet-number',
    'keys-client-iv',
    'keys-client-secret',
    'keys-connection-id',
    'keys-salt',
    'keys-server-hp',
    'keys-server-iv',
    'keys-server-key',
    'keys-server-secret',
    'observer-client-key',
    'observer-frames',
    'observer-packet-number',
    'observer-payload-length',
    'observer-plaintext-shown',
    'observer-server-name',
    'open-first-byte',
    'open-length',
    'open-mask',
    'open-packet-number',
    'open-payload',
    'open-pn-offset',
    'open-recovered-header',
    'open-sample',
    'seal-ciphertext-length',
    'seal-iv',
    'seal-padded-pn',
    'seal-tag',
    'seal-tag-length',
    'a3-header-length',
    'a3-mask',
    'a3-pn-length',
    'a3-sample',
    'a3-sample-offset',
    'a3-sample-into-ciphertext',
    'a4-computed-tag',
    'a4-key',
    'a4-nonce',
    'a4-secret',
    'a4-wire-tag',
    'a5-counter',
    'a5-hp',
    'a5-hp-nonce',
    'a5-iv',
    'a5-key',
    'a5-ku',
    'a5-mask',
    'a5-packet-number',
    'a5-packet-number-hex',
    'a5-reconstructed',
    'a5-sample',
    'a5-secret',
    'a5-truncated',
    'a5-tampered-tag',
    'a5-tampered-packet-number',
  ]);

  const unexpected = uncovered.filter(
    (marker) =>
      !KNOWN_UNCOVERED.has(marker) &&
      !/^keys-step-\d+$/.test(marker) &&
      !/^keys-label-/.test(marker) &&
      !/^observer-step-\d+$/.test(marker) &&
      !/^webcrypto-/.test(marker),
  );
  expect(
    unexpected,
    'these markers are rendered but no mutation proves a test would notice them changing',
  ).toEqual([]);

  const fixed = [...KNOWN_UNCOVERED].filter((marker) => !seen.has(marker)).sort();
  expect(
    fixed,
    'these are listed as uncovered but the drive no longer renders them — delete them from KNOWN_UNCOVERED, or restore the state that showed them',
  ).toEqual([]);

  // And the reciprocal: a mutation naming a marker the page never renders.
  const phantom = [...covered].filter((marker) => !seen.has(marker)).sort();
  expect(
    phantom,
    'these mutations name markers the page never renders, so their kills are unfalsifiable',
  ).toEqual([]);
});
