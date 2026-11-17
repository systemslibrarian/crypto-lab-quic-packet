import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

/**
 * A run-scoped sink recording which (test, marker, claim) triples actually
 * EXECUTED.
 *
 * This exists because a mutation registry that merely NAMES its killing
 * assertion can be satisfied by a mention. Three ways that was defeated
 * elsewhere in this fleet, all of them mentions rather than assertions:
 *
 *   - the killing call commented out: the substring survives in the file, the
 *     call does not, and the pair is never observed;
 *   - the killing assertion rewritten while an unrelated call elsewhere in the
 *     same file keeps the marker id present in the source;
 *   - the call kept but fed values read off the page in the same test, which
 *     on an unmutated baseline is byte-identical to a correct assertion.
 *
 * So the record pins the CLAIM as well as the pair. The moment the page moves
 * under a mutation, a tautological argument moves with it and stops matching
 * what was recorded. `global-teardown.ts` fails the run when a recorded kill
 * never appeared here.
 */

const SINK_DIR = join(tmpdir(), 'crypto-lab-quic-packet-observations');

export function runId(): string | null {
  return process.env.QUIC_RUN_ID ?? null;
}

function sinkPath(id: string): string {
  return join(SINK_DIR, `${id}.jsonl`);
}

export interface Observation {
  readonly test: string;
  readonly marker: string;
  readonly claim: Record<string, unknown>;
}

/** Canonical form of a claim, so a record and an observation compare equal. */
export function canonicalClaim(claim: Record<string, unknown>): string {
  const keys = Object.keys(claim).sort();
  return JSON.stringify(keys.map((k) => [k, claim[k]]));
}

export function truncateSink(id: string): void {
  mkdirSync(dirname(sinkPath(id)), { recursive: true });
  writeFileSync(sinkPath(id), '');
}

export function removeSink(id: string): void {
  rmSync(sinkPath(id), { force: true });
}

/**
 * Append one observation. Opened in append mode per write rather than held
 * open, because Playwright workers are separate processes and this has to be
 * safe across all of them.
 */
export function record(observation: Observation): void {
  const id = runId();
  if (id === null) return;
  mkdirSync(dirname(sinkPath(id)), { recursive: true });
  const line = JSON.stringify({
    test: observation.test,
    marker: observation.marker,
    claim: canonicalClaim(observation.claim),
  });
  writeFileSync(sinkPath(id), `${line}\n`, { flag: 'a' });
}

export function readObservations(id: string): Observation[] {
  try {
    return readFileSync(sinkPath(id), 'utf8')
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line) as Observation);
  } catch {
    return [];
  }
}

export function registryPath(): string {
  return fileURLToPath(new URL('./verdict-mutations.json', import.meta.url));
}
