import { readFileSync } from 'node:fs';

import { canonicalClaim, readObservations, registryPath, removeSink, runId } from './observations';

interface MutationEntry {
  kills: Record<string, { test: string; claim: Record<string, unknown> }>;
}

/** Separator for composite keys: never appears in a test title or a claim. */
const SEP = ' >>> ';

/**
 * The runtime half of the coverage rule (§4.1c).
 *
 * `verdict-coverage.spec.ts` asks whether every rendered marker has a recorded
 * mutation. This asks the other question: whether the assertion each mutation
 * NAMES as its kill actually ran. The answer is read from what
 * `expectVerdict` / `expectClaim` executed, never from the spec's source text,
 * because a mention is not an assertion — comment out the call and the marker
 * id still sits in the file looking performed.
 *
 * It runs here rather than in a project with `dependencies:` deliberately: a
 * dependent project is SKIPPED when the project it needs fails, which is
 * exactly the run — a mutation applied — where this answer matters most.
 *
 * It is SKIPPED when only part of the suite ran (`--grep`, a single project,
 * `--last-failed`), because then an unexecuted kill means "not selected"
 * rather than "not performed", and failing on that would make the teardown a
 * nuisance rather than a check. `scripts/mutate.mjs` always runs the whole
 * claims project, so the rule bites where it is relied upon.
 */
export default function globalTeardown(): void {
  const id = runId();
  if (!id) {
    throw new Error(
      'verdict runtime coverage: no run id. e2e/global-setup.ts did not run, so the ' +
        'observation sink was never truncated and nothing it holds can be trusted.',
    );
  }

  const observed = readObservations(id);
  removeSink(id);

  // A partial run cannot answer this question. "Nothing observed at all" is
  // the one case that is always a real failure: it means the claims project
  // did not run, and then no kill in the registry has any evidence.
  if (process.env.QUIC_PARTIAL_RUN === '1') return;

  const registry = JSON.parse(readFileSync(registryPath(), 'utf8')) as {
    mutations: Record<string, MutationEntry>;
  };

  const seen = new Set(
    observed.map((entry) => `${entry.test}${SEP}${entry.marker}${SEP}${entry.claim}`),
  );

  const unperformed: string[] = [];
  for (const [id_, entry] of Object.entries(registry.mutations)) {
    for (const [marker, kill] of Object.entries(entry.kills)) {
      const key = `${kill.test}${SEP}${marker}${SEP}${canonicalClaim(kill.claim)}`;
      if (!seen.has(key)) {
        unperformed.push(
          `${id_} -> ${marker}\n    expects: ${kill.test}\n    asserting: ${canonicalClaim(kill.claim)}`,
        );
      }
    }
  }

  if (observed.length === 0) {
    throw new Error(
      'verdict runtime coverage: NOTHING was observed. expectVerdict/expectClaim never ran, ' +
        'so every recorded kill in e2e/verdict-mutations.json is unevidenced. If this was a ' +
        'deliberately partial run, set QUIC_PARTIAL_RUN=1.',
    );
  }

  if (unperformed.length > 0) {
    throw new Error(
      `verdict runtime coverage: ${unperformed.length} recorded kill(s) never executed.\n\n` +
        'A mutation record names the test and the exact claim that kills it. These were not ' +
        'observed running, so those kills are claims about assertions nobody performed.\n\n' +
        unperformed.join('\n\n'),
    );
  }
}
