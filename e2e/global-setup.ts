import { randomUUID } from 'node:crypto';

import { truncateSink } from './observations';

/**
 * Stamp this run with an id and truncate its observation sink.
 *
 * Without the truncation, a stale sink from an earlier run could satisfy
 * `global-teardown.ts`'s coverage rule — so the check would pass on the
 * strength of assertions that did not execute in THIS run, which is precisely
 * the thing it exists to prevent.
 */
export default function globalSetup(): void {
  const id = process.env.QUIC_RUN_ID ?? randomUUID();
  process.env.QUIC_RUN_ID = id;
  truncateSink(id);
}
