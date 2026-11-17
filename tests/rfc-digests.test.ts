import { describe, expect, it } from 'vitest';

import { DIGESTS, rfcBytes, sha256Hex } from './rfc-text';

/**
 * The RFC texts this lab reads its expected values out of are exactly the ones
 * that were fetched and reviewed.
 *
 * Without this, the honesty of every other suite rests on nobody having edited
 * a 126 KB text file. A suite that reads its answers from a file it does not
 * pin is a suite that can be made to agree with anything.
 */
describe('RFC texts are the ones that were retrieved', () => {
  for (const [name, digest] of Object.entries(DIGESTS)) {
    it(`${name} still hashes to its recorded SHA-256`, () => {
      expect(sha256Hex(rfcBytes(name))).toBe(digest);
    });
  }
});
