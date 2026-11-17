import { describe, expect, it } from 'vitest';

import { RFC9001_EXCERPT } from '../src/fixtures/rfc9001';
import { DIGESTS, rfcBytes, rfcText, section, sha256Hex } from './rfc-text';

/**
 * The excerpt the PAGE reads is a byte-exact slice of the RFC.
 *
 * `src/fixtures/rfc9001-excerpt.txt` is bundled into the site, so it is the
 * only copy of the RFC a visitor's browser ever sees, and it is small enough
 * that a reader can diff it against rfc-editor.org by hand. This test is what
 * makes that worth doing: it rebuilds the excerpt from the full RFC text and
 * requires the three spans to match byte for byte, so the excerpt cannot be
 * quietly "corrected" into agreeing with a bug.
 */
describe('the bundled RFC 9001 excerpt', () => {
  const full = rfcText('rfc9001.txt');

  it('records the digest of the full RFC it was cut from', () => {
    expect(RFC9001_EXCERPT).toContain(DIGESTS['rfc9001.txt']);
    expect(sha256Hex(rfcBytes('rfc9001.txt'))).toBe(DIGESTS['rfc9001.txt']);
  });

  it('is the provenance header followed by exactly three verbatim spans', () => {
    const marker = '=== END PROVENANCE ===\n';
    const at = RFC9001_EXCERPT.indexOf(marker);
    expect(at, 'the excerpt must carry a provenance header').toBeGreaterThan(0);
    const body = RFC9001_EXCERPT.slice(at + marker.length);

    const rebuilt =
      '\n' +
      section(full, '5.2.  Initial Secrets', '5.3.  AEAD Usage') +
      '\n' +
      section(full, '5.8.  Retry Packet Integrity', '6.  Key Update') +
      '\n' +
      section(full, 'Appendix A.  Sample Packet Protection', 'Appendix B.  AEAD Algorithm Analysis');

    expect(body).toBe(rebuilt);
  });

  it('names the sections it contains', () => {
    for (const heading of [
      '5.2.  Initial Secrets',
      '5.8.  Retry Packet Integrity',
      'Appendix A.  Sample Packet Protection',
      'A.1.  Keys',
      'A.2.  Client Initial',
      'A.3.  Server Initial',
      'A.4.  Retry',
      'A.5.  ChaCha20-Poly1305 Short Header Packet',
    ]) {
      expect(RFC9001_EXCERPT).toContain(heading);
    }
  });
});
