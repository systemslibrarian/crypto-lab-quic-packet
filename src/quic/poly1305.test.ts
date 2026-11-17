import { describe, expect, it } from 'vitest';

import { concat, toHex } from './bytes';
import { poly1305 } from './poly1305';
import { colonHex, hexDump, rfcText, section, spacedHex } from '../../tests/rfc-text';

/**
 * Poly1305 against RFC 8439 section 2.5.2, plus the test-vector appendix.
 *
 * Invariant 4: this must pass before Appendix A.5 is attempted.
 */

const rfc8439 = rfcText('rfc8439.txt');

describe('Poly1305 (RFC 8439 section 2.5.2)', () => {
  const block = section(
    rfc8439,
    '2.5.2.  Poly1305 Example and Test Vector',
    '2.6.  Generating the Poly1305 Key Using ChaCha20',
  );
  const key = colonHex(block, 'Key Material');
  const message = hexDump(block, 'Message to be Authenticated');
  const tag = colonHex(block, 'Tag');

  it('reproduces the RFC\'s tag for the 34-byte message', () => {
    expect(key.length).toBe(32);
    expect(message.length).toBe(34);
    expect(tag.length).toBe(16);
    expect(toHex(poly1305(key, message))).toBe(toHex(tag));
  });

  it('is a one-time authenticator: a one-bit change moves the tag', () => {
    const tampered = message.slice();
    tampered[0] ^= 0x01;
    expect(toHex(poly1305(key, tampered))).not.toBe(toHex(tag));
  });

  it('handles a message that is an exact multiple of 16 bytes', () => {
    // The 34-byte vector exercises the short-final-block path (the appended
    // 0x01 byte). A 32-byte message takes the other branch, where no partial
    // block is absorbed at all, and nothing else here covers it.
    const exact = message.slice(0, 32);
    const padded = message.slice(0, 32);
    expect(toHex(poly1305(key, exact))).toBe(toHex(poly1305(key, padded)));
    expect(toHex(poly1305(key, exact))).not.toBe(toHex(poly1305(key, message)));
  });

  it('handles the empty message', () => {
    expect(poly1305(key, new Uint8Array(0)).length).toBe(16);
  });

  it('refuses a key of the wrong length', () => {
    expect(() => poly1305(new Uint8Array(16), message)).toThrow(/32 bytes/);
  });
});

/**
 * RFC 8439 Appendix A.3's Poly1305 vectors, which reach the reduction edges
 * the single section-2.5.2 vector does not: r clamped to zero (vector #2, where
 * the tag is s whatever the text says), an all-ones r, an accumulator that has
 * to wrap 2^130-5 more than once, and the exactly-2^130-5 case.
 *
 * These are the vectors that caught this file's first implementation, whose
 * 26-bit double limbs overflowed 2^53 on the multiply. The section-2.5.2
 * vector caught it too, but these are the ones that say WHERE.
 */
describe('Poly1305 (RFC 8439 Appendix A.3 edge vectors)', () => {
  const appendix = section(
    rfc8439,
    'A.3.  Poly1305 Message Authentication Code',
    'A.4.  Poly1305 Key Generation Using ChaCha20',
  );
  // The appendix indents its vector headings by two spaces and underlines them.
  const tests = appendix.split(/^ {2}Test Vector #\d+:\s*$/m).slice(1);

  it('finds the four offset-hexdump vectors', () => {
    // Vectors 1 to 4 are offset hexdumps; 5 to 11 use another format and are
    // covered by the suite below. Asserting the count is what stops this
    // describe block silently shrinking to zero and still reporting green.
    expect(tests.length).toBe(4);
  });

  tests.forEach((vector, index) => {
    it(`Test Vector #${index + 1}`, () => {
      const key = hexDump(vector, 'One-time Poly1305 Key');
      const text = hexDump(vector, 'Text to MAC');
      const tag = hexDump(vector, 'Tag');
      expect(key.length).toBe(32);
      expect(tag.length).toBe(16);
      expect(toHex(poly1305(key, text))).toBe(toHex(tag));
    });
  });
});

/**
 * RFC 8439 Appendix A.3 vectors 5 to 11 — the reduction and overflow edges,
 * each with the question it answers in its own heading. These print `R:` and
 * `S:` as separate 16-byte halves rather than one 32-byte key.
 */
describe('Poly1305 (RFC 8439 Appendix A.3 reduction edges)', () => {
  const appendix = section(
    rfc8439,
    'A.3.  Poly1305 Message Authentication Code',
    'A.4.  Poly1305 Key Generation Using ChaCha20',
  );
  const blocks = appendix.split(/^ {3}Test Vector #(\d+):/m);
  const vectors: Array<{ number: string; body: string }> = [];
  for (let i = 1; i < blocks.length; i += 2) {
    vectors.push({ number: blocks[i], body: blocks[i + 1] });
  }

  it('finds all seven', () => {
    expect(vectors.map((v) => v.number)).toEqual(['5', '6', '7', '8', '9', '10', '11']);
  });

  for (const vector of vectors) {
    it(`Test Vector #${vector.number}`, () => {
      const key = concat(spacedHex(vector.body, 'R'), spacedHex(vector.body, 'S'));
      const data = spacedHex(vector.body, 'data');
      const tag = spacedHex(vector.body, 'tag');
      expect(key.length).toBe(32);
      expect(tag.length).toBe(16);
      expect(toHex(poly1305(key, data))).toBe(toHex(tag));
    });
  }
});
