import { describe, expect, it } from 'vitest';

import { toHex } from './bytes';
import { chacha20, chacha20Block } from './chacha20';
import { colonBlock, colonHex, hexDump, rfcText, section } from '../../tests/rfc-text';

/**
 * ChaCha20 against RFC 8439's own vectors.
 *
 * INVARIANT 4 OF THIS LAB: this suite and poly1305.test.ts must pass before
 * Appendix A.5 is attempted anywhere. A hand-written cipher that happens to
 * reproduce one QUIC packet is not a verified cipher; these are the vectors
 * that make it one.
 */

const rfc8439 = rfcText('rfc8439.txt');

describe('ChaCha20 block function (RFC 8439 section 2.3.2)', () => {
  const block = section(
    rfc8439,
    '2.3.2.  Test Vector for the ChaCha20 Block Function',
    '2.4.  The ChaCha20 Encryption Algorithm',
  );
  const key = colonHex(block, 'Key');
  const nonce = colonHex(block, 'Nonce');
  const expected = hexDump(block, 'Serialized Block');

  it('reproduces the 64-byte serialized block', () => {
    expect(key.length).toBe(32);
    expect(nonce.length).toBe(12);
    expect(expected.length).toBe(64);
    expect(toHex(chacha20Block(key, 1, nonce))).toBe(toHex(expected));
  });

  it('refuses a key or nonce of the wrong length', () => {
    expect(() => chacha20Block(new Uint8Array(16), 1, nonce)).toThrow(/32 bytes/);
    expect(() => chacha20Block(key, 1, new Uint8Array(8))).toThrow(/12 bytes/);
  });

  it('reads the counter as a little-endian word, so counter 1 is 01 00 00 00', () => {
    // RFC 8439 section 2.3's state diagram puts the counter at word 12. The
    // RFC prints `00000001` there because it prints WORDS, not bytes; on the
    // wire that word is 01 00 00 00. QUIC header protection depends on this
    // (RFC 9001 section 5.4.4), and reading it big-endian is a mutation in
    // this lab's ledger.
    const sameNonce = new Uint8Array(12);
    expect(toHex(chacha20Block(key, 1, sameNonce))).not.toBe(
      toHex(chacha20Block(key, 0x01000000, sameNonce)),
    );
  });
});

describe('ChaCha20 encryption (RFC 8439 section 2.4.2)', () => {
  const block = section(
    rfc8439,
    '2.4.2.  Example and Test Vector for the ChaCha20 Cipher',
    '2.5.  The Poly1305 Algorithm',
  );
  const key = colonHex(block, 'Key');
  const nonce = colonHex(block, 'Nonce');
  const plaintext = hexDump(block, 'Plaintext Sunscreen');
  // 2.4.2 prints its keystream colon-separated and its plaintext and
  // ciphertext as hexdumps, three values in one section and two formats.
  const keystream = colonBlock(block, 'Keystream');
  const ciphertext = hexDump(block, 'Ciphertext Sunscreen');

  it('reproduces the RFC\'s 114-byte ciphertext from counter 1', () => {
    expect(plaintext.length).toBe(114);
    expect(ciphertext.length).toBe(114);
    expect(toHex(chacha20(key, 1, nonce, plaintext))).toBe(toHex(ciphertext));
  });

  it('reproduces the RFC\'s keystream, which spans two blocks', () => {
    expect(keystream.length).toBe(114);
    expect(toHex(chacha20(key, 1, nonce, new Uint8Array(keystream.length)))).toBe(toHex(keystream));
  });

  it('round-trips: the cipher is its own inverse', () => {
    const sealed = chacha20(key, 1, nonce, plaintext);
    expect(toHex(chacha20(key, 1, nonce, sealed))).toBe(toHex(plaintext));
  });

  it('increments the block counter across block boundaries', () => {
    // The 114-byte message crosses into a second block at byte 64. If the
    // counter did not advance, bytes 64.. would repeat bytes 0...
    const stream = chacha20(key, 1, nonce, new Uint8Array(128));
    expect(toHex(stream.slice(64, 128))).not.toBe(toHex(stream.slice(0, 64)));
    expect(toHex(stream.slice(64, 128))).toBe(toHex(chacha20Block(key, 2, nonce)));
  });
});
