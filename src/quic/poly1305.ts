/**
 * Poly1305, RFC 8439 section 2.5, over BigInt.
 *
 * Needed for the same reason as chacha20.ts: Appendix A.5 is a
 * ChaCha20-Poly1305 packet and WebCrypto will not take a raw ChaCha20 key.
 * Verified against RFC 8439 sections 2.5.2 and A.3 before use (invariant 4).
 *
 * WHY BIGINT AND NOT 26-BIT LIMBS. The usual portable layout keeps the
 * accumulator in five 26-bit limbs, and the first version of this file did
 * exactly that over plain JavaScript numbers with a comment claiming every
 * intermediate product "stays under 2^53 so it is exact in a double". That
 * claim was wrong and the vectors caught it: a limb holds up to 2^27 after an
 * absorb, `s` is 5*r and reaches 2^28.3, so one product is already 2^55 and
 * the five-term sum is near 2^58. Doubles silently round there, which is why
 * poly1305-donna's 32-bit layout carries those sums in 64-bit integers.
 *
 * Rather than port the 16-bit-limb arithmetic that would make doubles safe,
 * this uses BigInt and does the modular arithmetic the way the RFC writes it.
 * It is slower, and that cost is invisible here: the only ChaCha20-Poly1305
 * packet in the lab carries a one-byte PING frame, and the longest message
 * this ever authenticates is a 130-byte test vector.
 *
 * This is a teaching implementation. It is not constant time, and BigInt
 * arithmetic could not be made so; nothing in this lab claims otherwise.
 */

/** P = 2^130 - 5, RFC 8439 section 2.5. */
const P = (1n << 130n) - 5n;
const CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;

function littleEndianToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

export function poly1305(key: Uint8Array, message: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error(`Poly1305 key must be 32 bytes, got ${key.length}`);

  // r is the first half of the key, little-endian, with the bits RFC 8439
  // section 2.5 clears: the top four of bytes 3, 7, 11, 15 and the bottom two
  // of bytes 4, 8, 12. That is exactly the constant above.
  const r = littleEndianToBigInt(key.subarray(0, 16)) & CLAMP;
  const s = littleEndianToBigInt(key.subarray(16, 32));

  let accumulator = 0n;
  for (let offset = 0; offset < message.length; offset += 16) {
    const chunk = message.subarray(offset, Math.min(offset + 16, message.length));
    // Each block is read little-endian with a 1 bit appended ABOVE its bytes,
    // so a 16-byte block adds 2^128 and a shorter final block adds 2^(8*len).
    const block = littleEndianToBigInt(chunk) | (1n << BigInt(8 * chunk.length));
    accumulator = ((accumulator + block) * r) % P;
  }

  const tagValue = (accumulator + s) & ((1n << 128n) - 1n);
  const out = new Uint8Array(16);
  let remaining = tagValue;
  for (let i = 0; i < 16; i++) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}
