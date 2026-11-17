/**
 * Byte helpers shared by every module here.
 *
 * QUIC's worked examples are quoted in the RFC as hex with arbitrary
 * whitespace and line breaks, so `fromHex` tolerates whitespace and nothing
 * else: a stray non-hex character is a malformed fixture, not something to
 * skip past quietly.
 */

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error(`hex string has an odd length (${clean.length})`);
  }
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('hex string contains a non-hex character');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function xorInto(target: Uint8Array, source: Uint8Array, offset = 0): void {
  for (let i = 0; i < source.length; i++) target[offset + i] ^= source[i];
}

/**
 * Constant-time-ish equality.
 *
 * Nothing in a browser teaching demo is genuinely constant time, and claiming
 * so would be the kind of dishonesty this lab exists to argue against. What
 * this does guarantee is that the comparison does not short-circuit on the
 * first differing byte, which is the property the AEAD tag check wants and the
 * one a naive `every()` loop gives away.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** ASCII text as bytes. Used for HKDF labels, which are ASCII by definition. */
export function ascii(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code > 0x7f) throw new Error(`label is not ASCII: ${JSON.stringify(text)}`);
    out[i] = code;
  }
  return out;
}
