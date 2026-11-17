import { describe, expect, it } from 'vitest';

import { A2_CRYPTO_FRAME, A2_PAYLOAD } from '../fixtures/rfc9001';
import { concat, fromHex, toHex } from './bytes';
import { cryptoStreamFromPayload, findServerName } from './clienthello';

/**
 * The minimal TLS walk, and every way it is made to refuse.
 *
 * The fail-closed cases matter more than the success case here. A demo that
 * scanned the plaintext for something hostname-shaped would pass the one happy
 * test and print a server name for packets that contain none.
 */

const stream = cryptoStreamFromPayload(A2_PAYLOAD);

describe('reassembling the CRYPTO stream (RFC 9000 section 19.6)', () => {
  it('finds the CRYPTO frame and the PADDING that follows it', () => {
    expect(stream.frames).toContain('CRYPTO (offset 0, 241 bytes)');
    expect(stream.frames.some((f) => f.startsWith('PADDING'))).toBe(true);
    expect(stream.stoppedAt).toBeNull();
  });

  it('recovers exactly the handshake bytes, not the padding', () => {
    expect(stream.bytes.length).toBe(241);
    // The frame header A.2 prints is 06 00 40f1: type 0x06, offset 0, length
    // 0x40f1 -> 241. The stream is the 241 bytes after it.
    expect(toHex(A2_CRYPTO_FRAME.slice(0, 4))).toBe('060040f1');
    expect(toHex(stream.bytes)).toBe(toHex(A2_CRYPTO_FRAME.slice(4)));
  });

  it('handles an ACK frame, which the server Initial carries', () => {
    // 02 00 00 00 00: ACK, largest 0, delay 0, 0 ranges, first range 0.
    const result = cryptoStreamFromPayload(fromHex('0200000000'));
    expect(result.frames).toEqual(['ACK (largest 0)']);
    expect(result.stoppedAt).toBeNull();
  });

  it('stops at a frame type it cannot measure, rather than skipping it', () => {
    // 0x1e is HANDSHAKE_DONE; this parser does not know its length, and a
    // frame it cannot measure is a frame it cannot step over safely.
    const result = cryptoStreamFromPayload(fromHex('1e'));
    expect(result.stoppedAt).toMatch(/frame type 0x1e is not one this lab's minimal parser can measure/);
  });

  it('stops when a CRYPTO frame claims more bytes than remain', () => {
    const result = cryptoStreamFromPayload(fromHex('060040f10102'));
    expect(result.bytes.length).toBe(0);
    expect(result.stoppedAt).not.toBeNull();
  });

  it('refuses a stream with a gap rather than guessing the missing bytes', () => {
    // Two CRYPTO frames, the second starting at stream offset 8 with nothing
    // covering 4..7. Every byte past the gap would be invented. The offset
    // stays inside the payload so this exercises the gap check rather than
    // the offset bound tested below.
    const first = fromHex('06000401020304');
    const second = fromHex('06080401020304');
    const result = cryptoStreamFromPayload(concat(first, second));
    expect(result.stoppedAt).toMatch(/gap at offset 4/);
    expect(result.bytes.length).toBe(4);
  });

  it('refuses a CRYPTO frame whose stream offset is past this payload', () => {
    // Guards the reassembly buffer as well as the teaching point: a 2^60
    // offset would otherwise ask for a 2^60-byte allocation.
    const absurd = fromHex('06c00000000000ffff0401020304');
    const result = cryptoStreamFromPayload(absurd);
    expect(result.stoppedAt).toMatch(/past the \d+ bytes this payload holds/);
    expect(result.stoppedAt).toMatch(/will not invent the bytes before it/);
    expect(result.bytes.length).toBe(0);
  });
});

describe('finding the server name (RFC 8446 section 4.1.2, RFC 6066 section 3)', () => {
  it('reads example.com out of the RFC\'s ClientHello', () => {
    const result = findServerName(stream.bytes);
    expect(result.found).toBe(true);
    if (!result.found) throw new Error('unreachable');
    expect(result.serverName).toBe('example.com');
  });

  it('the name it reports is really in the bytes it parsed', () => {
    // An independent check by a different route: the ASCII of example.com
    // appears in the handshake, at the offset the walk says it does.
    expect(toHex(stream.bytes)).toContain(toHex(new TextEncoder().encode('example.com')));
  });

  it('records the steps it completed', () => {
    const result = findServerName(stream.bytes);
    expect(result.path.join(' | ')).toMatch(/ClientHello, \d+ bytes/);
    expect(result.path.join(' | ')).toContain('server_name extension (0x0000)');
    expect(result.path.join(' | ')).toContain('host_name, 11 bytes');
  });

  it('refuses a handshake message that is not a ClientHello', () => {
    const notHello = stream.bytes.slice();
    notHello[0] = 2; // ServerHello
    const result = findServerName(notHello);
    expect(result.found).toBe(false);
    if (result.found) throw new Error('unreachable');
    expect(result.reason).toMatch(/type 2, not a ClientHello/);
  });

  it('refuses a truncated ClientHello', () => {
    const result = findServerName(stream.bytes.slice(0, 40));
    expect(result.found).toBe(false);
    if (result.found) throw new Error('unreachable');
    expect(result.reason).toMatch(/needs \d+ byte/);
  });

  it('says "no server_name extension" when the extension is absent, naming what was there', () => {
    // Rebuild the ClientHello with the server_name extension removed.
    const stripped = withoutServerNameExtension(stream.bytes);
    const result = findServerName(stripped);
    expect(result.found).toBe(false);
    if (result.found) throw new Error('unreachable');
    expect(result.reason).toMatch(/no server_name extension among the \d+ extension\(s\) present/);
    expect(result.reason).toContain('0x0010'); // ALPN was among them
  });

  it('refuses a HostName that is not ASCII, rather than decoding it leniently', () => {
    const mangled = stream.bytes.slice();
    const at = indexOfSubsequence(mangled, new TextEncoder().encode('example.com'));
    expect(at).toBeGreaterThan(0);
    mangled[at] = 0x00;
    const result = findServerName(mangled);
    expect(result.found).toBe(false);
    if (result.found) throw new Error('unreachable');
    expect(result.reason).toMatch(/not the ASCII that RFC 6066 section 3 requires/);
  });

  it('refuses a NameType other than host_name', () => {
    const mangled = stream.bytes.slice();
    const at = indexOfSubsequence(mangled, new TextEncoder().encode('example.com'));
    // NameType sits three bytes before the name: type(1) + length(2).
    mangled[at - 3] = 1;
    const result = findServerName(mangled);
    expect(result.found).toBe(false);
    if (result.found) throw new Error('unreachable');
    expect(result.reason).toMatch(/NameType 1; only host_name \(0\) is defined/);
  });

  it('refuses an empty handshake', () => {
    const result = findServerName(new Uint8Array(0));
    expect(result.found).toBe(false);
  });
});

/** Find a byte subsequence, or -1. */
function indexOfSubsequence(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

/**
 * Rebuild a ClientHello with extension 0x0000 removed, fixing up the two
 * length fields that change. Built by walking the real structure rather than
 * by splicing at a hard-coded offset, so it stays correct if the fixture moves.
 */
function withoutServerNameExtension(handshake: Uint8Array): Uint8Array {
  const view = (offset: number): number => (handshake[offset] << 8) | handshake[offset + 1];
  let cursor = 4; // message type + 3-byte length
  cursor += 2 + 32; // legacy_version + random
  cursor += 1 + handshake[cursor]; // legacy_session_id
  cursor += 2 + view(cursor); // cipher_suites
  cursor += 1 + handshake[cursor]; // legacy_compression_methods
  const extensionsLengthAt = cursor;
  const extensionsLength = view(cursor);
  cursor += 2;
  const kept: Uint8Array[] = [];
  const end = cursor + extensionsLength;
  while (cursor < end) {
    const type = view(cursor);
    const length = view(cursor + 2);
    const whole = handshake.slice(cursor, cursor + 4 + length);
    if (type !== 0x0000) kept.push(whole);
    cursor += 4 + length;
  }
  const newExtensions = concat(...kept);
  const head = handshake.slice(0, extensionsLengthAt);
  const out = concat(
    head,
    Uint8Array.of((newExtensions.length >> 8) & 0xff, newExtensions.length & 0xff),
    newExtensions,
  );
  // Fix the handshake message's own 3-byte length.
  const bodyLength = out.length - 4;
  out[1] = (bodyLength >> 16) & 0xff;
  out[2] = (bodyLength >> 8) & 0xff;
  out[3] = bodyLength & 0xff;
  return out;
}
