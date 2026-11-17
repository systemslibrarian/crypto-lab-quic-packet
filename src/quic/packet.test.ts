import { describe, expect, it } from 'vitest';

import {
  A2_PROTECTED_PACKET,
  A2_UNPROTECTED_HEADER,
  A3_PROTECTED_PACKET,
  A3_UNPROTECTED_HEADER,
  A4_RETRY_PACKET,
  A5_PACKET,
  A5_PACKET_NUMBER,
  A5_UNPROTECTED_HEADER,
  CONNECTION_ID,
} from '../fixtures/rfc9001';
import { fromHex, toHex } from './bytes';
import {
  PacketFormatError,
  applyMask,
  asLength,
  buildInitialHeader,
  buildShortHeader,
  decodePacketNumber,
  destinationConnectionId,
  encodePacketNumber,
  firstByteMaskBits,
  headerProtectionSample,
  packetNumberLength,
  packetNumberOffset,
  parseHeader,
  readVarint,
  sampleRange,
  writeVarint,
} from './packet';
import { rfcText, section } from '../../tests/rfc-text';

describe('variable-length integers (RFC 9000 section 16)', () => {
  /**
   * RFC 9000 section 16 prints its four worked examples in prose; they are
   * read out of the RFC text here rather than transcribed.
   */
  const rfc9000 = rfcText('rfc9000.txt');
  // The worked examples are in Appendix A.1, not section 16, and the decimal
  // values are printed with thousands separators.
  const block = section(
    rfc9000,
    'A.1.  Sample Variable-Length Integer Decoding',
    'A.2.  Sample Packet Number Encoding Algorithm',
  );

  const examples = [
    ...block.matchAll(/0x([0-9a-f]+)\s+decodes to\s+(?:the\s+decimal\s+value\s+)?([\d,]+)/g),
  ].map((m) => ({ hex: m[1], value: BigInt(m[2].replace(/,/g, '')) }));

  it('found the four worked examples phrased as "decodes to"', () => {
    // The appendix adds a fifth, 0x4025, phrased as "(as does the two-byte
    // sequence 0x4025)" — it has its own test below rather than a looser
    // regex here, because a regex loose enough to catch it also catches prose.
    expect(examples.map((e) => e.hex)).toEqual(['c2197c5eff14e88c', '9d7f3e7d', '7bbd', '25']);
    expect(block).toContain('as does');
    expect(block).toContain('0x4025');
  });

  it('decodes 0x4025 to 37 as well, the RFC\'s non-minimal encoding', () => {
    // RFC 9000 section 16 permits a longer encoding than necessary, and the
    // appendix points out that 0x4025 and 0x25 decode alike. A parser that
    // rejected the non-minimal form would reject legal packets.
    expect(readVarint(fromHex('4025'), 0).value).toBe(37n);
    expect(readVarint(fromHex('25'), 0).value).toBe(37n);
  });

  for (const example of examples) {
    it(`decodes 0x${example.hex} to ${example.value}`, () => {
      const bytes = fromHex(example.hex);
      const read = readVarint(bytes, 0);
      expect(read.value).toBe(example.value);
      expect(read.length).toBe(bytes.length);
    });
  }

  it('decodes the eight-byte example EXACTLY', () => {
    // 151,288,809,941,952,652 is above Number.MAX_SAFE_INTEGER, and this
    // example is the whole reason the field is a bigint: an earlier readVarint
    // accumulated into a number and came back 12 short with nothing to say so.
    const read = readVarint(fromHex('c2197c5eff14e88c'), 0);
    expect(read.value).toBe(151288809941952652n);
    expect(read.value).toBeGreaterThan(BigInt(Number.MAX_SAFE_INTEGER));
    // Going through a double loses the exact value — which is the point. Note
    // that the decimal LITERAL would be rounded too, so the comparison has to
    // be made in bigint.
    expect(BigInt(Number(read.value))).not.toBe(read.value);
  });

  it('refuses to treat a value that large as a length', () => {
    expect(() => asLength(151288809941952652n, 'the Length field')).toThrow(
      /not a length this lab can read/,
    );
  });

  it('round-trips the four length classes at their boundaries', () => {
    for (const [value, length] of [
      [0, 1],
      [63, 1],
      [64, 2],
      [16383, 2],
      [16384, 4],
      [1073741823, 4],
      [1073741824, 8],
    ] as const) {
      const encoded = writeVarint(value);
      expect(encoded.length, `${value}`).toBe(length);
      expect(readVarint(encoded, 0).value, `${value}`).toBe(BigInt(value));
    }
  });

  it('reads the A.2 header\'s own Length field', () => {
    // The field is at offset 16 of A.2's header: 0x449e, two-byte form, 1182
    // = 4 packet-number bytes + 1162 payload + 16 tag.
    const read = readVarint(A2_UNPROTECTED_HEADER, 16);
    expect(read.length).toBe(2);
    expect(read.value).toBe(BigInt(4 + 1162 + 16));
  });

  it('refuses a varint that runs past the end of the packet', () => {
    expect(() => readVarint(fromHex('40'), 0)).toThrow(PacketFormatError);
    expect(() => readVarint(fromHex('40'), 0)).toThrow(/runs past the end/);
    expect(() => readVarint(new Uint8Array(0), 0)).toThrow(/past the end/);
  });

  it('refuses to encode a negative or non-integer value', () => {
    expect(() => writeVarint(-1)).toThrow(/not a variable-length integer/);
    expect(() => writeVarint(1.5)).toThrow(/not a variable-length integer/);
  });
});

describe('packet-number encoding (RFC 9000 Appendix A.2, with erratum 9281)', () => {
  it('encodes to the byte lengths the appendix\'s own examples give', () => {
    // The appendix's worked example: largest acked 0xabe8b3, sending 0xac5c02
    // needs 2 bytes; sending 0xace8fe needs 3.
    expect(packetNumberLength(0xac5c02n, 0xabe8b3n)).toBe(2);
    expect(packetNumberLength(0xace8fen, 0xabe8b3n)).toBe(3);
  });

  it('applies erratum 9281 at the three boundary cases the published pseudocode gets wrong', () => {
    // Section 17.1 requires 2^n > 2 * num_unacked. At num_unacked = 2^7, 2^15
    // and 2^23 the published `ceil(min_bits / 8)` yields exactly 2 * d — one
    // bit short — because min_bits lands on a whole multiple of 8.
    // Erratum 9281 (Verified 2026-11-13) replaces it with
    // `floor(min_bits / 8) + 1`, which is what this asserts.
    for (const exponent of [7, 15, 23]) {
      const numUnacked = 1n << BigInt(exponent);
      const largestAcked = 1n << 40n;
      const sending = largestAcked + numUnacked;
      const chosen = packetNumberLength(sending, largestAcked);
      // The published formula would give exponent/8 bytes; the corrected one
      // gives one more, and only here.
      expect(chosen, `num_unacked = 2^${exponent}`).toBe(Math.floor((exponent + 1) / 8) + 1);
      expect(BigInt(2) ** BigInt(chosen * 8) > 2n * numUnacked, `2^n > 2d at 2^${exponent}`).toBe(
        true,
      );
    }
  });

  it('never gives an encoding that fails section 17.1\'s inequality', () => {
    // The property the erratum restores, checked across the ranges either
    // formula could disagree on.
    const largestAcked = 1n << 40n;
    for (let exponent = 1; exponent <= 24; exponent++) {
      for (const numUnacked of [
        (1n << BigInt(exponent)) - 1n,
        1n << BigInt(exponent),
        (1n << BigInt(exponent)) + 1n,
      ]) {
        const chosen = packetNumberLength(largestAcked + numUnacked, largestAcked);
        expect(
          BigInt(2) ** BigInt(chosen * 8) > 2n * numUnacked,
          `num_unacked = ${numUnacked}`,
        ).toBe(true);
      }
    }
  });

  it('never exceeds four bytes, which is the field\'s maximum', () => {
    expect(packetNumberLength((1n << 40n) + (1n << 32n), 1n << 40n)).toBe(4);
  });

  it('refuses a packet number not greater than the largest acknowledged', () => {
    expect(() => packetNumberLength(5n, 5n)).toThrow(/not greater than/);
    expect(() => packetNumberLength(4n, 5n)).toThrow(/not greater than/);
  });

  it('truncates to the low bytes, big-endian', () => {
    expect(toHex(encodePacketNumber(2n, 4))).toBe('00000002');
    expect(toHex(encodePacketNumber(1n, 2))).toBe('0001');
    // A.5's three bytes are the low 24 bits of 654360564 = 0x2700bff4.
    expect(toHex(encodePacketNumber(A5_PACKET_NUMBER, 3))).toBe('00bff4');
    expect(Number(A5_PACKET_NUMBER & 0xffffffn)).toBe(0x00bff4);
  });

  it('refuses a length outside one to four bytes', () => {
    expect(() => encodePacketNumber(1n, 0)).toThrow(/1 to 4 bytes/);
    expect(() => encodePacketNumber(1n, 5)).toThrow(/1 to 4 bytes/);
  });
});

describe('packet-number decoding (RFC 9000 Appendix A.3)', () => {
  it('reproduces the appendix\'s worked example', () => {
    // The appendix: largest received 0xa82f30ea, truncated 0x9b32, so the
    // reconstructed number is 0xa82f9b32.
    expect(decodePacketNumber(fromHex('9b32'), 0xa82f30ean)).toBe(0xa82f9b32n);
  });

  it('takes the truncated value as-is for the first packet', () => {
    expect(decodePacketNumber(fromHex('00bff4'), null)).toBe(0x00bff4n);
  });

  it('round-trips A.5\'s three bytes against a plausible receive state', () => {
    const encoded = encodePacketNumber(A5_PACKET_NUMBER, 3);
    expect(decodePacketNumber(encoded, A5_PACKET_NUMBER - 1n)).toBe(A5_PACKET_NUMBER);
  });

  it('picks the candidate closest to the expected number', () => {
    // A one-byte field around a window boundary: expecting 0x100, a wire
    // value of 0xff is the packet just before it, not 256 ahead.
    expect(decodePacketNumber(fromHex('ff'), 0xffn)).toBe(0xffn);
    expect(decodePacketNumber(fromHex('01'), 0xffn)).toBe(0x101n);
  });
});

describe('long headers (RFC 9000 section 17.2)', () => {
  it('finds the packet-number offset in A.2\'s packet without any key', () => {
    // 1 first byte + 4 version + 1 + 8 DCID + 1 + 0 SCID + 1 token length
    // + 2 length = 18.
    expect(packetNumberOffset(A2_PROTECTED_PACKET)).toBe(18);
    expect(packetNumberOffset(A2_UNPROTECTED_HEADER)).toBe(18);
  });

  it('finds the packet-number offset in A.3\'s packet', () => {
    expect(packetNumberOffset(A3_PROTECTED_PACKET)).toBe(18);
  });

  it('reads A.2\'s Destination Connection ID straight off the wire', () => {
    expect(toHex(destinationConnectionId(A2_PROTECTED_PACKET))).toBe(toHex(CONNECTION_ID));
  });

  it('parses A.2\'s unprotected header into its fields', () => {
    const header = parseHeader(A2_UNPROTECTED_HEADER);
    expect(header.form).toBe('long');
    if (header.form !== 'long') throw new Error('unreachable');
    expect(header.type).toBe('Initial');
    expect(header.version).toBe(0x00000001);
    expect(toHex(header.destinationConnectionId)).toBe(toHex(CONNECTION_ID));
    expect(header.sourceConnectionId.length).toBe(0);
    expect(header.token.length).toBe(0);
    expect(header.length).toBe(1182);
    expect(header.packetNumberLength).toBe(4);
    expect(header.packetNumberOffset).toBe(18);
  });

  it('parses A.3\'s unprotected header, which has a source connection ID', () => {
    const header = parseHeader(A3_UNPROTECTED_HEADER);
    if (header.form !== 'long') throw new Error('unreachable');
    expect(header.type).toBe('Initial');
    expect(header.destinationConnectionId.length).toBe(0);
    expect(toHex(header.sourceConnectionId)).toBe('f067a5502a4262b5');
    expect(header.packetNumberLength).toBe(2);
    expect(header.length).toBe(2 + 99 + 16);
  });

  it('rebuilds A.2\'s header byte for byte', () => {
    const built = buildInitialHeader({
      destinationConnectionId: CONNECTION_ID,
      sourceConnectionId: new Uint8Array(0),
      packetNumber: 2n,
      packetNumberLength: 4,
      payloadLength: 1162,
      tagLength: 16,
    });
    expect(toHex(built)).toBe(toHex(A2_UNPROTECTED_HEADER));
  });

  it('rebuilds A.3\'s header byte for byte', () => {
    const built = buildInitialHeader({
      destinationConnectionId: new Uint8Array(0),
      sourceConnectionId: fromHex('f067a5502a4262b5'),
      packetNumber: 1n,
      packetNumberLength: 2,
      payloadLength: 99,
      tagLength: 16,
    });
    expect(toHex(built)).toBe(toHex(A3_UNPROTECTED_HEADER));
  });

  it('refuses an unknown version, showing it, and derives nothing', () => {
    const packet = A2_PROTECTED_PACKET.slice();
    packet[1] = 0xaa;
    packet[2] = 0xbb;
    packet[3] = 0xcc;
    packet[4] = 0xdd;
    expect(() => packetNumberOffset(packet)).toThrow(/unknown QUIC version 0xaabbccdd/);
    expect(() => packetNumberOffset(packet)).toThrow(/no keys are derived/);
  });

  it('refuses a Retry packet, which has no packet number at all', () => {
    expect(() => packetNumberOffset(A4_RETRY_PACKET)).toThrow(/no Packet Number field/);
  });

  it('refuses a connection ID length over 20', () => {
    const packet = A2_PROTECTED_PACKET.slice();
    packet[5] = 21;
    expect(() => packetNumberOffset(packet)).toThrow(/at most 20/);
  });

  it('refuses a header that ends inside a field', () => {
    expect(() => packetNumberOffset(A2_PROTECTED_PACKET.slice(0, 3))).toThrow(/inside the Version/);
    expect(() => packetNumberOffset(A2_PROTECTED_PACKET.slice(0, 6))).toThrow(
      /runs past the end|ends where/,
    );
    expect(() => packetNumberOffset(new Uint8Array(0))).toThrow(/empty/);
  });

  it('refuses a packet-number length that would read past the end', () => {
    // Four packet-number bytes claimed, but the packet stops after two.
    const truncated = A2_UNPROTECTED_HEADER.slice(0, 20);
    expect(() => parseHeader(truncated)).toThrow(/runs past the end of a 20-byte packet/);
  });
});

describe('short headers (RFC 9000 section 17.3)', () => {
  it('rebuilds A.5\'s header byte for byte', () => {
    const built = buildShortHeader({
      destinationConnectionId: new Uint8Array(0),
      packetNumber: A5_PACKET_NUMBER,
      packetNumberLength: 3,
    });
    expect(toHex(built)).toBe(toHex(A5_UNPROTECTED_HEADER));
  });

  it('needs the connection-ID length from the receiver, not the packet', () => {
    expect(() => packetNumberOffset(A5_PACKET)).toThrow(/must already know it/);
    expect(packetNumberOffset(A5_PACKET, 0)).toBe(1);
    expect(packetNumberOffset(A5_PACKET, 8)).toBe(9);
  });

  it('cannot read a connection ID out of a short header at all', () => {
    expect(() => destinationConnectionId(A5_PACKET)).toThrow(/cannot be read from the packet alone/);
  });
});

describe('the header-protection sample window (RFC 9001 section 5.4.2)', () => {
  it('starts 4 bytes after the start of the packet-number field', () => {
    expect(sampleRange(18, 1200)).toEqual({ start: 22, end: 38 });
  });

  it('for A.2\'s 4-byte packet number that is the first ciphertext byte', () => {
    const sample = headerProtectionSample(A2_PROTECTED_PACKET, 18);
    expect(toHex(sample)).toBe(toHex(A2_PROTECTED_PACKET.slice(22, 38)));
    // The header is 22 bytes, so the sample begins exactly at the ciphertext.
    expect(A2_UNPROTECTED_HEADER.length).toBe(22);
  });

  it('for A.3\'s 2-byte packet number it starts TWO bytes into the ciphertext', () => {
    // This is what catches an implementation that samples from the start of
    // the ciphertext: on A.2 the two are the same bytes, and on A.3 they are
    // not. A.3's header is 20 bytes and the sample starts at 22.
    expect(A3_UNPROTECTED_HEADER.length).toBe(20);
    const sample = headerProtectionSample(A3_PROTECTED_PACKET, 18);
    expect(toHex(sample)).toBe(toHex(A3_PROTECTED_PACKET.slice(22, 38)));
    expect(toHex(sample)).not.toBe(toHex(A3_PROTECTED_PACKET.slice(20, 36)));
  });

  it('for A.5\'s 3-byte packet number it skips ONE ciphertext byte', () => {
    expect(A5_UNPROTECTED_HEADER.length).toBe(4);
    const sample = headerProtectionSample(A5_PACKET, 1);
    expect(toHex(sample)).toBe(toHex(A5_PACKET.slice(5, 21)));
  });

  it('refuses a packet too short to supply a complete sample', () => {
    // RFC 9001 section 5.4.2: "An endpoint MUST discard packets that are not
    // long enough to contain a complete sample."
    expect(() => sampleRange(18, 37)).toThrow(/cannot supply a complete 16-byte/);
    expect(() => sampleRange(18, 37)).toThrow(/requires such a packet to be discarded/);
    expect(() => sampleRange(18, 38)).not.toThrow();
    expect(() => headerProtectionSample(A5_PACKET.slice(0, 20), 1)).toThrow(/complete 16-byte/);
  });
});

describe('the masked bits of the first byte (RFC 9001 section 5.4)', () => {
  it('covers four bits of a long header and five of a short one', () => {
    expect(firstByteMaskBits(0xc3)).toBe(0x0f);
    expect(firstByteMaskBits(0x42)).toBe(0x1f);
  });

  it('is its own inverse', () => {
    const mask = fromHex('437b9aec36');
    const once = applyMask(A2_UNPROTECTED_HEADER, 18, mask, 4);
    const twice = applyMask(once, 18, mask, 4);
    expect(toHex(twice)).toBe(toHex(A2_UNPROTECTED_HEADER));
  });

  it('leaves the bits above the mask width alone', () => {
    const mask = new Uint8Array([0xff, 0, 0, 0, 0]);
    // A long header: only the low four bits may move.
    const long = applyMask(A2_UNPROTECTED_HEADER, 18, mask, 4);
    expect(long[0] & 0xf0).toBe(A2_UNPROTECTED_HEADER[0] & 0xf0);
    expect(long[0] & 0x0f).toBe((A2_UNPROTECTED_HEADER[0] & 0x0f) ^ 0x0f);
    // A short header: five bits.
    const short = applyMask(A5_UNPROTECTED_HEADER, 1, mask, 3);
    expect(short[0] & 0xe0).toBe(A5_UNPROTECTED_HEADER[0] & 0xe0);
  });

  it('does not mutate the packet it was given', () => {
    const before = toHex(A2_UNPROTECTED_HEADER);
    applyMask(A2_UNPROTECTED_HEADER, 18, fromHex('437b9aec36'), 4);
    expect(toHex(A2_UNPROTECTED_HEADER)).toBe(before);
  });

  it('refuses a short mask or an out-of-range packet-number length', () => {
    expect(() => applyMask(A2_UNPROTECTED_HEADER, 18, fromHex('437b9a'), 4)).toThrow(/5 bytes/);
    expect(() => applyMask(A2_UNPROTECTED_HEADER, 18, fromHex('437b9aec36'), 5)).toThrow(
      /1 to 4 bytes/,
    );
  });

  it('refuses to mask past the end of the packet', () => {
    expect(() => applyMask(A2_UNPROTECTED_HEADER.slice(0, 20), 18, fromHex('437b9aec36'), 4)).toThrow(
      /run past the end/,
    );
  });
});
