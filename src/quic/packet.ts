import { concat } from './bytes';
import { MASK_LENGTH, SAMPLE_LENGTH } from './hp';

/**
 * QUIC packet formats — RFC 9000 sections 16 and 17, and Appendices A.2/A.3.
 *
 * Parsing is strict and fails closed. Every refusal below carries a message
 * naming the field and the document that requires it, because on this page a
 * refusal is a teaching surface rather than an error dialog.
 */

export class PacketFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PacketFormatError';
  }
}

/* ── Variable-length integers, RFC 9000 section 16 ───────────────────────── */

export interface Varint {
  /**
   * A bigint, not a number. QUIC varints reach 2^62-1 and RFC 9000 Appendix
   * A.1's own worked example decodes to 151,288,809,941,952,652 — above
   * Number.MAX_SAFE_INTEGER, where `value * 256 + byte` starts rounding
   * silently. That example is in this lab's test suite, so the lossy version
   * was caught rather than shipped.
   */
  readonly value: bigint;
  readonly length: number;
}

/** The two most significant bits of the first byte give log2 of the length. */
export function readVarint(bytes: Uint8Array, offset: number): Varint {
  if (offset >= bytes.length) {
    throw new PacketFormatError(
      `a variable-length integer starts at offset ${offset}, past the end of a ${bytes.length}-byte packet`,
    );
  }
  const prefix = bytes[offset] >> 6;
  const length = 1 << prefix;
  if (offset + length > bytes.length) {
    throw new PacketFormatError(
      `a ${length}-byte variable-length integer at offset ${offset} runs past the end of a ${bytes.length}-byte packet`,
    );
  }
  let value = BigInt(bytes[offset] & 0x3f);
  for (let i = 1; i < length; i++) value = (value << 8n) | BigInt(bytes[offset + i]);
  return { value, length };
}

/**
 * A varint used as a byte count or an offset into a packet.
 *
 * QUIC allows a Length or Offset field far larger than any datagram, so a
 * value that cannot be a real length is refused by name rather than wrapped
 * to something plausible. A UDP datagram cannot exceed 65,527 bytes of
 * payload, so anything past that is already impossible on the wire — but the
 * bound here is the array limit, because a packet may legitimately be
 * reassembled from more than one datagram in the CRYPTO stream.
 */
export function asLength(value: bigint, what: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new PacketFormatError(`${what} is ${value}, which is not a length this lab can read`);
  }
  return Number(value);
}

export function writeVarint(value: number | bigint): Uint8Array {
  // The integer check comes FIRST: BigInt(1.5) throws a RangeError whose
  // message says nothing about variable-length integers.
  if (typeof value === 'number' && !Number.isInteger(value)) {
    throw new PacketFormatError(`not a variable-length integer: ${value}`);
  }
  const n = typeof value === 'bigint' ? value : BigInt(value);
  if (n < 0n) throw new PacketFormatError(`not a variable-length integer: ${value}`);
  if (n <= 63n) return Uint8Array.of(Number(n));
  if (n <= 16383n) return Uint8Array.of(0x40 | Number(n >> 8n), Number(n & 0xffn));
  if (n <= 1073741823n) {
    return Uint8Array.of(
      0x80 | Number(n >> 24n),
      Number((n >> 16n) & 0xffn),
      Number((n >> 8n) & 0xffn),
      Number(n & 0xffn),
    );
  }
  if (n <= (1n << 62n) - 1n) {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, n | (3n << 62n));
    return out;
  }
  throw new PacketFormatError(`value too large for a variable-length integer: ${value}`);
}

/* ── Packet number encoding and decoding ─────────────────────────────────── */

/**
 * RFC 9000 Appendix A.2 — how many bytes a packet number needs.
 *
 * THE RFC'S OWN PSEUDOCODE IS WRONG HERE, and this implements the corrected
 * form. Erratum 9281 (Verified 2026-11-13, reported by Wenbin Zhou, verified
 * by Mike Bishop) replaces
 *
 *     num_bytes = ceil(min_bits / 8)
 * with
 *     num_bytes = floor(min_bits / 8) + 1
 *
 * Section 17.1 requires an encoding of n bits where 2^n > 2 * num_unacked. The
 * published pseudocode yields exactly 2 * num_unacked — one bit short — when
 * num_unacked is 2^7, 2^15 or 2^23, because min_bits is then a whole multiple
 * of 8 and `ceil` does not round it up. The verifier's note explains why
 * `floor(…) + 1` is the right correction rather than the reporter's `+ 2`,
 * which would add an unnecessary byte across three whole ranges.
 */
export function packetNumberLength(fullPacketNumber: bigint, largestAcked: bigint | null): number {
  const numUnacked = largestAcked === null ? fullPacketNumber + 1n : fullPacketNumber - largestAcked;
  if (numUnacked <= 0n) {
    throw new PacketFormatError(
      `packet number ${fullPacketNumber} is not greater than the largest acknowledged ${largestAcked}`,
    );
  }
  const minBits = numUnacked.toString(2).length; // floor(log2(n)) + 1
  return Math.min(4, Math.floor(minBits / 8) + 1);
}

export function encodePacketNumber(fullPacketNumber: bigint, length: number): Uint8Array {
  if (length < 1 || length > 4) {
    throw new PacketFormatError(`packet-number length must be 1 to 4 bytes, got ${length}`);
  }
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[length - 1 - i] = Number((fullPacketNumber >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

/**
 * RFC 9000 Appendix A.3 — reconstruct the full packet number from the
 * truncated bytes on the wire and the largest packet number already received.
 *
 * Only ONE worked example of this is exercised in the lab (the A.5 packet,
 * whose three bytes are the low 24 bits of 654360564); a receive window
 * walkthrough is a non-goal.
 */
export function decodePacketNumber(
  truncated: Uint8Array,
  largestReceived: bigint | null,
): bigint {
  const bits = BigInt(truncated.length * 8);
  let candidate = 0n;
  for (const byte of truncated) candidate = (candidate << 8n) | BigInt(byte);
  if (largestReceived === null) return candidate;

  const window = 1n << bits;
  const half = window >> 1n;
  const expected = largestReceived + 1n;
  const base = expected & ~(window - 1n);
  const value = base | candidate;
  if (value <= expected - half && value < (1n << 62n) - window) return value + window;
  if (value > expected + half && value >= window) return value - window;
  return value;
}

/* ── Headers ─────────────────────────────────────────────────────────────── */

export const QUIC_VERSION_1 = 0x00000001;

export type PacketForm = 'long' | 'short';

export type LongPacketType = 'Initial' | '0-RTT' | 'Handshake' | 'Retry';

const LONG_TYPES: readonly LongPacketType[] = ['Initial', '0-RTT', 'Handshake', 'Retry'];

export interface LongHeader {
  readonly form: 'long';
  readonly firstByte: number;
  readonly type: LongPacketType;
  readonly version: number;
  readonly destinationConnectionId: Uint8Array;
  readonly sourceConnectionId: Uint8Array;
  readonly token: Uint8Array;
  /** The Length field: packet-number bytes + payload + tag. */
  readonly length: number;
  readonly packetNumberOffset: number;
  readonly packetNumberLength: number;
}

export interface ShortHeader {
  readonly form: 'short';
  readonly firstByte: number;
  readonly destinationConnectionId: Uint8Array;
  readonly packetNumberOffset: number;
  readonly packetNumberLength: number;
}

export type Header = LongHeader | ShortHeader;

/**
 * Where the Packet Number field starts, and how long it is claimed to be,
 * reading a packet whose header protection has NOT yet been removed.
 *
 * The packet-number LENGTH is in the two protected bits of the first byte, so
 * before unmasking it is unknown — which is exactly why the sample is taken at
 * a fixed offset of 4 bytes past the start of the packet-number field
 * (RFC 9001 section 5.4.2). This returns the offset, which IS readable
 * unprotected, and leaves the length to the caller.
 */
export function packetNumberOffset(
  packet: Uint8Array,
  shortHeaderConnectionIdLength: number | null = null,
): number {
  if (packet.length === 0) throw new PacketFormatError('the packet is empty');
  const isLong = (packet[0] & 0x80) === 0x80;

  if (!isLong) {
    if (shortHeaderConnectionIdLength === null) {
      throw new PacketFormatError(
        'a short header carries no connection-ID length; the receiver must already know it (RFC 9000 section 17.3)',
      );
    }
    return 1 + shortHeaderConnectionIdLength;
  }

  let offset = 1;
  if (offset + 4 > packet.length) {
    throw new PacketFormatError('the packet ends inside the Version field');
  }
  const version = readUint32(packet, offset);
  offset += 4;
  if (version !== QUIC_VERSION_1) {
    throw new PacketFormatError(
      `unknown QUIC version 0x${version.toString(16).padStart(8, '0')}; this lab builds only version 1 (0x00000001), so no keys are derived`,
    );
  }
  offset = skipConnectionId(packet, offset, 'Destination');
  offset = skipConnectionId(packet, offset, 'Source');

  const type = LONG_TYPES[(packet[0] & 0x30) >> 4];
  if (type === 'Retry') {
    throw new PacketFormatError(
      'a Retry packet has no Packet Number field and no header protection (RFC 9001 section 5.4)',
    );
  }
  if (type === 'Initial') {
    const tokenLength = readVarint(packet, offset);
    offset += tokenLength.length + asLength(tokenLength.value, 'the Token Length field');
    if (offset > packet.length) {
      throw new PacketFormatError('the Token field runs past the end of the packet');
    }
  }
  const length = readVarint(packet, offset);
  offset += length.length;
  return offset;
}

function readUint32(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>>
    0
  );
}

function skipConnectionId(packet: Uint8Array, offset: number, which: string): number {
  if (offset >= packet.length) {
    throw new PacketFormatError(`the packet ends where the ${which} Connection ID Length byte should be`);
  }
  const length = packet[offset];
  if (length > 20) {
    throw new PacketFormatError(
      `${which} Connection ID Length is ${length}; RFC 9000 section 17.2 allows at most 20`,
    );
  }
  if (offset + 1 + length > packet.length) {
    throw new PacketFormatError(`the ${which} Connection ID runs past the end of the packet`);
  }
  return offset + 1 + length;
}

/**
 * The Version field of a long header, read before anything else happens.
 *
 * Separate from `packetNumberOffset` on purpose: the version has to be
 * checked BEFORE any key is derived, not as a side effect of locating the
 * packet number. An observer that derived version-1 keys and only then
 * noticed the packet was version 2 would have done work it had no business
 * doing, and the page would show a key set for a packet it cannot read.
 */
export function readVersion(packet: Uint8Array): number {
  if (packet.length === 0) throw new PacketFormatError('the packet is empty');
  if ((packet[0] & 0x80) !== 0x80) {
    throw new PacketFormatError('a short header carries no Version field (RFC 9000 section 17.3)');
  }
  if (packet.length < 5) throw new PacketFormatError('the packet ends inside the Version field');
  return readUint32(packet, 1);
}

export function assertKnownVersion(packet: Uint8Array): number {
  const version = readVersion(packet);
  if (version !== QUIC_VERSION_1) {
    throw new PacketFormatError(
      `unknown QUIC version 0x${version.toString(16).padStart(8, '0')}; this lab builds only version 1 (0x00000001), so no keys are derived`,
    );
  }
  return version;
}

/**
 * Read the Destination Connection ID out of a long header without needing any
 * key material. This is the whole input the observer in exhibit 4 gets, and it
 * comes out of the packet rather than from its caller.
 */
export function destinationConnectionId(packet: Uint8Array): Uint8Array {
  if (packet.length === 0) throw new PacketFormatError('the packet is empty');
  if ((packet[0] & 0x80) !== 0x80) {
    throw new PacketFormatError(
      'a short header does not carry its connection-ID length, so the ID cannot be read from the packet alone (RFC 9000 section 17.3)',
    );
  }
  if (packet.length < 6) throw new PacketFormatError('the packet ends before the Destination Connection ID');
  const length = packet[5];
  if (length > 20) {
    throw new PacketFormatError(
      `Destination Connection ID Length is ${length}; RFC 9000 section 17.2 allows at most 20`,
    );
  }
  if (6 + length > packet.length) {
    throw new PacketFormatError('the Destination Connection ID runs past the end of the packet');
  }
  return packet.slice(6, 6 + length);
}

/** Parse a header whose protection has already been removed. */
export function parseHeader(
  packet: Uint8Array,
  shortHeaderConnectionIdLength: number | null = null,
): Header {
  const pnOffset = packetNumberOffset(packet, shortHeaderConnectionIdLength);
  const pnLength = (packet[0] & 0x03) + 1;
  if (pnOffset + pnLength > packet.length) {
    throw new PacketFormatError(
      `the first byte claims a ${pnLength}-byte packet number at offset ${pnOffset}, which runs past the end of a ${packet.length}-byte packet`,
    );
  }
  const isLong = (packet[0] & 0x80) === 0x80;
  if (!isLong) {
    return {
      form: 'short',
      firstByte: packet[0],
      destinationConnectionId: packet.slice(1, 1 + (shortHeaderConnectionIdLength ?? 0)),
      packetNumberOffset: pnOffset,
      packetNumberLength: pnLength,
    };
  }
  const dcid = destinationConnectionId(packet);
  const scidLengthOffset = 6 + dcid.length;
  const scid = packet.slice(scidLengthOffset + 1, scidLengthOffset + 1 + packet[scidLengthOffset]);
  const type = LONG_TYPES[(packet[0] & 0x30) >> 4];
  let cursor = scidLengthOffset + 1 + scid.length;
  let token = new Uint8Array(0);
  if (type === 'Initial') {
    const tokenLength = readVarint(packet, cursor);
    cursor += tokenLength.length;
    const count = asLength(tokenLength.value, 'the Token Length field');
    token = packet.slice(cursor, cursor + count);
    cursor += count;
  }
  const length = readVarint(packet, cursor);
  return {
    form: 'long',
    firstByte: packet[0],
    type,
    version: readUint32(packet, 1),
    destinationConnectionId: dcid,
    sourceConnectionId: scid,
    token,
    length: asLength(length.value, 'the Length field'),
    packetNumberOffset: pnOffset,
    packetNumberLength: pnLength,
  };
}

/* ── Header protection, applied and removed ──────────────────────────────── */

/**
 * The sample window: 16 bytes starting 4 bytes after the START of the
 * packet-number field, whatever the packet number's real length
 * (RFC 9001 section 5.4.2).
 *
 * For A.2's 4-byte packet number that is the first 16 ciphertext bytes. For
 * A.3's 2-byte packet number it starts two bytes INTO the ciphertext, and for
 * A.5's 3-byte packet number one byte in. Those two are what catch an
 * implementation that samples from the start of the ciphertext instead.
 */
export function sampleRange(pnOffset: number, packetLength: number): { start: number; end: number } {
  const start = pnOffset + 4;
  const end = start + SAMPLE_LENGTH;
  if (end > packetLength) {
    throw new PacketFormatError(
      `a ${packetLength}-byte packet cannot supply a complete ${SAMPLE_LENGTH}-byte header-protection sample (it needs bytes ${start} to ${end - 1}); RFC 9001 section 5.4.2 requires such a packet to be discarded`,
    );
  }
  return { start, end };
}

export function headerProtectionSample(packet: Uint8Array, pnOffset: number): Uint8Array {
  const { start, end } = sampleRange(pnOffset, packet.length);
  return packet.slice(start, end);
}

/** How many of the first byte's low bits header protection covers. */
export function firstByteMaskBits(firstByte: number): number {
  return (firstByte & 0x80) === 0x80 ? 0x0f : 0x1f;
}

/**
 * Apply or remove the 5-byte mask. The operation is its own inverse, so one
 * function serves both directions — but the ORDER differs, and that is the
 * lesson of exhibit 3: a sender masks after sealing, a receiver unmasks the
 * first byte before it knows how many packet-number bytes to unmask.
 */
export function applyMask(
  packet: Uint8Array,
  pnOffset: number,
  mask: Uint8Array,
  pnLength: number,
): Uint8Array {
  if (mask.length < MASK_LENGTH) {
    throw new PacketFormatError(`header-protection mask must be ${MASK_LENGTH} bytes, got ${mask.length}`);
  }
  if (pnLength < 1 || pnLength > 4) {
    throw new PacketFormatError(`packet-number length must be 1 to 4 bytes, got ${pnLength}`);
  }
  if (pnOffset + pnLength > packet.length) {
    throw new PacketFormatError(
      `masking a ${pnLength}-byte packet number at offset ${pnOffset} would run past the end of a ${packet.length}-byte packet`,
    );
  }
  const out = packet.slice();
  out[0] ^= mask[0] & firstByteMaskBits(out[0]);
  for (let i = 0; i < pnLength; i++) out[pnOffset + i] ^= mask[1 + i];
  return out;
}

/** Build an unprotected long header for an Initial packet. */
export function buildInitialHeader(options: {
  destinationConnectionId: Uint8Array;
  sourceConnectionId: Uint8Array;
  token?: Uint8Array;
  version?: number;
  packetNumber: bigint;
  packetNumberLength: number;
  payloadLength: number;
  tagLength: number;
}): Uint8Array {
  const token = options.token ?? new Uint8Array(0);
  const firstByte = 0xc0 | (options.packetNumberLength - 1);
  const version = new Uint8Array(4);
  new DataView(version.buffer).setUint32(0, options.version ?? QUIC_VERSION_1);
  const length = options.packetNumberLength + options.payloadLength + options.tagLength;
  return concat(
    Uint8Array.of(firstByte),
    version,
    Uint8Array.of(options.destinationConnectionId.length),
    options.destinationConnectionId,
    Uint8Array.of(options.sourceConnectionId.length),
    options.sourceConnectionId,
    writeVarint(token.length),
    token,
    writeVarint(length),
    encodePacketNumber(options.packetNumber, options.packetNumberLength),
  );
}

/** Build an unprotected short header (a 1-RTT packet). */
export function buildShortHeader(options: {
  destinationConnectionId: Uint8Array;
  spinBit?: boolean;
  keyPhase?: boolean;
  packetNumber: bigint;
  packetNumberLength: number;
}): Uint8Array {
  const firstByte =
    0x40 |
    (options.spinBit ? 0x20 : 0) |
    (options.keyPhase ? 0x04 : 0) |
    (options.packetNumberLength - 1);
  return concat(
    Uint8Array.of(firstByte),
    options.destinationConnectionId,
    encodePacketNumber(options.packetNumber, options.packetNumberLength),
  );
}
