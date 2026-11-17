/**
 * Just enough TLS parsing to find the server name in a ClientHello carried by
 * a QUIC CRYPTO frame.
 *
 * FAIL CLOSED, ALWAYS. Every function here returns a reason instead of a guess
 * the moment the bytes stop matching what RFC 8446 and RFC 6066 describe. The
 * temptation in a demo like this is to scan the plaintext for something that
 * looks like a hostname and print it; that would make exhibit 4 a conjuring
 * trick rather than a parse, and it would print a server name for a packet
 * that does not contain one. So the only thing that ever produces a name here
 * is a walk down CRYPTO frame -> ClientHello -> extensions -> server_name ->
 * host_name, with a length check at every step.
 */

export type SniResult =
  | { readonly found: true; readonly serverName: string; readonly path: readonly string[] }
  | { readonly found: false; readonly reason: string; readonly path: readonly string[] };

/** RFC 9000 section 19.6 — the CRYPTO frame type. */
const FRAME_CRYPTO = 0x06;
/** RFC 9000 section 19.1 — PADDING. */
const FRAME_PADDING = 0x00;
/** RFC 9000 section 19.3 — ACK (and its ECN variant 0x03). */
const FRAME_ACK = 0x02;
const FRAME_ACK_ECN = 0x03;
/** RFC 9000 section 19.2 — PING. */
const FRAME_PING = 0x01;

class Reader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  get position(): number {
    return this.offset;
  }

  u8(what: string): number {
    this.need(1, what);
    return this.bytes[this.offset++];
  }

  u16(what: string): number {
    this.need(2, what);
    const value = (this.bytes[this.offset] << 8) | this.bytes[this.offset + 1];
    this.offset += 2;
    return value;
  }

  u24(what: string): number {
    this.need(3, what);
    const value =
      (this.bytes[this.offset] << 16) | (this.bytes[this.offset + 1] << 8) | this.bytes[this.offset + 2];
    this.offset += 3;
    return value;
  }

  take(length: number, what: string): Uint8Array {
    this.need(length, what);
    const slice = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  /**
   * RFC 9000 section 16 variable-length integer, read exactly.
   *
   * The bound here is Number.MAX_SAFE_INTEGER and nothing tighter, because
   * this reads FRAME TYPES as well as lengths and offsets: an earlier version
   * bounded every varint by the payload length and refused frame type 0x1e in
   * a one-byte payload. Where a value is used as an offset, the caller bounds
   * it — see `cryptoStreamFromPayload`.
   */
  varint(what: string): number {
    this.need(1, what);
    const length = 1 << (this.bytes[this.offset] >> 6);
    this.need(length, what);
    let value = BigInt(this.bytes[this.offset] & 0x3f);
    for (let i = 1; i < length; i++) value = (value << 8n) | BigInt(this.bytes[this.offset + i]);
    this.offset += length;
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new ParseStop(`${what} is ${value}, too large to use as a length or offset`);
    }
    return Number(value);
  }

  private need(count: number, what: string): void {
    if (this.offset + count > this.bytes.length) {
      throw new ParseStop(
        `${what} needs ${count} byte(s) at offset ${this.offset} but only ${this.remaining} remain`,
      );
    }
  }
}

class ParseStop extends Error {}

/**
 * Reassemble the CRYPTO stream from a QUIC packet payload.
 *
 * Only the frame types the four worked packets actually contain are decoded;
 * anything else stops the walk by name rather than being skipped, because a
 * frame this parser cannot measure is a frame it cannot step over safely.
 */
export function cryptoStreamFromPayload(payload: Uint8Array): {
  readonly bytes: Uint8Array;
  readonly frames: readonly string[];
  readonly stoppedAt: string | null;
} {
  const reader = new Reader(payload);
  const pieces: Array<{ offset: number; data: Uint8Array }> = [];
  const frames: string[] = [];
  let stoppedAt: string | null = null;
  let padding = 0;

  try {
    while (reader.remaining > 0) {
      const type = reader.varint('a frame type');
      if (type === FRAME_PADDING) {
        padding++;
        continue;
      }
      if (type === FRAME_PING) {
        frames.push('PING');
        continue;
      }
      if (type === FRAME_ACK || type === FRAME_ACK_ECN) {
        const largest = reader.varint('ACK Largest Acknowledged');
        reader.varint('ACK Delay');
        const rangeCount = reader.varint('ACK Range Count');
        reader.varint('ACK First Range');
        for (let i = 0; i < rangeCount; i++) {
          reader.varint('ACK Gap');
          reader.varint('ACK Range Length');
        }
        if (type === FRAME_ACK_ECN) {
          reader.varint('ECT0 Count');
          reader.varint('ECT1 Count');
          reader.varint('ECN-CE Count');
        }
        frames.push(`ACK (largest ${largest})`);
        continue;
      }
      if (type === FRAME_CRYPTO) {
        const offset = reader.varint('CRYPTO Offset');
        const length = reader.varint('CRYPTO Length');
        // This lab reassembles the CRYPTO stream from ONE packet, so a frame
        // whose stream offset is past what this payload could have filled
        // cannot be joined to anything here. Refusing it by name also bounds
        // the buffer allocated below, which a 2^60 offset would otherwise
        // ask for.
        if (offset > payload.length) {
          stoppedAt =
            `a CRYPTO frame starts at stream offset ${offset}, past the ${payload.length} bytes this payload holds; ` +
            'this lab reassembles the handshake from a single packet and will not invent the bytes before it';
          break;
        }
        pieces.push({ offset, data: reader.take(length, 'CRYPTO Data') });
        frames.push(`CRYPTO (offset ${offset}, ${length} bytes)`);
        continue;
      }
      stoppedAt = `frame type 0x${type.toString(16)} is not one this lab's minimal parser can measure, so the walk stops here rather than guessing its length`;
      break;
    }
  } catch (error) {
    stoppedAt = error instanceof ParseStop ? error.message : String(error);
  }

  if (padding > 0) frames.push(`PADDING (${padding} bytes)`);

  pieces.sort((a, b) => a.offset - b.offset);
  const end = pieces.reduce((n, p) => Math.max(n, p.offset + p.data.length), 0);
  const bytes = new Uint8Array(end);
  const covered = new Uint8Array(end);
  for (const piece of pieces) {
    bytes.set(piece.data, piece.offset);
    covered.fill(1, piece.offset, piece.offset + piece.data.length);
  }
  // A gap in the reassembled stream would make every offset past it a guess.
  const firstGap = covered.indexOf(0);
  if (firstGap >= 0) {
    return {
      bytes: bytes.slice(0, firstGap),
      frames,
      stoppedAt: stoppedAt ?? `the CRYPTO stream has a gap at offset ${firstGap}`,
    };
  }
  return { bytes, frames, stoppedAt };
}

/** RFC 6066 section 3 — the server_name extension. */
const EXT_SERVER_NAME = 0x0000;
/** RFC 8446 section 4.1.2 — the ClientHello handshake type. */
const HANDSHAKE_CLIENT_HELLO = 1;

/**
 * Find the host_name in a ClientHello's server_name extension.
 *
 * The returned `path` records the steps the walk actually completed, so the
 * page can show how far it got — including on the failure branches, which is
 * what makes "server name not found" informative rather than a shrug.
 */
export function findServerName(handshake: Uint8Array): SniResult {
  const path: string[] = [];
  const stop = (reason: string): SniResult => ({ found: false, reason, path });

  try {
    const reader = new Reader(handshake);
    const type = reader.u8('the handshake message type');
    if (type !== HANDSHAKE_CLIENT_HELLO) {
      return stop(`the handshake message is type ${type}, not a ClientHello (type 1)`);
    }
    const bodyLength = reader.u24('the handshake message length');
    path.push(`ClientHello, ${bodyLength} bytes`);
    const body = new Reader(reader.take(bodyLength, 'the ClientHello body'));

    body.u16('legacy_version');
    body.take(32, 'random');
    const sessionIdLength = body.u8('legacy_session_id length');
    body.take(sessionIdLength, 'legacy_session_id');
    const cipherSuitesLength = body.u16('cipher_suites length');
    body.take(cipherSuitesLength, 'cipher_suites');
    const compressionLength = body.u8('legacy_compression_methods length');
    body.take(compressionLength, 'legacy_compression_methods');
    path.push(`cipher_suites ${cipherSuitesLength / 2} offered`);

    if (body.remaining === 0) {
      return stop('the ClientHello carries no extensions, so it carries no server_name');
    }
    const extensionsLength = body.u16('extensions length');
    const extensions = new Reader(body.take(extensionsLength, 'the extensions block'));
    path.push(`extensions block, ${extensionsLength} bytes`);

    const seen: number[] = [];
    while (extensions.remaining > 0) {
      const extensionType = extensions.u16('an extension type');
      const extensionLength = extensions.u16('an extension length');
      const extensionData = extensions.take(extensionLength, `extension 0x${extensionType.toString(16)}`);
      seen.push(extensionType);
      if (extensionType !== EXT_SERVER_NAME) continue;

      path.push('server_name extension (0x0000)');
      const list = new Reader(extensionData);
      const listLength = list.u16('server_name_list length');
      const entries = new Reader(list.take(listLength, 'the server_name_list'));
      while (entries.remaining > 0) {
        const nameType = entries.u8('a NameType');
        const nameLength = entries.u16('a HostName length');
        const name = entries.take(nameLength, 'a HostName');
        if (nameType !== 0) {
          return stop(`the server_name entry has NameType ${nameType}; only host_name (0) is defined`);
        }
        const text = asciiHostName(name);
        if (text === null) {
          return stop('the HostName is not the ASCII that RFC 6066 section 3 requires');
        }
        path.push(`host_name, ${nameLength} bytes`);
        return { found: true, serverName: text, path };
      }
      return stop('the server_name extension is present but its list is empty');
    }
    return stop(
      `no server_name extension among the ${seen.length} extension(s) present (${seen
        .map((t) => `0x${t.toString(16).padStart(4, '0')}`)
        .join(', ')})`,
    );
  } catch (error) {
    return stop(error instanceof ParseStop ? error.message : String(error));
  }
}

/**
 * RFC 6066 section 3 requires HostName to be the ASCII representation of the
 * name. Anything outside printable ASCII is refused rather than decoded
 * leniently — a lenient decode is how a demo prints a hostname that was never
 * there.
 */
function asciiHostName(bytes: Uint8Array): string | null {
  if (bytes.length === 0) return null;
  let out = '';
  for (const byte of bytes) {
    if (byte < 0x21 || byte > 0x7e) return null;
    out += String.fromCharCode(byte);
  }
  return out;
}
