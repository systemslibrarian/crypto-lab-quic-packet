import { type Aead, TAG_LENGTH, aeadNonce } from './aead';
import { concat, toHex } from './bytes';
import {
  type AesBlockRoute,
  MASK_LENGTH,
  aesHeaderProtectionMask,
  chachaHeaderProtectionMask,
} from './hp';
import {
  PacketFormatError,
  applyMask,
  decodePacketNumber,
  firstByteMaskBits,
  headerProtectionSample,
  packetNumberOffset,
  sampleRange,
} from './packet';

/**
 * Sealing and opening a whole QUIC packet, in the order RFC 9001 requires.
 *
 * THE ORDER IS THE LESSON, so it is in the shape of the code rather than in a
 * comment on top of code that could run either way:
 *
 *   sending   build the header -> seal the payload (header is the associated
 *             data) -> sample the ciphertext just produced -> mask the header
 *   receiving unmask the first byte -> only NOW is the packet-number length
 *             known -> unmask the packet number -> rebuild the associated data
 *             from the recovered header -> open
 *
 * A sender that masked before sealing would seal over a masked header, and the
 * receiver's associated data would never match. A receiver that assumed a
 * packet-number length would unmask the wrong bytes. Both are mutations in
 * this lab's ledger.
 */

export type HeaderProtectionKind = 'aes' | 'chacha20';

export interface PacketKeys {
  readonly key: Uint8Array;
  readonly iv: Uint8Array;
  readonly hp: Uint8Array;
}

export interface SealOptions {
  readonly header: Uint8Array;
  readonly payload: Uint8Array;
  readonly packetNumber: bigint;
  readonly keys: PacketKeys;
  readonly aead: Aead;
  readonly headerProtection: HeaderProtectionKind;
  /** Needed only for a short header, whose connection-ID length is implicit. */
  readonly connectionIdLength?: number;
  readonly aesBlockRoute?: AesBlockRoute;
}

export interface SealTrace {
  readonly nonce: Uint8Array;
  readonly associatedData: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
  readonly packetNumberOffset: number;
  readonly packetNumberLength: number;
  readonly sampleStart: number;
  readonly sample: Uint8Array;
  readonly mask: Uint8Array;
  readonly unprotectedHeader: Uint8Array;
  readonly protectedHeader: Uint8Array;
  readonly packet: Uint8Array;
}

async function mask(
  kind: HeaderProtectionKind,
  hp: Uint8Array,
  sample: Uint8Array,
  route: AesBlockRoute | undefined,
): Promise<Uint8Array> {
  return kind === 'aes'
    ? aesHeaderProtectionMask(hp, sample, route)
    : chachaHeaderProtectionMask(hp, sample);
}

/** Seal a packet and record every intermediate value the exhibits show. */
export async function sealPacket(options: SealOptions): Promise<SealTrace> {
  const { header, payload, packetNumber, keys, aead } = options;
  if (keys.key.length !== aead.keyLength) {
    throw new PacketFormatError(
      `${aead.name} needs a ${aead.keyLength}-byte key, got ${keys.key.length}`,
    );
  }

  // 1. The nonce and the associated data come from the UNPROTECTED header.
  const nonce = aeadNonce(keys.iv, packetNumber);
  const associatedData = header;

  // 2. Seal. The tag is the last 16 bytes of what comes back.
  const sealed = await aead.seal(keys.key, nonce, associatedData, payload);
  const ciphertext = sealed.subarray(0, sealed.length - TAG_LENGTH);
  const tag = sealed.subarray(sealed.length - TAG_LENGTH);

  // 3. Sample the ciphertext just produced, at a fixed offset from the start
  //    of the packet-number field.
  const draft = concat(header, sealed);
  const pnOffset = packetNumberOffset(draft, options.connectionIdLength ?? null);
  const pnLength = (header[0] & 0x03) + 1;
  if (pnOffset + pnLength !== header.length) {
    throw new PacketFormatError(
      `the header is ${header.length} bytes but its fields place the ${pnLength}-byte packet number at ${pnOffset}..${pnOffset + pnLength - 1}; the header and its own length field disagree`,
    );
  }
  const { start: sampleStart } = sampleRange(pnOffset, draft.length);
  const sample = headerProtectionSample(draft, pnOffset);

  // 4. Mask the header — last, never first.
  const headerMask = await mask(options.headerProtection, keys.hp, sample, options.aesBlockRoute);
  const packet = applyMask(draft, pnOffset, headerMask, pnLength);

  return {
    nonce,
    associatedData,
    ciphertext,
    tag,
    packetNumberOffset: pnOffset,
    packetNumberLength: pnLength,
    sampleStart,
    sample,
    mask: headerMask,
    unprotectedHeader: header,
    protectedHeader: packet.slice(0, header.length),
    packet,
  };
}

export interface OpenOptions {
  readonly packet: Uint8Array;
  readonly keys: PacketKeys;
  readonly aead: Aead;
  readonly headerProtection: HeaderProtectionKind;
  readonly connectionIdLength?: number;
  /** For the one worked packet-number reconstruction; null means "first packet". */
  readonly largestReceived?: bigint | null;
  readonly aesBlockRoute?: AesBlockRoute;
}

export interface OpenTrace {
  readonly opened: boolean;
  readonly reason: string | null;
  readonly packetNumberOffset: number;
  readonly sampleStart: number;
  readonly sample: Uint8Array;
  readonly mask: Uint8Array;
  readonly protectedFirstByte: number;
  readonly unprotectedFirstByte: number;
  readonly packetNumberLength: number;
  readonly truncatedPacketNumber: Uint8Array;
  readonly packetNumber: bigint;
  readonly nonce: Uint8Array;
  readonly associatedData: Uint8Array;
  readonly unprotectedHeader: Uint8Array;
  /** Present only when the authentication tag verified. Invariant 3. */
  readonly plaintext: Uint8Array | null;
}

/**
 * Remove header protection and open the payload.
 *
 * Returns a trace in both outcomes, because what a failed open DID manage to
 * recover is itself the teaching point: header protection comes off with no
 * authentication at all, so an attacker learns the packet number from a packet
 * whose tag then fails. `plaintext` is null unless the tag verified.
 */
export async function openPacket(options: OpenOptions): Promise<OpenTrace> {
  const { packet, keys, aead } = options;
  if (keys.key.length !== aead.keyLength) {
    throw new PacketFormatError(
      `${aead.name} needs a ${aead.keyLength}-byte key, got ${keys.key.length}`,
    );
  }

  // 1. The packet-number OFFSET is readable unprotected. Its LENGTH is not.
  const pnOffset = packetNumberOffset(packet, options.connectionIdLength ?? null);
  const { start: sampleStart } = sampleRange(pnOffset, packet.length);
  const sample = headerProtectionSample(packet, pnOffset);
  const headerMask = await mask(options.headerProtection, keys.hp, sample, options.aesBlockRoute);

  // 2. Unmask the first byte. Only now is the packet-number length known.
  const protectedFirstByte = packet[0];
  const unprotectedFirstByte = protectedFirstByte ^ (headerMask[0] & firstByteMaskBits(protectedFirstByte));
  const pnLength = (unprotectedFirstByte & 0x03) + 1;
  if (pnOffset + pnLength > packet.length) {
    throw new PacketFormatError(
      `after unmasking, the first byte claims a ${pnLength}-byte packet number at offset ${pnOffset}, which runs past the end of a ${packet.length}-byte packet`,
    );
  }

  // 3. Unmask the packet number, now that its length is known.
  const unprotected = applyMask(packet, pnOffset, headerMask, pnLength);
  const truncated = unprotected.slice(pnOffset, pnOffset + pnLength);
  const packetNumber = decodePacketNumber(truncated, options.largestReceived ?? null);

  // 4. Rebuild the associated data from the RECOVERED header and open.
  const unprotectedHeader = unprotected.slice(0, pnOffset + pnLength);
  const nonce = aeadNonce(keys.iv, packetNumber);
  const sealed = unprotected.subarray(pnOffset + pnLength);
  const plaintext =
    sealed.length < TAG_LENGTH
      ? null
      : await aead.open(keys.key, nonce, unprotectedHeader, sealed);

  return {
    opened: plaintext !== null,
    reason:
      plaintext !== null
        ? null
        : sealed.length < TAG_LENGTH
          ? `the packet carries ${sealed.length} bytes where a ${TAG_LENGTH}-byte authentication tag alone would need ${TAG_LENGTH}`
          : `the ${aead.name} authentication tag did not verify under this key and nonce`,
    packetNumberOffset: pnOffset,
    sampleStart,
    sample,
    mask: headerMask.slice(0, MASK_LENGTH),
    protectedFirstByte,
    unprotectedFirstByte,
    packetNumberLength: pnLength,
    truncatedPacketNumber: truncated,
    packetNumber,
    nonce,
    associatedData: unprotectedHeader,
    unprotectedHeader,
    plaintext,
  };
}

/** A one-line description of a trace, for logs and failure messages. */
export function describeOpen(trace: OpenTrace): string {
  return trace.opened
    ? `opened: packet number ${trace.packetNumber}, ${trace.plaintext?.length ?? 0} payload bytes`
    : `not opened: ${trace.reason} (mask ${toHex(trace.mask)})`;
}
