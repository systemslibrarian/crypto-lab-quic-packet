import { TAG_LENGTH, aesGcmSeal } from './aead';
import { bytesEqual, concat } from './bytes';
import { PacketFormatError } from './packet';

/**
 * RFC 9001 section 5.8 — the Retry Integrity Tag.
 *
 * The odd one out among the four worked packets. A Retry packet has no packet
 * number, no header protection and no encrypted payload; the AEAD is used with
 * an EMPTY plaintext, purely for the tag. Its key and nonce are fixed
 * constants published in the RFC, derived from a published secret by the same
 * HKDF-Expand-Label as everything else.
 *
 * The associated data is the Retry Pseudo-Packet: the Original Destination
 * Connection ID, length-prefixed, prepended to the transmitted Retry packet
 * with its tag removed. The ODCID is NOT on the wire — and that is the whole
 * security property. RFC 9001 section 5.8: "only an entity that observes an
 * Initial packet can send a valid Retry packet."
 */

export interface RetryTagInputs {
  readonly originalDestinationConnectionId: Uint8Array;
  /** The transmitted Retry packet INCLUDING its 16-byte tag. */
  readonly retryPacket: Uint8Array;
  readonly key: Uint8Array;
  readonly nonce: Uint8Array;
}

export interface RetryTagResult {
  readonly pseudoPacket: Uint8Array;
  readonly computedTag: Uint8Array;
  readonly tagOnTheWire: Uint8Array;
  readonly verified: boolean;
}

export function retryPseudoPacket(
  originalDestinationConnectionId: Uint8Array,
  retryPacketWithoutTag: Uint8Array,
): Uint8Array {
  if (originalDestinationConnectionId.length > 20) {
    throw new PacketFormatError(
      `Original Destination Connection ID is ${originalDestinationConnectionId.length} bytes; RFC 9000 section 17.2 allows at most 20`,
    );
  }
  return concat(
    Uint8Array.of(originalDestinationConnectionId.length),
    originalDestinationConnectionId,
    retryPacketWithoutTag,
  );
}

export async function retryIntegrityTag(inputs: RetryTagInputs): Promise<RetryTagResult> {
  if (inputs.retryPacket.length < TAG_LENGTH) {
    throw new PacketFormatError(
      `a Retry packet is ${inputs.retryPacket.length} bytes, shorter than the ${TAG_LENGTH}-byte integrity tag it must end with`,
    );
  }
  const withoutTag = inputs.retryPacket.subarray(0, inputs.retryPacket.length - TAG_LENGTH);
  const tagOnTheWire = inputs.retryPacket.subarray(inputs.retryPacket.length - TAG_LENGTH);
  const pseudoPacket = retryPseudoPacket(inputs.originalDestinationConnectionId, withoutTag);
  // Empty plaintext: AES-GCM over no data returns exactly the 16-byte tag.
  const computedTag = await aesGcmSeal(inputs.key, inputs.nonce, pseudoPacket, new Uint8Array(0));
  return {
    pseudoPacket,
    computedTag,
    tagOnTheWire,
    verified: bytesEqual(computedTag, tagOnTheWire),
  };
}
