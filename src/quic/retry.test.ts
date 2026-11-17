import { describe, expect, it } from 'vitest';

import {
  A4_RETRY_PACKET,
  CONNECTION_ID,
  RETRY_KEY,
  RETRY_NONCE,
  RETRY_SECRET,
} from '../fixtures/rfc9001';
import { toHex } from './bytes';
import { hkdfExpandLabel } from './hkdf';
import { retryIntegrityTag, retryPseudoPacket } from './retry';

/**
 * RFC 9001 Appendix A.4 and section 5.8 — the Retry Integrity Tag.
 */

describe('the Retry integrity tag (RFC 9001 section 5.8, Appendix A.4)', () => {
  it('reproduces the tag the RFC\'s Retry packet carries', async () => {
    const result = await retryIntegrityTag({
      originalDestinationConnectionId: CONNECTION_ID,
      retryPacket: A4_RETRY_PACKET,
      key: RETRY_KEY,
      nonce: RETRY_NONCE,
    });
    expect(result.verified).toBe(true);
    expect(toHex(result.computedTag)).toBe(toHex(result.tagOnTheWire));
    expect(toHex(result.computedTag)).toBe(toHex(A4_RETRY_PACKET.slice(-16)));
  });

  it('derives the published key and nonce from the published secret', async () => {
    expect(toHex(await hkdfExpandLabel(RETRY_SECRET, 'quic key', 16))).toBe(toHex(RETRY_KEY));
    expect(toHex(await hkdfExpandLabel(RETRY_SECRET, 'quic iv', 12))).toBe(toHex(RETRY_NONCE));
  });

  it('prepends the length-prefixed ODCID, which is NOT on the wire', async () => {
    const withoutTag = A4_RETRY_PACKET.slice(0, -16);
    const pseudo = retryPseudoPacket(CONNECTION_ID, withoutTag);
    expect(pseudo[0]).toBe(CONNECTION_ID.length);
    expect(toHex(pseudo.slice(1, 1 + CONNECTION_ID.length))).toBe(toHex(CONNECTION_ID));
    expect(toHex(pseudo.slice(1 + CONNECTION_ID.length))).toBe(toHex(withoutTag));
    // The security property of section 5.8: the original connection ID is
    // absent from the transmitted packet, so only something that saw the
    // client's Initial can compute this tag.
    expect(toHex(A4_RETRY_PACKET)).not.toContain(toHex(CONNECTION_ID));
  });

  it('fails verification under a different original connection ID', async () => {
    const other = CONNECTION_ID.slice();
    other[0] ^= 0x01;
    const result = await retryIntegrityTag({
      originalDestinationConnectionId: other,
      retryPacket: A4_RETRY_PACKET,
      key: RETRY_KEY,
      nonce: RETRY_NONCE,
    });
    expect(result.verified).toBe(false);
    expect(toHex(result.computedTag)).not.toBe(toHex(result.tagOnTheWire));
  });

  it('fails verification when the Retry token is altered', async () => {
    const tampered = A4_RETRY_PACKET.slice();
    tampered[20] ^= 0x01;
    const result = await retryIntegrityTag({
      originalDestinationConnectionId: CONNECTION_ID,
      retryPacket: tampered,
      key: RETRY_KEY,
      nonce: RETRY_NONCE,
    });
    expect(result.verified).toBe(false);
  });

  it('seals an empty plaintext, so the tag is the whole output', async () => {
    const result = await retryIntegrityTag({
      originalDestinationConnectionId: CONNECTION_ID,
      retryPacket: A4_RETRY_PACKET,
      key: RETRY_KEY,
      nonce: RETRY_NONCE,
    });
    expect(result.computedTag.length).toBe(16);
  });

  it('refuses a packet shorter than the tag it must end with', async () => {
    await expect(
      retryIntegrityTag({
        originalDestinationConnectionId: CONNECTION_ID,
        retryPacket: new Uint8Array(15),
        key: RETRY_KEY,
        nonce: RETRY_NONCE,
      }),
    ).rejects.toThrow(/shorter than the 16-byte integrity tag/);
  });

  it('refuses an original connection ID over 20 bytes', () => {
    expect(() => retryPseudoPacket(new Uint8Array(21), A4_RETRY_PACKET)).toThrow(/at most 20/);
  });
});
