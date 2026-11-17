import { describe, expect, it } from 'vitest';

import {
  A2_PACKET_NUMBER,
  A2_PAYLOAD,
  A2_PROTECTED_PACKET,
  A2_UNPROTECTED_HEADER,
  A5_PACKET,
  CONNECTION_ID,
  INITIAL_SALT,
} from '../fixtures/rfc9001';
import { AES_128_GCM } from './aead';
import { fromHex, toHex } from './bytes';
import { deriveInitialKeys, quicV1 } from './initial';
import { observe } from './observer';
import { buildInitialHeader } from './packet';
import { sealPacket } from './protect';

/**
 * Exhibit 4's observer. Acceptance check E, and the fail-closed paths.
 *
 * Invariant 2 is a property of the SIGNATURE: `observe` takes the packet bytes
 * and nothing else. There is no parameter it could be handed a key or a
 * connection ID through. The tests below are about what it does with them.
 */

describe('an on-path observer with no key material', () => {
  it('returns example.com given only the RFC\'s 1200-byte client Initial', async () => {
    const result = await observe(A2_PROTECTED_PACKET);
    expect(result.serverName).toBe('example.com');
    expect(result.refusal).toBeNull();
  });

  it('read the connection ID out of the packet rather than being told it', async () => {
    const result = await observe(A2_PROTECTED_PACKET);
    expect(toHex(result.connectionId as Uint8Array)).toBe(toHex(CONNECTION_ID));
    expect(result.path[0]).toContain(toHex(CONNECTION_ID));
  });

  it('derived the RFC\'s client keys from the salt and that ID alone', async () => {
    const result = await observe(A2_PROTECTED_PACKET);
    const expected = await deriveInitialKeys(CONNECTION_ID, quicV1(INITIAL_SALT));
    expect(toHex(result.keys?.client.key as Uint8Array)).toBe(toHex(expected.client.key));
  });

  it('recovered the packet number and the whole payload', async () => {
    const result = await observe(A2_PROTECTED_PACKET);
    expect(result.open?.packetNumber).toBe(A2_PACKET_NUMBER);
    expect(toHex(result.open?.plaintext as Uint8Array)).toBe(toHex(A2_PAYLOAD));
    expect(result.frames.some((f) => f.startsWith('CRYPTO'))).toBe(true);
  });

  /**
   * THE KILL FOR MUTATION (11).
   *
   * An observer handed the connection ID separately — or carrying the RFC's
   * ID as a constant — reproduces every test above, because every one of them
   * uses the RFC's own packet. The question that separates the two is what
   * happens to a DIFFERENT connection's packet: a real observer reads the new
   * ID off the wire, derives the matching keys and opens it; one that ignores
   * the packet's own ID derives the wrong keys and fails.
   *
   * The brief suggested a packet with a different connection ID and an
   * expectation of FAILURE. That version does not discriminate: altering the
   * ID bytes in the RFC's packet also alters the associated data, so the tag
   * fails either way. So the kill is the success case — and the altered-bytes
   * case is kept below as a fail-closed test, which is what it actually is.
   */
  it('opens a packet from a DIFFERENT connection, because it reads that ID too', async () => {
    const otherId = fromHex('0badc0ffee1dea00');
    expect(toHex(otherId)).not.toBe(toHex(CONNECTION_ID));
    const keys = await deriveInitialKeys(otherId, quicV1(INITIAL_SALT));

    const header = buildInitialHeader({
      destinationConnectionId: otherId,
      sourceConnectionId: new Uint8Array(0),
      packetNumber: 7n,
      packetNumberLength: 4,
      payloadLength: A2_PAYLOAD.length,
      tagLength: 16,
    });
    const sealed = await sealPacket({
      header,
      payload: A2_PAYLOAD,
      packetNumber: 7n,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });

    const result = await observe(sealed.packet);
    expect(toHex(result.connectionId as Uint8Array)).toBe(toHex(otherId));
    expect(result.open?.opened).toBe(true);
    expect(result.open?.packetNumber).toBe(7n);
    expect(result.serverName).toBe('example.com');
  });

  it('says "not opened" and shows NO server name when a payload bit is flipped', async () => {
    const tampered = A2_PROTECTED_PACKET.slice();
    tampered[600] ^= 0x01;
    const result = await observe(tampered);
    expect(result.open?.opened).toBe(false);
    expect(result.serverName).toBeNull();
    expect(result.refusal).toMatch(/authentication tag did not verify/);
    expect(result.open?.plaintext).toBeNull();
  });

  it('says "not opened" when the connection ID bytes are altered in place', async () => {
    // Fail-closed, not the mutation kill: changing the ID changes both the
    // derived keys AND the associated data, so this fails for either reason.
    const tampered = A2_PROTECTED_PACKET.slice();
    tampered[6] ^= 0x01;
    const result = await observe(tampered);
    expect(toHex(result.connectionId as Uint8Array)).not.toBe(toHex(CONNECTION_ID));
    expect(result.open?.opened).toBe(false);
    expect(result.serverName).toBeNull();
  });

  it('refuses an unknown version, showing it, with no keys derived', async () => {
    const other = A2_PROTECTED_PACKET.slice();
    other[1] = 0x6b;
    other[2] = 0x33;
    other[3] = 0x43;
    other[4] = 0xcf; // QUIC v2's version number, which this lab does not build
    const result = await observe(other);
    expect(result.refusal).toMatch(/unknown QUIC version 0x6b3343cf/);
    expect(result.keys).toBeNull();
    expect(result.serverName).toBeNull();
  });

  it('refuses a packet too short to supply a sample', async () => {
    const result = await observe(A2_PROTECTED_PACKET.slice(0, 30));
    expect(result.refusal).toMatch(/cannot supply a complete 16-byte header-protection sample/);
    expect(result.serverName).toBeNull();
  });

  it('refuses a short header, which carries neither a version nor its connection ID', async () => {
    // The version check comes first, so a short header is refused there — and
    // its message is the right one: a 1-RTT packet has no Version field at
    // all, and its connection-ID length is known only to the endpoints.
    const result = await observe(A5_PACKET);
    expect(result.refusal).toMatch(/carries no Version field/);
    expect(result.connectionId).toBeNull();
    expect(result.serverName).toBeNull();
  });

  it('refuses an empty packet', async () => {
    const result = await observe(new Uint8Array(0));
    expect(result.refusal).toMatch(/empty/);
    expect(result.serverName).toBeNull();
  });

  it('says "server name not found" for a packet that opens but carries no ClientHello', async () => {
    // A legitimate Initial packet whose payload is one PING frame and padding:
    // the tag verifies, the payload is recovered, and there is no name in it.
    // This is the branch where a demo that scanned for hostname-shaped bytes
    // would print something.
    const payload = new Uint8Array(1162);
    payload[0] = 0x01; // PING
    const header = buildInitialHeader({
      destinationConnectionId: CONNECTION_ID,
      sourceConnectionId: new Uint8Array(0),
      packetNumber: 2n,
      packetNumberLength: 4,
      payloadLength: payload.length,
      tagLength: 16,
    });
    expect(toHex(header)).toBe(toHex(A2_UNPROTECTED_HEADER));
    const keys = await deriveInitialKeys(CONNECTION_ID, quicV1(INITIAL_SALT));
    const sealed = await sealPacket({
      header,
      payload,
      packetNumber: 2n,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });

    const result = await observe(sealed.packet);
    expect(result.open?.opened).toBe(true);
    expect(result.serverName).toBeNull();
    expect(result.refusal).toMatch(/no CRYPTO frame|server name not found/);
    expect(result.frames).toContain('PING');
  });

  it('never reports a server name without an opened packet', async () => {
    // Invariant 3, asserted over every case above at once.
    for (const packet of [
      A2_PROTECTED_PACKET,
      A2_PROTECTED_PACKET.slice(0, 30),
      A5_PACKET,
      new Uint8Array(0),
    ]) {
      const result = await observe(packet);
      if (result.serverName !== null) {
        expect(result.open?.opened).toBe(true);
        expect(result.open?.plaintext).not.toBeNull();
      }
    }
  });
});
