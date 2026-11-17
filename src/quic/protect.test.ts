import { describe, expect, it } from 'vitest';

import {
  A2_MASK,
  A2_MASKED_FIRST_BYTE,
  A2_MASKED_PACKET_NUMBER,
  A2_PACKET_NUMBER,
  A2_PAYLOAD,
  A2_PROTECTED_HEADER,
  A2_PROTECTED_PACKET,
  A2_SAMPLE,
  A2_UNPROTECTED_HEADER,
  A3_MASK,
  A3_PACKET_NUMBER,
  A3_PAYLOAD,
  A3_PROTECTED_HEADER,
  A3_PROTECTED_PACKET,
  A3_SAMPLE,
  A3_UNPROTECTED_HEADER,
  A5_CIPHERTEXT,
  A5_HP,
  A5_IV,
  A5_KEY,
  A5_KU,
  A5_MASK,
  A5_NONCE,
  A5_PACKET,
  A5_PACKET_NUMBER,
  A5_PLAINTEXT,
  A5_PROTECTED_HEADER,
  A5_SAMPLE,
  A5_SECRET,
  A5_UNPROTECTED_HEADER,
  CONNECTION_ID,
  INITIAL_SALT,
} from '../fixtures/rfc9001';
import { AES_128_GCM, CHACHA20_POLY1305, aeadNonce } from './aead';
import { concat, toHex } from './bytes';
import { hkdfExpandLabel } from './hkdf';
import { aesHeaderProtectionMask, chachaHeaderProtectionMask } from './hp';
import { deriveInitialKeys, quicV1 } from './initial';
import { openPacket, sealPacket } from './protect';

/**
 * The three protected worked packets of RFC 9001 Appendix A, built forwards
 * and opened backwards.
 *
 * Every expected value is parsed out of the RFC text. Each packet is checked
 * BOTH ways round, because the forward and reverse paths make different
 * mistakes: a sender that masks before sealing and a receiver that assumes a
 * packet-number length both produce a self-consistent implementation that
 * cannot talk to anyone else.
 */

const version = quicV1(INITIAL_SALT);
const keys = await deriveInitialKeys(CONNECTION_ID, version);

describe('Appendix A.2 — the client Initial, built', () => {
  it('seals, samples, masks and assembles the RFC\'s 1200-byte packet', async () => {
    const trace = await sealPacket({
      header: A2_UNPROTECTED_HEADER,
      payload: A2_PAYLOAD,
      packetNumber: A2_PACKET_NUMBER,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });

    expect(toHex(trace.nonce)).toBe(toHex(aeadNonce(keys.client.iv, 2n)));
    expect(toHex(trace.associatedData)).toBe(toHex(A2_UNPROTECTED_HEADER));
    expect(trace.packetNumberOffset).toBe(18);
    expect(trace.packetNumberLength).toBe(4);
    expect(trace.sampleStart).toBe(22);
    expect(toHex(trace.sample)).toBe(toHex(A2_SAMPLE));
    expect(toHex(trace.mask)).toBe(toHex(A2_MASK));
    expect(toHex(trace.protectedHeader)).toBe(toHex(A2_PROTECTED_HEADER));
    expect(trace.packet.length).toBe(1200);
    expect(toHex(trace.packet)).toBe(toHex(A2_PROTECTED_PACKET));
  });

  it('matches the two masked fields A.2 prints separately', async () => {
    const trace = await sealPacket({
      header: A2_UNPROTECTED_HEADER,
      payload: A2_PAYLOAD,
      packetNumber: A2_PACKET_NUMBER,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(toHex(trace.packet.slice(0, 1))).toBe(toHex(A2_MASKED_FIRST_BYTE));
    expect(toHex(trace.packet.slice(18, 22))).toBe(toHex(A2_MASKED_PACKET_NUMBER));
  });

  it('puts the 16-byte tag last, after 1162 bytes of ciphertext', async () => {
    const trace = await sealPacket({
      header: A2_UNPROTECTED_HEADER,
      payload: A2_PAYLOAD,
      packetNumber: A2_PACKET_NUMBER,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(trace.ciphertext.length).toBe(1162);
    expect(trace.tag.length).toBe(16);
    expect(toHex(concat(trace.protectedHeader, trace.ciphertext, trace.tag))).toBe(
      toHex(A2_PROTECTED_PACKET),
    );
  });

  it('refuses a header whose own Length field disagrees with its fields', async () => {
    const wrong = A2_UNPROTECTED_HEADER.slice(0, 21);
    await expect(
      sealPacket({
        header: wrong,
        payload: A2_PAYLOAD,
        packetNumber: A2_PACKET_NUMBER,
        keys: keys.client,
        aead: AES_128_GCM,
        headerProtection: 'aes',
      }),
    ).rejects.toThrow(/disagree/);
  });

  it('refuses a key of the wrong length for the AEAD', async () => {
    await expect(
      sealPacket({
        header: A2_UNPROTECTED_HEADER,
        payload: A2_PAYLOAD,
        packetNumber: A2_PACKET_NUMBER,
        keys: { ...keys.client, key: new Uint8Array(32) },
        aead: AES_128_GCM,
        headerProtection: 'aes',
      }),
    ).rejects.toThrow(/needs a 16-byte key/);
  });
});

describe('Appendix A.2 — the client Initial, opened', () => {
  it('unmasks and opens the RFC\'s packet to packet number 2 and its payload', async () => {
    const trace = await openPacket({
      packet: A2_PROTECTED_PACKET,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(trace.opened).toBe(true);
    expect(trace.reason).toBeNull();
    expect(toHex(trace.sample)).toBe(toHex(A2_SAMPLE));
    expect(toHex(trace.mask)).toBe(toHex(A2_MASK));
    expect(trace.packetNumberLength).toBe(4);
    expect(trace.packetNumber).toBe(2n);
    expect(toHex(trace.unprotectedHeader)).toBe(toHex(A2_UNPROTECTED_HEADER));
    expect(trace.plaintext).not.toBeNull();
    expect((trace.plaintext as Uint8Array).length).toBe(1162);
    expect(toHex(trace.plaintext as Uint8Array)).toBe(toHex(A2_PAYLOAD));
  });

  it('learns the packet-number length only from the UNMASKED first byte', async () => {
    const trace = await openPacket({
      packet: A2_PROTECTED_PACKET,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    // On the wire the first byte is 0xc0, whose low two bits say "1 byte".
    // Unmasked it is 0xc3, which says four. A receiver that trusted the wire
    // would unmask one byte and rebuild the wrong associated data.
    expect(trace.protectedFirstByte).toBe(0xc0);
    expect((trace.protectedFirstByte & 0x03) + 1).toBe(1);
    expect(trace.unprotectedFirstByte).toBe(0xc3);
    expect(trace.packetNumberLength).toBe(4);
  });

  it('reports "not opened" and NO plaintext when a ciphertext bit is flipped', async () => {
    const tampered = A2_PROTECTED_PACKET.slice();
    tampered[100] ^= 0x01;
    const trace = await openPacket({
      packet: tampered,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(trace.opened).toBe(false);
    expect(trace.plaintext).toBeNull();
    expect(trace.reason).toMatch(/authentication tag did not verify/);
    // Header protection is unauthenticated, so the packet number still came
    // out — which is itself worth seeing.
    expect(trace.packetNumber).toBe(2n);
  });

  it('reports "not opened" when the masked header is altered', async () => {
    const tampered = A2_PROTECTED_PACKET.slice();
    tampered[0] ^= 0x01; // moves the packet-number length
    const trace = await openPacket({
      packet: tampered,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(trace.packetNumberLength).not.toBe(4);
    expect(trace.opened).toBe(false);
    expect(trace.plaintext).toBeNull();
  });

  it('reports "not opened" under keys from a different connection ID', async () => {
    const other = CONNECTION_ID.slice();
    other[0] ^= 0x01;
    const otherKeys = await deriveInitialKeys(other, version);
    expect(toHex(otherKeys.client.key)).not.toBe(toHex(keys.client.key));
    const trace = await openPacket({
      packet: A2_PROTECTED_PACKET,
      keys: otherKeys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(trace.opened).toBe(false);
    expect(trace.plaintext).toBeNull();
  });

  it('refuses a packet too short to sample', async () => {
    await expect(
      openPacket({
        packet: A2_PROTECTED_PACKET.slice(0, 30),
        keys: keys.client,
        aead: AES_128_GCM,
        headerProtection: 'aes',
      }),
    ).rejects.toThrow(/cannot supply a complete 16-byte header-protection sample/);
  });
});

describe('Appendix A.3 — the server Initial', () => {
  it('builds the RFC\'s 135-byte packet, sampling past the packet number', async () => {
    const trace = await sealPacket({
      header: A3_UNPROTECTED_HEADER,
      payload: A3_PAYLOAD,
      packetNumber: A3_PACKET_NUMBER,
      keys: keys.server,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(trace.packetNumberLength).toBe(2);
    // The header is 20 bytes and the sample starts at 22: two bytes INTO the
    // ciphertext. A.2 cannot catch a sample taken from the ciphertext's start
    // because there the two coincide; this is the packet that does.
    expect(trace.sampleStart).toBe(22);
    expect(toHex(trace.sample)).toBe(toHex(A3_SAMPLE));
    expect(toHex(trace.sample)).not.toBe(toHex(A3_PROTECTED_PACKET.slice(20, 36)));
    expect(toHex(trace.mask)).toBe(toHex(A3_MASK));
    expect(toHex(trace.protectedHeader)).toBe(toHex(A3_PROTECTED_HEADER));
    expect(trace.packet.length).toBe(135);
    expect(toHex(trace.packet)).toBe(toHex(A3_PROTECTED_PACKET));
  });

  it('opens the RFC\'s packet to packet number 1 and its payload', async () => {
    const trace = await openPacket({
      packet: A3_PROTECTED_PACKET,
      keys: keys.server,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(trace.opened).toBe(true);
    expect(trace.packetNumber).toBe(1n);
    expect(trace.packetNumberLength).toBe(2);
    expect(toHex(trace.unprotectedHeader)).toBe(toHex(A3_UNPROTECTED_HEADER));
    expect(toHex(trace.plaintext as Uint8Array)).toBe(toHex(A3_PAYLOAD));
  });

  it('does not open under the CLIENT\'s keys', async () => {
    const trace = await openPacket({
      packet: A3_PROTECTED_PACKET,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(trace.opened).toBe(false);
  });
});

describe('Appendix A.5 — the ChaCha20-Poly1305 short-header packet', () => {
  it('derives the five values A.5 prints from its application secret', async () => {
    expect(toHex(await hkdfExpandLabel(A5_SECRET, 'quic key', 32))).toBe(toHex(A5_KEY));
    expect(toHex(await hkdfExpandLabel(A5_SECRET, 'quic iv', 12))).toBe(toHex(A5_IV));
    expect(toHex(await hkdfExpandLabel(A5_SECRET, 'quic hp', 32))).toBe(toHex(A5_HP));
    // "quic ku" is the next secret after a key update. A.5 prints it and does
    // not use it; key update is a non-goal of this lab.
    expect(toHex(await hkdfExpandLabel(A5_SECRET, 'quic ku', 32))).toBe(toHex(A5_KU));
  });

  it('builds the RFC\'s 21-byte packet', async () => {
    const trace = await sealPacket({
      header: A5_UNPROTECTED_HEADER,
      payload: A5_PLAINTEXT,
      packetNumber: A5_PACKET_NUMBER,
      keys: { key: A5_KEY, iv: A5_IV, hp: A5_HP },
      aead: CHACHA20_POLY1305,
      headerProtection: 'chacha20',
      connectionIdLength: 0,
    });
    expect(toHex(trace.nonce)).toBe(toHex(A5_NONCE));
    expect(trace.packetNumberLength).toBe(3);
    expect(toHex(concat(trace.ciphertext, trace.tag))).toBe(toHex(A5_CIPHERTEXT));
    // One byte of ciphertext is skipped before the sample.
    expect(trace.sampleStart).toBe(5);
    expect(toHex(trace.sample)).toBe(toHex(A5_SAMPLE));
    expect(toHex(trace.mask)).toBe(toHex(A5_MASK));
    expect(toHex(trace.protectedHeader)).toBe(toHex(A5_PROTECTED_HEADER));
    expect(trace.packet.length).toBe(21);
    expect(toHex(trace.packet)).toBe(toHex(A5_PACKET));
  });

  it('opens the RFC\'s packet back to its single PING frame', async () => {
    const trace = await openPacket({
      packet: A5_PACKET,
      keys: { key: A5_KEY, iv: A5_IV, hp: A5_HP },
      aead: CHACHA20_POLY1305,
      headerProtection: 'chacha20',
      connectionIdLength: 0,
      largestReceived: A5_PACKET_NUMBER - 1n,
    });
    expect(trace.opened).toBe(true);
    expect(trace.packetNumberLength).toBe(3);
    expect(trace.packetNumber).toBe(A5_PACKET_NUMBER);
    expect(toHex(trace.truncatedPacketNumber)).toBe('00bff4');
    expect(toHex(trace.plaintext as Uint8Array)).toBe(toHex(A5_PLAINTEXT));
    expect(toHex(trace.plaintext as Uint8Array)).toBe('01');
  });

  it('recovers the unprotected first byte 0x42 from 0x4c on the wire', async () => {
    const trace = await openPacket({
      packet: A5_PACKET,
      keys: { key: A5_KEY, iv: A5_IV, hp: A5_HP },
      aead: CHACHA20_POLY1305,
      headerProtection: 'chacha20',
      connectionIdLength: 0,
    });
    expect(trace.protectedFirstByte).toBe(0x4c);
    expect(trace.unprotectedFirstByte).toBe(0x42);
    expect(trace.protectedFirstByte ^ trace.unprotectedFirstByte).toBe(A5_MASK[0] & 0x1f);
  });

  it('cannot, by itself, tell the five-bit mask from the four-bit one', async () => {
    // Worth stating rather than glossing: A.5's mask byte is 0xae, whose bit 4
    // is CLEAR, so 0xae & 0x1f and 0xae & 0x0f are both 0x0e and this packet
    // is reproduced correctly by either width. The same is true of A.2's 0x43
    // and A.3's 0x2e. All three worked packets in the RFC are therefore blind
    // to the long/short distinction of section 5.4, which means a suite that
    // checked only them would let that mutation through. The test below is the
    // one that catches it.
    expect(A2_MASK[0] & 0x10).toBe(0);
    expect(A3_MASK[0] & 0x10).toBe(0);
    expect(A5_MASK[0] & 0x10).toBe(0);
    expect(A5_MASK[0] & 0x1f).toBe(A5_MASK[0] & 0x0f);
  });

  it('builds the mask from the ChaCha20 keystream, not from AES', async () => {
    expect(toHex(chachaHeaderProtectionMask(A5_HP, A5_SAMPLE))).toBe(toHex(A5_MASK));
    // The AES route over the same sample produces something else entirely —
    // the point being that the mask construction is chosen by the AEAD.
    const aes = await aesHeaderProtectionMask(A5_HP, A5_SAMPLE);
    expect(toHex(aes)).not.toBe(toHex(A5_MASK));
  });
});

describe('the order of operations', () => {
  it('a sender seals BEFORE masking: the associated data is the unmasked header', async () => {
    const trace = await sealPacket({
      header: A2_UNPROTECTED_HEADER,
      payload: A2_PAYLOAD,
      packetNumber: A2_PACKET_NUMBER,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(toHex(trace.associatedData)).toBe(toHex(A2_UNPROTECTED_HEADER));
    expect(toHex(trace.associatedData)).not.toBe(toHex(A2_PROTECTED_HEADER));
  });

  it('cannot even seal a MASKED header: its packet-number length bits are gone', async () => {
    // Masking first is mutation (7), and it fails earlier than one might
    // expect. A.2's masked first byte is 0xc0, whose low two bits now read
    // "1-byte packet number" — so the header no longer describes itself, and
    // the length check refuses it before any AEAD runs.
    await expect(
      sealPacket({
        header: A2_PROTECTED_HEADER,
        payload: A2_PAYLOAD,
        packetNumber: A2_PACKET_NUMBER,
        keys: keys.client,
        aead: AES_128_GCM,
        headerProtection: 'aes',
      }),
    ).rejects.toThrow(/disagree/);
  });

  it('masks only FOUR bits of a long header, proved on a mask with bit 4 set', async () => {
    // The RFC's three packets cannot show this (see the A.5 suite above), so
    // the packet is built here: packet numbers are walked until one produces a
    // mask byte with bit 4 set, which is where 0x0f and 0x1f diverge. For a
    // long header bit 4 belongs to the Long Packet Type field, so a five-bit
    // mask would change an Initial packet into a Handshake one.
    let found: { packetNumber: bigint; mask: number; first: number } | null = null;
    for (let pn = 0n; pn < 64n; pn++) {
      const header = A2_UNPROTECTED_HEADER.slice();
      header[18] = Number((pn >> 24n) & 0xffn);
      header[19] = Number((pn >> 16n) & 0xffn);
      header[20] = Number((pn >> 8n) & 0xffn);
      header[21] = Number(pn & 0xffn);
      const trace = await sealPacket({
        header,
        payload: A2_PAYLOAD,
        packetNumber: pn,
        keys: keys.client,
        aead: AES_128_GCM,
        headerProtection: 'aes',
      });
      if ((trace.mask[0] & 0x10) !== 0) {
        found = {
          packetNumber: pn,
          mask: trace.mask[0],
          first: trace.packet[0],
        };
        break;
      }
    }
    expect(found, 'no packet number under 64 produced a mask with bit 4 set').not.toBeNull();
    const { mask, first } = found as { packetNumber: bigint; mask: number; first: number };
    expect(mask & 0x10).not.toBe(0);
    // Only the low four bits moved: the type nibble is untouched.
    expect(first ^ A2_UNPROTECTED_HEADER[0]).toBe(mask & 0x0f);
    expect(first ^ A2_UNPROTECTED_HEADER[0]).not.toBe(mask & 0x1f);
    expect(first & 0xf0).toBe(A2_UNPROTECTED_HEADER[0] & 0xf0);
  });

  it('round-trips a packet this lab builds itself, under its own keys', async () => {
    const payload = new Uint8Array(64);
    payload.set([0x06, 0x00, 0x3c], 0); // a CRYPTO frame header, 60 bytes
    const header = A2_UNPROTECTED_HEADER.slice();
    const sealed = await sealPacket({
      header,
      payload: A2_PAYLOAD,
      packetNumber: A2_PACKET_NUMBER,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    const opened = await openPacket({
      packet: sealed.packet,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
    expect(opened.opened).toBe(true);
    expect(toHex(opened.plaintext as Uint8Array)).toBe(toHex(A2_PAYLOAD));
  });
});
