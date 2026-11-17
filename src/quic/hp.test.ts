import { describe, expect, it } from 'vitest';

import {
  A2_MASK,
  A2_SAMPLE,
  A3_MASK,
  A3_SAMPLE,
  A5_HP,
  A5_MASK,
  A5_SAMPLE,
  EXPECTED_CLIENT_KEYS,
  EXPECTED_SERVER_KEYS,
} from '../fixtures/rfc9001';
import { fromHex, toHex } from './bytes';
import { chacha20 } from './chacha20';
import {
  MASK_LENGTH,
  SAMPLE_LENGTH,
  aesBlock,
  aesHeaderProtectionMask,
  chachaHeaderProtectionMask,
} from './hp';

/**
 * RFC 9001 section 5.4.3 and 5.4.4 — the two mask constructions.
 *
 * The AES half is the interesting one to test, because the primitive the RFC
 * names does not exist in WebCrypto: `AES-ECB` is not in the algorithm
 * registry at all. This lab reaches one AES block two ways and requires them
 * to agree; what these tests check is that the agreement is real and that the
 * disagreement path refuses rather than guessing.
 */

describe('one AES block, with no AES-ECB available', () => {
  it('AES-CTR and AES-CBC agree, so the cross-check is not vacuous', async () => {
    const viaCtr = await aesBlock(EXPECTED_CLIENT_KEYS.hp, A2_SAMPLE, 'ctr');
    const viaCbc = await aesBlock(EXPECTED_CLIENT_KEYS.hp, A2_SAMPLE, 'cbc');
    expect(toHex(viaCtr)).toBe(toHex(viaCbc));
  });

  it('mask via AES-CBC agrees with the mask via AES-CTR, on every worked sample', async () => {
    // Named by the mutation ledger: flipping the CBC route to decryption makes
    // these two disagree, `aesBlock` refuses, and the panels report that they
    // cannot draw rather than drawing a wrong mask.
    for (const [key, sample] of [
      [EXPECTED_CLIENT_KEYS.hp, A2_SAMPLE],
      [EXPECTED_SERVER_KEYS.hp, A3_SAMPLE],
    ] as const) {
      const viaCtr = await aesBlock(key, sample, 'ctr');
      const viaCbc = await aesBlock(key, sample, 'cbc');
      expect(toHex(viaCbc), toHex(sample)).toBe(toHex(viaCtr));
      // And the default route returns the agreed value rather than either one
      // by preference.
      expect(toHex(await aesBlock(key, sample))).toBe(toHex(viaCtr));
    }
  });

  it('returns a full 16-byte block, of which the mask is the first five', async () => {
    const block = await aesBlock(EXPECTED_CLIENT_KEYS.hp, A2_SAMPLE);
    expect(block.length).toBe(16);
    expect(toHex(block.slice(0, MASK_LENGTH))).toBe(toHex(A2_MASK));
  });

  it('refuses a block that is not 16 bytes', async () => {
    await expect(aesBlock(EXPECTED_CLIENT_KEYS.hp, new Uint8Array(15))).rejects.toThrow(
      /must be 16 bytes/,
    );
  });

  it('is deterministic: the same key and sample give the same block', async () => {
    const first = await aesBlock(EXPECTED_CLIENT_KEYS.hp, A2_SAMPLE);
    const second = await aesBlock(EXPECTED_CLIENT_KEYS.hp, A2_SAMPLE);
    expect(toHex(first)).toBe(toHex(second));
  });
});

describe('AES-based header protection (RFC 9001 section 5.4.3)', () => {
  it("reproduces A.2's mask", async () => {
    expect(toHex(await aesHeaderProtectionMask(EXPECTED_CLIENT_KEYS.hp, A2_SAMPLE))).toBe(
      toHex(A2_MASK),
    );
  });

  it("reproduces A.3's mask under the SERVER's header-protection key", async () => {
    expect(toHex(await aesHeaderProtectionMask(EXPECTED_SERVER_KEYS.hp, A3_SAMPLE))).toBe(
      toHex(A3_MASK),
    );
    // Under the client's hp key it is something else: the two directions are
    // separated by nothing but the HKDF label.
    expect(toHex(await aesHeaderProtectionMask(EXPECTED_CLIENT_KEYS.hp, A3_SAMPLE))).not.toBe(
      toHex(A3_MASK),
    );
  });

  it('returns exactly five bytes', async () => {
    const mask = await aesHeaderProtectionMask(EXPECTED_CLIENT_KEYS.hp, A2_SAMPLE);
    expect(mask.length).toBe(MASK_LENGTH);
  });

  it('refuses a sample of the wrong length', async () => {
    await expect(
      aesHeaderProtectionMask(EXPECTED_CLIENT_KEYS.hp, new Uint8Array(15)),
    ).rejects.toThrow(/must be 16 bytes/);
    expect(SAMPLE_LENGTH).toBe(16);
  });

  it('refuses a header-protection key that is not 16 or 32 bytes', async () => {
    await expect(aesHeaderProtectionMask(new Uint8Array(24), A2_SAMPLE)).rejects.toThrow(
      /must be 16 or 32 bytes/,
    );
  });

  it('accepts a 32-byte key, for AEAD_AES_256_GCM', async () => {
    // RFC 9001 section 5.4.3: AEAD_AES_256_GCM uses 256-bit AES in ECB mode.
    // Nothing in this lab negotiates it; the length is accepted so the
    // refusal above is about a WRONG length rather than about 32 specifically.
    const mask = await aesHeaderProtectionMask(new Uint8Array(32), A2_SAMPLE);
    expect(mask.length).toBe(MASK_LENGTH);
  });
});

describe('ChaCha20-based header protection (RFC 9001 section 5.4.4)', () => {
  it("reproduces A.5's mask", () => {
    expect(toHex(chachaHeaderProtectionMask(A5_HP, A5_SAMPLE))).toBe(toHex(A5_MASK));
  });

  it('reads the counter LITTLE-endian, as the RFC says in as many words', () => {
    // THIS TEST WAS DECORATIVE AND THE MUTATION RUNNER SAID SO. Its first
    // version compared two DataView readings and asserted they differed, which
    // is true of the sample and says nothing about the function under test: the
    // big-endian mutation survived it. What bites is re-deriving the mask BOTH
    // ways and requiring the function to match one and not the other.
    const view = new DataView(A5_SAMPLE.buffer, A5_SAMPLE.byteOffset, 4);
    const little = view.getUint32(0, true);
    const big = view.getUint32(0, false);
    expect(toHex(A5_SAMPLE.subarray(0, 4))).toBe('5e5cd55c');
    expect(little).toBe(0x5cd55c5e);
    expect(big).toBe(0x5e5cd55c);

    const nonce = A5_SAMPLE.slice(4, 16);
    const zeros = new Uint8Array(MASK_LENGTH);
    const produced = chachaHeaderProtectionMask(A5_HP, A5_SAMPLE);
    expect(toHex(produced)).toBe(toHex(chacha20(A5_HP, little, nonce, zeros)));
    expect(toHex(produced)).not.toBe(toHex(chacha20(A5_HP, big, nonce, zeros)));
    // And the little-endian reading is the one the RFC prints.
    expect(toHex(produced)).toBe(toHex(A5_MASK));
  });

  it('uses the remaining twelve sample bytes as the nonce', () => {
    // Shifting the nonce by one byte must change the mask, which is what makes
    // the 4/12 split a measurement rather than a convention.
    const shifted = fromHex(`00${toHex(A5_SAMPLE).slice(0, 30)}`);
    expect(shifted.length).toBe(16);
    expect(toHex(chachaHeaderProtectionMask(A5_HP, shifted))).not.toBe(toHex(A5_MASK));
  });

  it('returns exactly five bytes', () => {
    expect(chachaHeaderProtectionMask(A5_HP, A5_SAMPLE).length).toBe(MASK_LENGTH);
  });

  it('refuses a key that is not 32 bytes', () => {
    expect(() => chachaHeaderProtectionMask(new Uint8Array(16), A5_SAMPLE)).toThrow(
      /must be 32 bytes/,
    );
  });

  it('refuses a sample that is not 16 bytes', () => {
    expect(() => chachaHeaderProtectionMask(A5_HP, new Uint8Array(15))).toThrow(/must be 16 bytes/);
  });

  it('is a different construction from the AES one, not a wrapper round it', async () => {
    const chacha = chachaHeaderProtectionMask(A5_HP, A5_SAMPLE);
    const aes = await aesHeaderProtectionMask(A5_HP, A5_SAMPLE);
    expect(toHex(chacha)).not.toBe(toHex(aes));
    expect(toHex(chacha)).toBe(toHex(A5_MASK));
  });
});
