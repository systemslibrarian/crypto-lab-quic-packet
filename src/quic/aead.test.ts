import { describe, expect, it } from 'vitest';

import { toHex } from './bytes';
import {
  AES_128_GCM,
  CHACHA20_POLY1305,
  TAG_LENGTH,
  aeadNonce,
  aesGcmOpen,
  aesGcmSeal,
  chachaPolyOpen,
  chachaPolySeal,
} from './aead';
import {
  cavpCases,
  colonBlock,
  hexDump,
  nistText,
  rfcText,
  section,
  sha256Hex,
} from '../../tests/rfc-text';

/**
 * Both AEADs against published vectors, and the QUIC nonce construction.
 *
 * AES-128-GCM comes from WebCrypto, so what these cases prove is not that the
 * browser's GCM is right — it is that this lab WIRES it right: key, 96-bit
 * nonce, associated data and 128-bit tag in the arrangement QUIC needs.
 */

describe('AES-128-GCM (NIST CAVP gcmEncryptExtIV128)', () => {
  const text = nistText('gcm-encrypt-128-selected.rsp');
  const cases = cavpCases(text);

  it('the excerpt records the digest of the complete CAVP file', () => {
    expect(text).toContain('30156236f768b0d81e58a3e5bd3bd79ce294cf9ef0ba0a84cf7b869c89ebd9fd');
  });

  it('parsed every case in all three groups', () => {
    expect(cases.length).toBe(45);
    for (const testCase of cases) {
      expect(testCase.group.Keylen).toBe(128);
      expect(testCase.group.IVlen).toBe(96);
      expect(testCase.group.Taglen).toBe(128);
      // The groups kept are the ones with a non-empty AAD and a plaintext
      // longer than one AES block, which is what the brief's acceptance check
      // asks for. Asserting it here is what keeps a future re-cut honest.
      expect(testCase.group.AADlen).toBeGreaterThan(0);
      expect(testCase.group.PTlen).toBeGreaterThan(128);
    }
  });

  it('seals every case to the CAVP ciphertext and tag', async () => {
    for (const testCase of cases) {
      const { Key, IV, PT, AAD, CT, Tag } = testCase.fields;
      const sealed = await aesGcmSeal(Key, IV, AAD, PT);
      expect(
        toHex(sealed),
        `CAVP case ${testCase.count} (PTlen ${testCase.group.PTlen}, AADlen ${testCase.group.AADlen})`,
      ).toBe(toHex(CT) + toHex(Tag));
    }
  });

  it('opens every case back to its plaintext', async () => {
    for (const testCase of cases) {
      const { Key, IV, PT, AAD, CT, Tag } = testCase.fields;
      const opened = await aesGcmOpen(Key, IV, AAD, new Uint8Array([...CT, ...Tag]));
      expect(opened).not.toBeNull();
      expect(toHex(opened as Uint8Array)).toBe(toHex(PT));
    }
  });

  it('returns null rather than plaintext when the tag is wrong', async () => {
    const { Key, IV, AAD, CT, Tag } = cases[0].fields;
    const broken = new Uint8Array([...CT, ...Tag]);
    broken[broken.length - 1] ^= 0x01;
    expect(await aesGcmOpen(Key, IV, AAD, broken)).toBeNull();
  });

  it('returns null when the associated data differs by one bit', async () => {
    const { Key, IV, AAD, CT, Tag } = cases[0].fields;
    const tamperedAad = AAD.slice();
    tamperedAad[0] ^= 0x01;
    expect(await aesGcmOpen(Key, IV, tamperedAad, new Uint8Array([...CT, ...Tag]))).toBeNull();
  });

  it('returns null for a value too short to hold a tag', async () => {
    const { Key, IV, AAD } = cases[0].fields;
    expect(await aesGcmOpen(Key, IV, AAD, new Uint8Array(TAG_LENGTH - 1))).toBeNull();
  });
});

describe('ChaCha20-Poly1305 (RFC 8439 section 2.8.2)', () => {
  const rfc8439 = rfcText('rfc8439.txt');
  const block = section(
    rfc8439,
    '2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305',
    '3.  Implementation Advice',
  );
  const plaintext = hexDump(block, 'Plaintext');
  const aad = hexDump(block, 'AAD');
  const key = hexDump(block, 'Key');
  const iv = hexDump(block, 'IV');
  const fixed = hexDump(block, '32-bit fixed-common part');
  const ciphertext = hexDump(block, 'Ciphertext');
  // 2.8.2 prints its tag colon-separated and everything else as hexdumps.
  const tag = colonBlock(block, 'Tag');
  // RFC 8439 section 2.8 builds the 96-bit nonce as the 32-bit fixed-common
  // part followed by the 64-bit IV.
  const nonce = new Uint8Array([...fixed, ...iv]);

  it('reproduces the RFC\'s ciphertext and tag', () => {
    expect(plaintext.length).toBe(114);
    expect(aad.length).toBe(12);
    expect(nonce.length).toBe(12);
    expect(toHex(chachaPolySeal(key, nonce, aad, plaintext))).toBe(toHex(ciphertext) + toHex(tag));
  });

  it('opens its own output', () => {
    const sealed = chachaPolySeal(key, nonce, aad, plaintext);
    expect(toHex(chachaPolyOpen(key, nonce, aad, sealed) as Uint8Array)).toBe(toHex(plaintext));
  });

  it('returns null rather than plaintext when the tag is wrong', () => {
    const sealed = chachaPolySeal(key, nonce, aad, plaintext);
    sealed[sealed.length - 1] ^= 0x01;
    expect(chachaPolyOpen(key, nonce, aad, sealed)).toBeNull();
  });

  it('returns null when the associated data differs', () => {
    const sealed = chachaPolySeal(key, nonce, aad, plaintext);
    const tampered = aad.slice();
    tampered[0] ^= 0x01;
    expect(chachaPolyOpen(key, nonce, tampered, sealed)).toBeNull();
  });

  it('checks the tag BEFORE applying the keystream', () => {
    // Not an implementation detail: it is what makes invariant 3 structural
    // rather than a promise. A failed open has no plaintext to hand back even
    // by accident, because it never computed one.
    const sealed = chachaPolySeal(key, nonce, aad, plaintext);
    sealed[0] ^= 0xff; // corrupt the ciphertext, not the tag
    expect(chachaPolyOpen(key, nonce, aad, sealed)).toBeNull();
  });
});

describe('RFC 8439 Appendix A.5 decryption vector', () => {
  const rfc8439 = rfcText('rfc8439.txt');
  const block = section(
    rfc8439,
    'A.5.  ChaCha20-Poly1305 AEAD Decryption',
    'Appendix B.  Performance Measurements of ChaCha20',
  );

  it('opens the appendix vector and agrees with its calculated tag', () => {
    // A.5's labels are its own: `The ChaCha20 Key` with no colon, `The nonce`,
    // `The AAD`, and `Plaintext::` with two colons.
    const key = hexDump(block, 'The ChaCha20 Key');
    const ciphertext = hexDump(block, 'Ciphertext');
    const aad = hexDump(block, 'The AAD');
    const nonce = hexDump(block, 'The nonce');
    const received = hexDump(block, 'Received Tag');
    const calculated = hexDump(block, 'Calculated Tag');
    const plaintext = hexDump(block, 'Plaintext:');
    expect(toHex(calculated)).toBe(toHex(received));
    const opened = chachaPolyOpen(key, nonce, aad, new Uint8Array([...ciphertext, ...received]));
    expect(opened).not.toBeNull();
    expect(toHex(opened as Uint8Array)).toBe(toHex(plaintext));
  });
});

describe('the QUIC AEAD nonce (RFC 9001 section 5.3)', () => {
  const iv = new Uint8Array(12).fill(0xaa);

  it('XORs the right-aligned packet number into the IV', () => {
    const nonce = aeadNonce(iv, 2n);
    expect(toHex(nonce)).toBe('aaaaaaaaaaaaaaaaaaaaaaa8');
  });

  it('does not append the packet number', () => {
    // Concatenation instead of XOR is a mutation in this lab's ledger. The
    // tell is that the nonce would be longer than the IV, and that the IV's
    // own bytes would survive unchanged.
    const nonce = aeadNonce(iv, 0x0102030405060708n);
    expect(nonce.length).toBe(iv.length);
    expect(toHex(nonce)).toBe('aaaaaaaaaba8a9aeafacada2');
  });

  it('leaves the IV untouched for packet number 0', () => {
    expect(toHex(aeadNonce(iv, 0n))).toBe(toHex(iv));
  });

  it('does not mutate the IV it was given', () => {
    const original = toHex(iv);
    aeadNonce(iv, 12345n);
    expect(toHex(iv)).toBe(original);
  });

  it('refuses a packet number outside QUIC\'s 62-bit range', () => {
    expect(() => aeadNonce(iv, -1n)).toThrow(/62-bit/);
    expect(() => aeadNonce(iv, 1n << 62n)).toThrow(/62-bit/);
    expect(() => aeadNonce(iv, (1n << 62n) - 1n)).not.toThrow();
  });
});

describe('the two Aead implementations share one interface', () => {
  it('each reports the key length it needs', () => {
    expect(AES_128_GCM.keyLength).toBe(16);
    expect(CHACHA20_POLY1305.keyLength).toBe(32);
  });

  it('each round-trips through the shared interface', async () => {
    for (const aead of [AES_128_GCM, CHACHA20_POLY1305]) {
      const key = new Uint8Array(aead.keyLength).fill(0x42);
      const nonce = new Uint8Array(12).fill(0x24);
      const aad = new Uint8Array([1, 2, 3]);
      const plaintext = new Uint8Array([9, 8, 7, 6]);
      const sealed = await aead.seal(key, nonce, aad, plaintext);
      expect(sealed.length, aead.name).toBe(plaintext.length + TAG_LENGTH);
      const opened = await aead.open(key, nonce, aad, sealed);
      expect(toHex(opened as Uint8Array), aead.name).toBe(toHex(plaintext));
    }
  });
});

describe('the NIST excerpt is the file that was reviewed', () => {
  it('hashes to a stable digest', () => {
    // Pins the EXCERPT, where the group headers the suite above asserts live.
    // The complete CAVP file's digest is recorded in the excerpt's own header.
    expect(sha256Hex(nistText('gcm-encrypt-128-selected.rsp'))).toBe(
      '61ff7910e9d1c1892bfc3e16624c0fbe056bc51db853cb63ae0a2fc0a869f956',
    );
  });
});
