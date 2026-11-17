import { describe, expect, it } from 'vitest';

import { EXPECTED_HKDF_LABELS } from '../fixtures/rfc9001';
import { toHex } from './bytes';
import { hkdfExpand, hkdfExpandLabel, hkdfExtract, hkdfLabel } from './hkdf';
import { rfc5869Value, rfcText, section } from '../../tests/rfc-text';

/**
 * HKDF against RFC 5869's own test cases, and the HkdfLabel encodings against
 * the five RFC 9001 Appendix A.1 prints.
 *
 * Cases 1 and 3 are the SHA-256 ones (this lab needs no other hash): case 1
 * has a salt and info, case 3 has neither, which is the branch RFC 5869
 * section 2.2 handles by substituting HashLen zeros. Both are read out of the
 * RFC text rather than typed.
 */

const rfc5869 = rfcText('rfc5869.txt');

const CASES = [
  { name: 'Test Case 1 (basic, SHA-256)', heading: 'A.1.  Test Case 1', next: 'A.2.  Test Case 2' },
  {
    name: 'Test Case 3 (SHA-256, zero-length salt and info)',
    heading: 'A.3.  Test Case 3',
    next: 'A.4.  Test Case 4',
  },
] as const;

describe('HKDF (RFC 5869)', () => {
  for (const testCase of CASES) {
    const block = section(rfc5869, testCase.heading, testCase.next);
    const ikm = rfc5869Value(block, 'IKM');
    const salt = rfc5869Value(block, 'salt');
    const info = rfc5869Value(block, 'info');
    const expectedPrk = rfc5869Value(block, 'PRK');
    const expectedOkm = rfc5869Value(block, 'OKM');
    const length = Number(/^\s*L\s+=\s*(\d+)\s*$/m.exec(block)?.[1]);

    it(`${testCase.name}: Extract reproduces the RFC's PRK`, async () => {
      expect(expectedPrk.length).toBe(32);
      expect(toHex(await hkdfExtract(salt, ikm))).toBe(toHex(expectedPrk));
    });

    it(`${testCase.name}: Expand reproduces the RFC's ${length}-byte OKM`, async () => {
      expect(expectedOkm.length).toBe(length);
      expect(toHex(await hkdfExpand(expectedPrk, info, length))).toBe(toHex(expectedOkm));
    });
  }

  it('an empty salt is HashLen zeros, not an empty HMAC key', async () => {
    // RFC 5869 section 2.2. Case 3's PRK is the evidence: WebCrypto refuses a
    // zero-length raw HMAC key outright, so a build that forwarded the empty
    // salt would throw rather than quietly differ.
    const block = section(rfc5869, 'A.3.  Test Case 3', 'A.4.  Test Case 4');
    const ikm = rfc5869Value(block, 'IKM');
    const viaEmpty = await hkdfExtract(new Uint8Array(0), ikm);
    const viaZeros = await hkdfExtract(new Uint8Array(32), ikm);
    expect(toHex(viaEmpty)).toBe(toHex(viaZeros));
    expect(toHex(viaEmpty)).toBe(toHex(rfc5869Value(block, 'PRK')));
  });
});

describe('HKDF-Expand-Label (RFC 8446 section 7.1, via RFC 9001 Appendix A.1)', () => {
  for (const { label, length, info } of EXPECTED_HKDF_LABELS) {
    it(`encodes HkdfLabel for "${label}" exactly as A.1 prints it`, () => {
      expect(toHex(hkdfLabel(length, label))).toBe(toHex(info));
    });
  }

  it('puts the output length in TWO big-endian bytes', () => {
    // A one-byte length field is a mutation in this lab's ledger. 32 would
    // still encode as 0x20 in one byte, so the tell is the total length and
    // the position of everything after it.
    const encoded = hkdfLabel(32, 'client in');
    expect(encoded[0]).toBe(0x00);
    expect(encoded[1]).toBe(0x20);
    expect(encoded.length).toBe(2 + 1 + 'tls13 client in'.length + 1);
  });

  it('prefixes the label with the six ASCII bytes of "tls13 "', () => {
    const encoded = hkdfLabel(16, 'quic key');
    const labelBytes = encoded.subarray(3, 3 + encoded[2]);
    expect(new TextDecoder().decode(labelBytes)).toBe('tls13 quic key');
  });

  it('writes a zero context-length byte even with no context', () => {
    const encoded = hkdfLabel(12, 'quic iv');
    expect(encoded[encoded.length - 1]).toBe(0x00);
  });

  it('refuses a non-ASCII label rather than encoding something else', () => {
    expect(() => hkdfLabel(16, 'quic kéy')).toThrow(/not ASCII/);
  });

  it('agrees with Expand over the same info', async () => {
    const secret = new Uint8Array(32).fill(7);
    const direct = await hkdfExpand(secret, hkdfLabel(16, 'quic key'), 16);
    const viaLabel = await hkdfExpandLabel(secret, 'quic key', 16);
    expect(toHex(viaLabel)).toBe(toHex(direct));
  });
});
