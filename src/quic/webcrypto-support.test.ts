import { describe, expect, it } from 'vitest';

import { probeWebCrypto } from './webcrypto-support';

/**
 * The three WebCrypto facts this lab's architecture rests on, measured.
 *
 * Measured under Node's `crypto.subtle` here; the page runs the same probe in
 * the browser and prints what it got, and `e2e/claims.spec.ts` asserts the
 * browser's answer agrees with the reason the page gives for hand-rolling
 * ChaCha20. Neither is a claim about every runtime, and neither pretends to
 * be: they are dated measurements of the one they ran in.
 */

const support = await probeWebCrypto();
const byName = (name: string) => support.find((s) => s.name === name);

describe('what WebCrypto provides here', () => {
  it('provides HMAC-SHA-256, so HKDF is a platform primitive', () => {
    expect(byName('HMAC-SHA-256')?.available).toBe(true);
  });

  it('provides AES-GCM, so packet protection is a platform primitive', () => {
    expect(byName('AES-GCM')?.available).toBe(true);
  });

  it('does NOT provide AES-ECB, which is why the mask comes from CTR or CBC', () => {
    const ecb = byName('AES-ECB');
    expect(ecb?.available).toBe(false);
    expect(ecb?.detail).toMatch(/NotSupportedError|Unrecognized|not supported/i);
  });

  it('provides both routes to the single AES block the mask needs', () => {
    expect(byName('AES-CTR')?.available).toBe(true);
    expect(byName('AES-CBC')?.available).toBe(true);
  });

  it('refuses a raw ChaCha20-Poly1305 key, which is why A.5 is hand-rolled', () => {
    const aead = byName('ChaCha20-Poly1305');
    expect(aead?.available).toBe(false);
    expect(aead?.detail).toMatch(/NotSupportedError|Unable to import|Unrecognized/i);
  });

  it('refuses a raw ChaCha20 key, which is why the A.5 mask is hand-rolled', () => {
    const cipher = byName('ChaCha20');
    expect(cipher?.available).toBe(false);
  });

  it('reports a reason for every refusal, never a bare false', () => {
    for (const entry of support) {
      expect(entry.detail.length, entry.name).toBeGreaterThan(0);
      expect(entry.what.length, entry.name).toBeGreaterThan(0);
    }
  });
});
