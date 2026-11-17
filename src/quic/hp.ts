import { chacha20 } from './chacha20';

/**
 * RFC 9001 section 5.4 — header protection.
 *
 * Two mask constructions, one per AEAD family. Both take 16 bytes sampled from
 * the packet's own ciphertext and return a 5-byte mask; only the first byte
 * and the packet-number bytes are ever masked with it.
 *
 * Erratum note: RFC 9001 erratum 9272 (Verified 2026-11-05) corrects section
 * 5.4.3's opening sentence from "packet protection algorithm" to "header
 * protection algorithm". It is a wording fix; the algorithm below is as
 * published.
 */

export const SAMPLE_LENGTH = 16;
export const MASK_LENGTH = 5;

/**
 * One AES block, encrypted. This is AES-ECB over exactly one block, which
 * WebCrypto does not offer — `AES-ECB` is not in the algorithm registry at
 * all. Two routes reach it from algorithms WebCrypto does have, and this lab
 * runs BOTH and requires them to agree, because each is a trick and a trick
 * that silently stops working is worse than a missing primitive:
 *
 *   - AES-CTR with the sample as the counter block, over 16 zero bytes. CTR
 *     encrypts the counter block and XORs; XOR with zero is identity, so the
 *     output IS the encrypted block.
 *   - AES-CBC with a zero IV. The first block's XOR with the IV is identity,
 *     so the first output block is the encrypted input block. (CBC appends a
 *     padding block, which is discarded.)
 *
 * `cross-check` is the default because the agreement is the evidence. A caller
 * can ask for one route by name; the page shows both.
 */
export type AesBlockRoute = 'ctr' | 'cbc' | 'cross-check';

export async function aesBlock(
  key: Uint8Array,
  block: Uint8Array,
  route: AesBlockRoute = 'cross-check',
): Promise<Uint8Array> {
  if (block.length !== 16) throw new Error(`AES block must be 16 bytes, got ${block.length}`);

  const viaCtr = async (): Promise<Uint8Array> => {
    const imported = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CTR', false, [
      'encrypt',
    ]);
    const out = await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter: block as BufferSource, length: 128 },
      imported,
      new Uint8Array(16) as BufferSource,
    );
    return new Uint8Array(out);
  };

  const viaCbc = async (): Promise<Uint8Array> => {
    const imported = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CBC', false, [
      'encrypt',
    ]);
    const out = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: new Uint8Array(16) as BufferSource },
      imported,
      block as BufferSource,
    );
    return new Uint8Array(out).slice(0, 16);
  };

  if (route === 'ctr') return viaCtr();
  if (route === 'cbc') return viaCbc();

  const [ctr, cbc] = await Promise.all([viaCtr(), viaCbc()]);
  for (let i = 0; i < 16; i++) {
    if (ctr[i] !== cbc[i]) {
      throw new Error(
        'AES-CTR and AES-CBC disagree on one AES block; neither route to AES-ECB can be trusted here.',
      );
    }
  }
  return ctr;
}

/** RFC 9001 section 5.4.3: mask = AES-ECB(hp_key, sample), first 5 bytes. */
export async function aesHeaderProtectionMask(
  hpKey: Uint8Array,
  sample: Uint8Array,
  route: AesBlockRoute = 'cross-check',
): Promise<Uint8Array> {
  if (hpKey.length !== 16 && hpKey.length !== 32) {
    throw new Error(`AES header-protection key must be 16 or 32 bytes, got ${hpKey.length}`);
  }
  if (sample.length !== SAMPLE_LENGTH) {
    throw new Error(`header-protection sample must be ${SAMPLE_LENGTH} bytes, got ${sample.length}`);
  }
  return (await aesBlock(hpKey, sample, route)).slice(0, MASK_LENGTH);
}

/**
 * RFC 9001 section 5.4.4: the first 4 sample bytes are the ChaCha20 block
 * counter and the remaining 12 are the nonce; the mask is ChaCha20 applied to
 * five zero bytes.
 *
 * The counter is LITTLE-ENDIAN. The RFC says so in as many words — "the byte
 * sequence is interpreted as a little-endian value" — and reading it the other
 * way is a mutation in this lab's ledger, because it produces a plausible
 * 5-byte mask that matches nothing.
 */
export function chachaHeaderProtectionMask(hpKey: Uint8Array, sample: Uint8Array): Uint8Array {
  if (hpKey.length !== 32) {
    throw new Error(`ChaCha20 header-protection key must be 32 bytes, got ${hpKey.length}`);
  }
  if (sample.length !== SAMPLE_LENGTH) {
    throw new Error(`header-protection sample must be ${SAMPLE_LENGTH} bytes, got ${sample.length}`);
  }
  const counterBytes = sample.subarray(0, 4);
  const counter = new DataView(
    counterBytes.buffer,
    counterBytes.byteOffset,
    4,
  ).getUint32(0, true);
  const nonce = sample.slice(4, 16);
  return chacha20(hpKey, counter, nonce, new Uint8Array(MASK_LENGTH));
}
