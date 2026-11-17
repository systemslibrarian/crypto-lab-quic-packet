import { bytesEqual, concat } from './bytes';
import { chacha20 } from './chacha20';
import { poly1305 } from './poly1305';

/**
 * RFC 9001 section 5.3 — packet protection.
 *
 * Two AEADs, because the four worked packets need two: AES-128-GCM from
 * WebCrypto for the Initial packets and the Retry tag, and
 * ChaCha20-Poly1305 built here for Appendix A.5.
 */

export const TAG_LENGTH = 16;

export type AeadName = 'AEAD_AES_128_GCM' | 'AEAD_CHACHA20_POLY1305';

/**
 * The AEAD nonce of RFC 9001 section 5.3: the packet number, left-padded with
 * zeros to the length of the IV, XORed with the IV.
 *
 * NOT concatenated, and not truncated to the encoded packet-number length. The
 * full reconstructed packet number goes in, which is why a receiver has to
 * reconstruct it before it can open anything. RFC 9001 erratum 7785 proposed
 * narrowing the RFC's "62 bits" to 32 and was REJECTED on 2024-01-29: the full
 * packet number is 62 bits, it just never appears as such in the header.
 */
export function aeadNonce(iv: Uint8Array, packetNumber: bigint): Uint8Array {
  if (packetNumber < 0n || packetNumber > (1n << 62n) - 1n) {
    throw new Error(`packet number out of the 62-bit QUIC range: ${packetNumber}`);
  }
  const nonce = iv.slice();
  const padded = new Uint8Array(8);
  new DataView(padded.buffer).setBigUint64(0, packetNumber);
  // Right-aligned: the packet number's last byte lands on the IV's last byte.
  for (let i = 0; i < 8; i++) nonce[nonce.length - 8 + i] ^= padded[i];
  return nonce;
}

/* ── AES-128-GCM, from WebCrypto ─────────────────────────────────────────── */

async function importGcm(key: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', key as BufferSource, 'AES-GCM', false, [usage]);
}

export async function aesGcmSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const imported = await importGcm(key, 'encrypt');
  const sealed = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce as BufferSource,
      additionalData: associatedData as BufferSource,
      tagLength: TAG_LENGTH * 8,
    },
    imported,
    plaintext as BufferSource,
  );
  return new Uint8Array(sealed);
}

/**
 * Open an AES-GCM sealed value, returning `null` when the tag does not verify.
 *
 * `null` rather than a thrown error, and rather than the plaintext-plus-a-flag
 * shape, because invariant 3 of this lab is that "opened" is shown only when
 * the tag verifies — and the surest way to honour that is for the failing path
 * to have NO plaintext to show. WebCrypto will not hand back unverified
 * plaintext in the first place, which is the behaviour this lab mutates to
 * prove its tests catch a verdict rendered without a tag check.
 */
export async function aesGcmOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  sealed: Uint8Array,
): Promise<Uint8Array | null> {
  if (sealed.length < TAG_LENGTH) return null;
  try {
    const imported = await importGcm(key, 'decrypt');
    const opened = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce as BufferSource,
        additionalData: associatedData as BufferSource,
        tagLength: TAG_LENGTH * 8,
      },
      imported,
      sealed as BufferSource,
    );
    return new Uint8Array(opened);
  } catch {
    return null;
  }
}

/* ── ChaCha20-Poly1305, RFC 8439 section 2.8 ─────────────────────────────── */

/** RFC 8439 section 2.6: the one-time Poly1305 key is ChaCha20 block 0. */
function poly1305KeyGen(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  return chacha20(key, 0, nonce, new Uint8Array(32));
}

function padTo16(bytes: Uint8Array): Uint8Array {
  const remainder = bytes.length % 16;
  return remainder === 0 ? new Uint8Array(0) : new Uint8Array(16 - remainder);
}

function littleEndian64(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
  return out;
}

/** The AEAD construction of RFC 8439 section 2.8. */
function chachaPolyMacData(associatedData: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return concat(
    associatedData,
    padTo16(associatedData),
    ciphertext,
    padTo16(ciphertext),
    littleEndian64(associatedData.length),
    littleEndian64(ciphertext.length),
  );
}

export function chachaPolySeal(
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  // Counter 1: block 0 was spent on the Poly1305 one-time key.
  const ciphertext = chacha20(key, 1, nonce, plaintext);
  const tag = poly1305(poly1305KeyGen(key, nonce), chachaPolyMacData(associatedData, ciphertext));
  return concat(ciphertext, tag);
}

export function chachaPolyOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  sealed: Uint8Array,
): Uint8Array | null {
  if (sealed.length < TAG_LENGTH) return null;
  const ciphertext = sealed.subarray(0, sealed.length - TAG_LENGTH);
  const receivedTag = sealed.subarray(sealed.length - TAG_LENGTH);
  const expectedTag = poly1305(
    poly1305KeyGen(key, nonce),
    chachaPolyMacData(associatedData, ciphertext),
  );
  // The tag is checked BEFORE the keystream is applied, so a failure has no
  // plaintext to leak even by accident.
  if (!bytesEqual(expectedTag, receivedTag)) return null;
  return chacha20(key, 1, nonce, ciphertext);
}

/* ── One interface over both ─────────────────────────────────────────────── */

export interface Aead {
  readonly name: AeadName;
  readonly keyLength: number;
  seal(
    key: Uint8Array,
    nonce: Uint8Array,
    associatedData: Uint8Array,
    plaintext: Uint8Array,
  ): Promise<Uint8Array>;
  open(
    key: Uint8Array,
    nonce: Uint8Array,
    associatedData: Uint8Array,
    sealed: Uint8Array,
  ): Promise<Uint8Array | null>;
}

export const AES_128_GCM: Aead = {
  name: 'AEAD_AES_128_GCM',
  keyLength: 16,
  seal: aesGcmSeal,
  open: aesGcmOpen,
};

export const CHACHA20_POLY1305: Aead = {
  name: 'AEAD_CHACHA20_POLY1305',
  keyLength: 32,
  seal: async (key, nonce, associatedData, plaintext) =>
    chachaPolySeal(key, nonce, associatedData, plaintext),
  open: async (key, nonce, associatedData, sealed) =>
    chachaPolyOpen(key, nonce, associatedData, sealed),
};
