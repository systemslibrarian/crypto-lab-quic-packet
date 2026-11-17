import { ascii, concat } from './bytes';

/**
 * HKDF (RFC 5869) and the TLS 1.3 HKDF-Expand-Label construction (RFC 8446
 * section 7.1), built from WebCrypto HMAC rather than WebCrypto HKDF.
 *
 * WHY NOT `subtle.deriveBits({name: 'HKDF', ...})`. That one-shot always runs
 * Extract and then Expand. QUIC's second-level derivations — key, iv, hp from
 * an already-extracted secret — are Expand ALONE, on a PRK that is already a
 * PRK. Feeding `client_initial_secret` to the one-shot would extract it a
 * second time and produce bytes that match nothing in RFC 9001 Appendix A. So
 * Extract and Expand are separate functions here, each one HMAC call deep,
 * which is also the form the exhibits show on screen.
 *
 * SHA-256 throughout: RFC 9001 section 5.2 fixes the hash for Initial secrets,
 * and every cipher suite QUIC may negotiate uses SHA-256 or SHA-384 — this lab
 * only builds the SHA-256 ones.
 */

const HASH_LENGTH = 32;

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  // An empty HMAC key is legal in HKDF (RFC 5869 says a zero-length salt is
  // replaced by HashLen zeros, which is what Extract below does), but
  // WebCrypto refuses a zero-length raw key, so callers must never reach here
  // with one.
  const imported = await crypto.subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', imported, data as BufferSource);
  return new Uint8Array(signature);
}

/** RFC 5869 section 2.2. The salt is the HMAC key; the IKM is the message. */
export async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
  // "if not provided, it is set to a string of HashLen zeros" — RFC 5869 2.2.
  // The annotation is load-bearing: without it the ternary's first branch
  // fixes the inferred buffer type and the second no longer fits it.
  const key: Uint8Array = salt.length === 0 ? new Uint8Array(HASH_LENGTH) : salt;
  return hmac(key, ikm);
}

/** RFC 5869 section 2.3. */
export async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  if (length < 0 || length > 255 * HASH_LENGTH) {
    throw new Error(`HKDF-Expand length out of range: ${length}`);
  }
  const blocks: Uint8Array[] = [];
  let previous: Uint8Array = new Uint8Array(0);
  let produced = 0;
  for (let counter = 1; produced < length; counter++) {
    previous = await hmac(prk, concat(previous, info, Uint8Array.of(counter)));
    blocks.push(previous);
    produced += previous.length;
  }
  return concat(...blocks).slice(0, length);
}

/**
 * The HkdfLabel structure of RFC 8446 section 7.1, which RFC 9001 section 5.1
 * requires QUIC to use:
 *
 *     struct {
 *       uint16 length;
 *       opaque label<7..255>;      // "tls13 " + the caller's label
 *       opaque context<0..255>;
 *     } HkdfLabel;
 *
 * Three details are load-bearing and each one is a mutation in this lab's
 * ledger: the length is TWO bytes big-endian, the label is prefixed with the
 * six ASCII bytes `tls13 ` (with its trailing space), and the context length
 * byte is present even when the context is empty — which it always is in QUIC.
 */
export function hkdfLabel(length: number, label: string, context = new Uint8Array(0)): Uint8Array {
  const full = ascii(`tls13 ${label}`);
  if (full.length > 255) throw new Error(`HkdfLabel label too long: ${full.length}`);
  if (context.length > 255) throw new Error(`HkdfLabel context too long: ${context.length}`);
  return concat(
    Uint8Array.of((length >> 8) & 0xff, length & 0xff),
    Uint8Array.of(full.length),
    full,
    Uint8Array.of(context.length),
    context,
  );
}

/** HKDF-Expand-Label: Expand over the HkdfLabel encoding above. */
export async function hkdfExpandLabel(
  secret: Uint8Array,
  label: string,
  length: number,
  context = new Uint8Array(0),
): Promise<Uint8Array> {
  return hkdfExpand(secret, hkdfLabel(length, label, context), length);
}
