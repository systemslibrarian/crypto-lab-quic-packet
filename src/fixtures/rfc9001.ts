import excerpt from './rfc9001-excerpt.txt?raw';
import { concat, fromHex } from '../quic/bytes';

/**
 * Every expected value in this lab, parsed out of the RFC text itself.
 *
 * THE RULE THIS FILE EXISTS TO ENFORCE (invariant 1): no expected value is
 * typed by hand anywhere in this repository. Not in a test, not in the UI, not
 * in a comment that a reader might trust. They are all read at load time out
 * of `rfc9001-excerpt.txt`, which carries its own provenance header and is
 * proven to be a byte-exact slice of the full RFC text in
 * `tests/rfc-excerpt-provenance.test.ts`.
 *
 * The cost of that rule is this parser. The benefit is that a transcription
 * error is impossible rather than unlikely, and that a reader who distrusts
 * the lab can diff one text file against rfc-editor.org and be done.
 */

export const RFC9001_EXCERPT = excerpt;

/* ── Parsing helpers ─────────────────────────────────────────────────────── */

function fail(what: string): never {
  throw new Error(
    `RFC 9001 fixture: could not find ${what} in rfc9001-excerpt.txt. The excerpt has been edited or re-cut; see its provenance header.`,
  );
}

/** A section body, from one heading up to the next. */
function section(heading: string, nextHeading: string): string {
  const start = excerpt.indexOf(`\n${heading}`);
  const end = excerpt.indexOf(`\n${nextHeading}`);
  if (start < 0) fail(`the heading ${JSON.stringify(heading)}`);
  if (end < 0 || end <= start) fail(`the heading ${JSON.stringify(nextHeading)} after ${JSON.stringify(heading)}`);
  return excerpt.slice(start + 1, end);
}

/** Every line in `block` that is nothing but indented hex, concatenated. */
function hexLump(block: string, what: string): Uint8Array {
  const lines = block
    .split('\n')
    .filter((line) => /^ {3,}(?:[0-9a-f]{2,})(?: [0-9a-f]{2,})*\s*$/.test(line));
  if (lines.length === 0) fail(`hex lines for ${what}`);
  return fromHex(lines.join('').replace(/\s+/g, ''));
}

/** The span of a block between two literal markers. */
function between(block: string, after: string, before: string, what: string): string {
  const start = block.indexOf(after);
  if (start < 0) fail(`${JSON.stringify(after)} (${what})`);
  const from = start + after.length;
  const end = block.indexOf(before, from);
  if (end < 0) fail(`${JSON.stringify(before)} after ${JSON.stringify(after)} (${what})`);
  return block.slice(from, end);
}

/** A `0x…` constant in prose. */
function hexConstant(block: string, what: string, nth = 0): Uint8Array {
  const matches = [...block.matchAll(/0x([0-9a-f]{8,})/g)];
  if (matches.length <= nth) fail(`0x-prefixed constant #${nth + 1} for ${what}`);
  return fromHex(matches[nth][1]);
}

/**
 * A labelled hex value, read line by line rather than by regex.
 *
 * Appendix A prints its values in four shapes, and a single pattern meant to
 * match all four matched the wrong thing twice while this was being built: it
 * truncated A.5's `secret` to its first line, and it returned A.5's
 * `unprotected header` when asked for `header`, because one label is a
 * substring of the other. So the label is compared EXACTLY, after trimming,
 * and continuation lines are gathered until the value ends.
 *
 * The four shapes:
 *
 *     sample = d1b1c98d...                    one line, hex on the right
 *     key = HKDF-Expand-Label(..., 16)        right side is an expression,
 *         = 1f369613...                       so the value is on the next line
 *     client_initial_secret                   label alone on its line
 *         = HKDF-Expand-Label(...)
 *         = c00cf151...
 *           2d6b7db6...                       and it wraps
 *     secret                                  label alone, value follows
 *         = 9ac312a7...
 *           5443f182...
 */
const PURE_HEX = /^[0-9a-f]+$/;

function labelledValue(block: string, label: string, what: string): Uint8Array {
  const lines = block.split('\n');
  const wanted = label.trim();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const eq = line.indexOf('=');
    const head = (eq < 0 ? line : line.slice(0, eq)).trim();
    if (head !== wanted) continue;

    const pieces: string[] = [];
    // The remainder of the label's own line, when it is hex.
    if (eq >= 0) {
      const rhs = line.slice(eq + 1).trim();
      if (PURE_HEX.test(rhs)) pieces.push(rhs);
    }
    // Continuation lines: `= <hex>`, or a bare indented `<hex>`. A right-hand
    // side that is not pure hex is an expression (`HKDF-Expand-Label(...)`)
    // and is stepped over; anything else ends the value.
    for (let j = i + 1; j < lines.length; j++) {
      const next = lines[j];
      if (next.trim() === '') {
        if (pieces.length > 0) break;
        continue;
      }
      if (!/^\s{4,}/.test(next)) break;
      const body = next.trim().replace(/^=\s*/, '');
      if (PURE_HEX.test(body)) {
        pieces.push(body);
        continue;
      }
      if (pieces.length > 0) break;
      if (next.includes('=')) continue; // an expression line; keep looking
      break;
    }
    if (pieces.length > 0) return fromHex(pieces.join(''));
  }
  return fail(`the value labelled ${JSON.stringify(wanted)} (${what})`);
}


/* ── RFC 9001 section 5.2: the version-1 initial salt ────────────────────── */

const SECTION_5_2 = section('5.2.  Initial Secrets', '5.8.  Retry Packet Integrity');

/** `initial_salt = 0x38762cf7…` — RFC 9001 section 5.2. */
export const INITIAL_SALT: Uint8Array = (() => {
  const line = between(SECTION_5_2, 'initial_salt = ', '\n', 'the version-1 initial salt');
  return fromHex(line.trim().replace(/^0x/, ''));
})();

/* ── RFC 9001 section 5.8: the Retry integrity constants ─────────────────── */

const SECTION_5_8 = section('5.8.  Retry Packet Integrity', 'Appendix A.  Sample Packet Protection');

export const RETRY_KEY: Uint8Array = hexConstant(
  between(SECTION_5_8, 'The secret key, K, is 128 bits equal to', 'The nonce, N,', 'the Retry key'),
  'the Retry AEAD key',
);

export const RETRY_NONCE: Uint8Array = hexConstant(
  between(SECTION_5_8, 'The nonce, N, is 96 bits equal to', 'The plaintext, P,', 'the Retry nonce'),
  'the Retry AEAD nonce',
);

/** The secret the Retry key and nonce are derived from, also published. */
export const RETRY_SECRET: Uint8Array = hexConstant(
  between(SECTION_5_8, 'are values derived by calling HKDF-', 'Retry Pseudo-Packet {', 'the Retry secret'),
  'the Retry derivation secret',
);

/* ── Appendix A.1: keys ──────────────────────────────────────────────────── */

const APPENDIX_A = section('Appendix A.  Sample Packet Protection', 'A.2.  Client Initial');
const A_1 = section('A.1.  Keys', 'A.2.  Client Initial');

/** The 8-byte client-chosen Destination Connection ID used by A.1 to A.4. */
export const CONNECTION_ID: Uint8Array = hexConstant(APPENDIX_A, 'the sample Destination Connection ID');

export interface ExpectedDirectionKeys {
  readonly secret: Uint8Array;
  readonly key: Uint8Array;
  readonly iv: Uint8Array;
  readonly hp: Uint8Array;
}

export const EXPECTED_INITIAL_SECRET: Uint8Array = labelledValue(
  A_1,
  'initial_secret',
  'the A.1 initial_secret',
);

const A_1_CLIENT = between(A_1, 'The secrets for protecting client packets are:', 'The secrets for protecting server packets are:', 'A.1 client keys');
const A_1_SERVER = A_1.slice(A_1.indexOf('The secrets for protecting server packets are:'));

export const EXPECTED_CLIENT_KEYS: ExpectedDirectionKeys = {
  secret: labelledValue(A_1_CLIENT, 'client_initial_secret', 'A.1 client_initial_secret'),
  key: labelledValue(A_1_CLIENT, 'key', 'A.1 client key'),
  iv: labelledValue(A_1_CLIENT, 'iv', 'A.1 client iv'),
  hp: labelledValue(A_1_CLIENT, 'hp', 'A.1 client hp'),
};

export const EXPECTED_SERVER_KEYS: ExpectedDirectionKeys = {
  secret: labelledValue(A_1_SERVER, 'server_initial_secret', 'A.1 server_initial_secret'),
  key: labelledValue(A_1_SERVER, 'key', 'A.1 server key'),
  iv: labelledValue(A_1_SERVER, 'iv', 'A.1 server iv'),
  hp: labelledValue(A_1_SERVER, 'hp', 'A.1 server hp'),
};

/**
 * The five HkdfLabel encodings A.1 prints, as `label -> bytes`. A.1 writes
 * them as `client in:  00200f74…`, one per line.
 */
export const EXPECTED_HKDF_LABELS: ReadonlyArray<{ label: string; length: number; info: Uint8Array }> =
  (() => {
    const block = between(A_1, 'produce its output are:', 'The initial secret is common:', 'A.1 HkdfLabel encodings');
    const lengths: Record<string, number> = {
      'client in': 32,
      'server in': 32,
      'quic key': 16,
      'quic iv': 12,
      'quic hp': 16,
    };
    const out = [...block.matchAll(/^\s{3}([a-z0-9 ]+):\s+([0-9a-f]+)\s*$/gm)].map((m) => ({
      label: m[1].trim(),
      length: lengths[m[1].trim()] ?? fail(`a known output length for the label ${JSON.stringify(m[1].trim())}`),
      info: fromHex(m[2]),
    }));
    if (out.length !== 5) fail(`five HkdfLabel encodings in A.1 (found ${out.length})`);
    return out;
  })();

/* ── Appendix A.2: the client Initial ────────────────────────────────────── */

const A_2 = section('A.2.  Client Initial', 'A.3.  Server Initial');

/** The CRYPTO frame A.2 prints, BEFORE the PADDING that pads it to 1162. */
export const A2_CRYPTO_FRAME: Uint8Array = hexLump(
  between(A_2, '1162-byte payload:', 'The unprotected header', 'A.2 CRYPTO frame'),
  'the A.2 CRYPTO frame',
);

/**
 * The full 1162-byte unprotected payload: the CRYPTO frame followed by PADDING
 * frames. A.2 says "plus enough PADDING frames to make a 1162-byte payload"
 * rather than printing them; RFC 9000 section 19.1 defines a PADDING frame as
 * the single byte 0x00, so the padding is that many zero bytes.
 */
export const A2_PAYLOAD_LENGTH: number = (() => {
  const match = /(\d+)-byte payload/.exec(A_2);
  if (!match) fail('the stated A.2 payload length');
  return Number(match[1]);
})();

export const A2_PAYLOAD: Uint8Array = concat(
  A2_CRYPTO_FRAME,
  new Uint8Array(A2_PAYLOAD_LENGTH - A2_CRYPTO_FRAME.length),
);

export const A2_UNPROTECTED_HEADER: Uint8Array = hexLump(
  between(A_2, 'a packet number of 2:', 'Protecting the payload', 'A.2 unprotected header'),
  'the A.2 unprotected header',
);

export const A2_SAMPLE: Uint8Array = labelledValue(A_2, 'sample', 'the A.2 sample');
export const A2_MASK: Uint8Array = labelledValue(A_2, 'mask', 'the A.2 mask');
export const A2_PROTECTED_HEADER: Uint8Array = labelledValue(
  A_2,
  'header',
  'the A.2 protected header',
);

/** The two masked fields A.2 prints on their own, as a cross-check. */
export const A2_MASKED_FIRST_BYTE: Uint8Array = labelledValue(
  A_2,
  'header[0] ^',
  'the A.2 masked first byte',
);
export const A2_MASKED_PACKET_NUMBER: Uint8Array = labelledValue(
  A_2,
  'header[18..21] ^',
  'the A.2 masked packet-number bytes',
);

export const A2_PROTECTED_PACKET: Uint8Array = hexLump(
  A_2.slice(A_2.indexOf('The resulting protected packet is:')),
  'the A.2 protected packet',
);

/** A.2's packet number, stated in prose. */
export const A2_PACKET_NUMBER = 2n;

/* ── Appendix A.3: the server Initial ────────────────────────────────────── */

const A_3 = section('A.3.  Server Initial', 'A.4.  Retry');

export const A3_PAYLOAD: Uint8Array = hexLump(
  between(A_3, 'no PADDING frames:', 'The header from the server', 'A.3 payload'),
  'the A.3 payload',
);

export const A3_UNPROTECTED_HEADER: Uint8Array = hexLump(
  between(A_3, 'packet number of 1:', 'As a result, after protection', 'A.3 unprotected header'),
  'the A.3 unprotected header',
);

export const A3_SAMPLE: Uint8Array = labelledValue(A_3, 'sample', 'the A.3 sample');
export const A3_MASK: Uint8Array = labelledValue(A_3, 'mask', 'the A.3 mask');
export const A3_PROTECTED_HEADER: Uint8Array = labelledValue(
  A_3,
  'header',
  'the A.3 protected header',
);

export const A3_PROTECTED_PACKET: Uint8Array = hexLump(
  A_3.slice(A_3.indexOf('The final protected packet is then:')),
  'the A.3 protected packet',
);

export const A3_PACKET_NUMBER = 1n;

/* ── Appendix A.4: Retry ─────────────────────────────────────────────────── */

const A_4 = section('A.4.  Retry', 'A.5.  ChaCha20-Poly1305 Short Header Packet');

export const A4_RETRY_PACKET: Uint8Array = hexLump(
  A_4.slice(A_4.indexOf('final Retry packet:')),
  'the A.4 Retry packet',
);

/* ── Appendix A.5: the ChaCha20-Poly1305 short-header packet ─────────────── */

const A_5 = excerpt.slice(excerpt.indexOf('\nA.5.  ChaCha20-Poly1305 Short Header Packet') + 1);

export const A5_SECRET: Uint8Array = labelledValue(A_5, 'secret', 'A.5 secret');
export const A5_KEY: Uint8Array = labelledValue(A_5, 'key', 'A.5 key');
export const A5_IV: Uint8Array = labelledValue(A_5, 'iv', 'A.5 iv');
export const A5_HP: Uint8Array = labelledValue(A_5, 'hp', 'A.5 hp');
export const A5_KU: Uint8Array = labelledValue(A_5, 'ku', 'A.5 ku');

export const A5_PACKET_NUMBER: bigint = (() => {
  const match = /pn\s+= (\d+) \(decimal\)/.exec(A_5);
  if (!match) fail('the A.5 packet number');
  return BigInt(match[1]);
})();

export const A5_NONCE: Uint8Array = labelledValue(A_5, 'nonce', 'the A.5 nonce');
/**
 * `unprotected header` and `header` are different labels four lines apart in
 * A.5, and `header` is a substring of the other. An earlier substring search
 * here returned 4200bff4 for both; exact label matching is why it does not.
 */
export const A5_UNPROTECTED_HEADER: Uint8Array = labelledValue(
  A_5,
  'unprotected header',
  'the A.5 unprotected header',
);
export const A5_PLAINTEXT: Uint8Array = labelledValue(A_5, 'payload plaintext', 'the A.5 plaintext');
export const A5_CIPHERTEXT: Uint8Array = labelledValue(
  A_5,
  'payload ciphertext',
  'the A.5 ciphertext',
);
export const A5_SAMPLE: Uint8Array = labelledValue(A_5, 'sample', 'the A.5 sample');
export const A5_MASK: Uint8Array = labelledValue(A_5, 'mask', 'the A.5 mask');
export const A5_PROTECTED_HEADER: Uint8Array = labelledValue(
  A_5,
  'header',
  'the A.5 protected header',
);
export const A5_PACKET: Uint8Array = labelledValue(A_5, 'packet', 'the A.5 protected packet');
