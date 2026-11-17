import {
  A3_PACKET_NUMBER,
  A3_PAYLOAD,
  A3_PROTECTED_PACKET,
  A3_UNPROTECTED_HEADER,
  A4_RETRY_PACKET,
  A5_HP,
  A5_IV,
  A5_KEY,
  A5_KU,
  A5_PACKET,
  A5_PACKET_NUMBER,
  A5_PLAINTEXT,
  A5_SAMPLE,
  A5_SECRET,
  A5_UNPROTECTED_HEADER,
  CONNECTION_ID,
  INITIAL_SALT,
  RETRY_KEY,
  RETRY_NONCE,
  RETRY_SECRET,
} from '../../fixtures/rfc9001';
import { AES_128_GCM, CHACHA20_POLY1305 } from '../../quic/aead';
import { bytesEqual, toHex } from '../../quic/bytes';
import { hkdfExpandLabel } from '../../quic/hkdf';
import { deriveInitialKeys, quicV1 } from '../../quic/initial';
import { encodePacketNumber, parseHeader } from '../../quic/packet';
import { openPacket, sealPacket } from '../../quic/protect';
import { retryIntegrityTag } from '../../quic/retry';
import { probeWebCrypto } from '../../quic/webcrypto-support';
import { card, clear, compare, disclosure, el, note } from '../dom';
import { hexView, longHeaderSpans, sampleSpan } from '../hexview';
import { claim, verdict } from '../verdict';

/**
 * Exhibit 5 — the other direction and the other cipher.
 *
 * Three packets, each here because it catches something the client Initial
 * cannot:
 *
 *  - A.3 has a TWO-byte packet number, so its sample starts two bytes into the
 *    ciphertext rather than at the start. It is the packet that catches a
 *    sample taken from the ciphertext's beginning.
 *  - A.4 is a Retry: no packet number, no header protection, an empty
 *    plaintext, and associated data containing a connection ID that is not on
 *    the wire.
 *  - A.5 is a short header under ChaCha20-Poly1305, with the other mask
 *    construction and a three-byte packet number.
 */

export async function renderOthersPanel(panel: HTMLElement): Promise<void> {
  clear(panel);
  panel.append(await serverInitialCard(), await retryCard(), await chachaCard(), await capabilityCard());
}

async function serverInitialCard(): Promise<HTMLElement> {
  const keys = await deriveInitialKeys(CONNECTION_ID, quicV1(INITIAL_SALT));
  const trace = await sealPacket({
    header: A3_UNPROTECTED_HEADER,
    payload: A3_PAYLOAD,
    packetNumber: A3_PACKET_NUMBER,
    keys: keys.server,
    aead: AES_128_GCM,
    headerProtection: 'aes',
  });
  const header = parseHeader(A3_UNPROTECTED_HEADER);
  const matches = bytesEqual(trace.packet, A3_PROTECTED_PACKET);
  const ciphertextStart = A3_UNPROTECTED_HEADER.length;
  const sampleIntoCiphertext = trace.sampleStart - ciphertextStart;

  return card('A.3 - the server Initial, and the packet it alone can catch', [
    note(
      'The server answers under the OTHER half of the same key ladder - "server in" instead of "client in" - from the same connection ID the client chose. It also picks its own Source Connection ID, which the client will use from then on, and it encodes the packet number in two bytes rather than four.',
    ),
    note(
      `That two-byte packet number is what makes this packet worth building. The sample always starts four bytes after the packet-number field BEGINS, so here it starts ${sampleIntoCiphertext} bytes into the ciphertext rather than at its first byte. In the client Initial those two positions coincide, so an implementation that sampled from the start of the ciphertext would reproduce Appendix A.2 perfectly and fail here.`,
    ),
    hexView({
      title: 'A.3 header, unprotected',
      bytes: A3_UNPROTECTED_HEADER,
      spans: longHeaderSpans({
        dcidLength: header.destinationConnectionId.length,
        scidLength: header.form === 'long' ? header.sourceConnectionId.length : 0,
        tokenLengthBytes: 1,
        lengthFieldBytes: 2,
        packetNumberOffset: trace.packetNumberOffset,
        packetNumberLength: trace.packetNumberLength,
      }),
      ariaLabel: 'The server Initial header, unprotected, annotated by field',
    }),
    hexView({
      title: 'A.3 packet, protected, with the sample window marked',
      bytes: trace.packet,
      limit: 64,
      spans: [sampleSpan(trace.sampleStart)],
      meta: `${trace.packet.length} bytes; the sample runs from byte ${trace.sampleStart}`,
      ariaLabel: 'The protected server Initial packet with its sample window bracketed',
    }),
    compare([
      { label: 'packet-number bytes', value: String(trace.packetNumberLength), claim: 'a3-pn-length' },
      { label: 'header length', value: `${A3_UNPROTECTED_HEADER.length} bytes`, claim: 'a3-header-length' },
      { label: 'sample starts at', value: `byte ${trace.sampleStart}`, claim: 'a3-sample-offset' },
      {
        label: 'into the ciphertext',
        value: `${sampleIntoCiphertext} bytes`,
        claim: 'a3-sample-into-ciphertext',
      },
      { label: 'sample', value: toHex(trace.sample), claim: 'a3-sample' },
      { label: 'mask', value: toHex(trace.mask), claim: 'a3-mask' },
    ]),
    verdict({
      id: 'a3-result',
      tone: matches ? 'pass' : 'fail',
      headline: matches
        ? `BUILT - the ${trace.packet.length}-byte server Initial matches RFC 9001 Appendix A.3 byte for byte`
        : 'BUILT - but the packet does NOT match RFC 9001 Appendix A.3',
      body: matches
        ? 'Server keys from the same ladder, AES-128-GCM over an ACK and a CRYPTO frame, mask from a sample two bytes inside the ciphertext.'
        : 'That is a defect in this lab.',
    }),
  ]);
}

async function retryCard(): Promise<HTMLElement> {
  const result = await retryIntegrityTag({
    originalDestinationConnectionId: CONNECTION_ID,
    retryPacket: A4_RETRY_PACKET,
    key: RETRY_KEY,
    nonce: RETRY_NONCE,
  });
  const derivedKey = await hkdfExpandLabel(RETRY_SECRET, 'quic key', 16);
  const derivedNonce = await hkdfExpandLabel(RETRY_SECRET, 'quic iv', 12);
  const keysDerive = bytesEqual(derivedKey, RETRY_KEY) && bytesEqual(derivedNonce, RETRY_NONCE);

  const altered = await retryIntegrityTag({
    originalDestinationConnectionId: (() => {
      const other = CONNECTION_ID.slice();
      other[0] ^= 0x01;
      return other;
    })(),
    retryPacket: A4_RETRY_PACKET,
    key: RETRY_KEY,
    nonce: RETRY_NONCE,
  });

  return card('A.4 - a Retry packet, which encrypts nothing at all', [
    note(
      'A Retry has no packet number, no header protection and no encrypted payload. It runs AES-128-GCM with an EMPTY plaintext, purely for the 16-byte tag, under a key and nonce that RFC 9001 section 5.8 prints as constants. Everything about it is public.',
    ),
    note(
      'What it does have is one piece of hidden state. The associated data is the Retry Pseudo-Packet: the ORIGINAL Destination Connection ID, length-prefixed, in front of the packet with its tag removed. That original ID is not in the Retry packet, so only something that saw the client’s Initial can compute this tag - which is the entire point of the mechanism.',
    ),
    hexView({
      title: 'The Retry packet on the wire',
      bytes: A4_RETRY_PACKET,
      spans: [
        { start: 0, end: 1, className: 'f-first', label: 'first byte (long header, type Retry)' },
        { start: 1, end: 5, className: 'f-version', label: 'Version' },
        { start: 5, end: 6, className: 'f-length', label: 'Destination Connection ID Length (0)' },
        { start: 6, end: 7, className: 'f-length', label: 'Source Connection ID Length' },
        { start: 7, end: 15, className: 'f-scid', label: 'Source Connection ID' },
        { start: 15, end: A4_RETRY_PACKET.length - 16, className: 'f-ct', label: 'Retry Token' },
        {
          start: A4_RETRY_PACKET.length - 16,
          end: A4_RETRY_PACKET.length,
          className: 'f-tag',
          label: 'Retry Integrity Tag',
        },
      ],
      ariaLabel: 'The Retry packet, annotated by field',
    }),
    hexView({
      title: 'The Retry Pseudo-Packet, which is never sent',
      bytes: result.pseudoPacket,
      spans: [
        { start: 0, end: 1, className: 'f-length', label: 'ODCID Length' },
        {
          start: 1,
          end: 1 + CONNECTION_ID.length,
          className: 'f-dcid',
          label: 'Original Destination Connection ID - NOT on the wire',
          bracket: true,
        },
      ],
      ariaLabel: 'The Retry Pseudo-Packet, with the original connection ID bracketed',
    }),
    compare([
      { label: 'secret (published)', value: toHex(RETRY_SECRET), claim: 'a4-secret' },
      { label: 'key = "quic key"', value: toHex(derivedKey), claim: 'a4-key' },
      { label: 'nonce = "quic iv"', value: toHex(derivedNonce), claim: 'a4-nonce' },
      { label: 'computed tag', value: toHex(result.computedTag), claim: 'a4-computed-tag' },
      { label: 'tag on the wire', value: toHex(result.tagOnTheWire), claim: 'a4-wire-tag' },
    ]),
    verdict({
      id: 'a4-result',
      tone: result.verified && keysDerive ? 'pass' : 'fail',
      headline: result.verified
        ? 'VERIFIED - the computed tag equals the one RFC 9001 Appendix A.4 prints'
        : 'NOT VERIFIED - the computed tag differs from the RFC’s',
      body: result.verified
        ? `The key and nonce were themselves derived here from the published secret with HKDF-Expand-Label${keysDerive ? ' and match the constants section 5.8 prints' : ', but they do NOT match the constants section 5.8 prints'}.`
        : 'That is a defect in this lab.',
    }),
    verdict({
      id: 'a4-wrong-odcid',
      tone: altered.verified ? 'fail' : 'pass',
      headline: altered.verified
        ? 'A WRONG ORIGINAL CONNECTION ID STILL VERIFIED - that would be a defect'
        : 'A wrong original connection ID does NOT verify',
      body: altered.verified
        ? 'The tag should commit to the original connection ID.'
        : `Flipping one bit of the original Destination Connection ID gives ${toHex(altered.computedTag)} instead. An attacker who did not see the client’s Initial cannot produce the right tag, because the value it commits to never travelled.`,
    }),
  ]);
}

async function chachaCard(): Promise<HTMLElement> {
  const keys = { key: A5_KEY, iv: A5_IV, hp: A5_HP };
  const trace = await sealPacket({
    header: A5_UNPROTECTED_HEADER,
    payload: A5_PLAINTEXT,
    packetNumber: A5_PACKET_NUMBER,
    keys,
    aead: CHACHA20_POLY1305,
    headerProtection: 'chacha20',
    connectionIdLength: 0,
  });
  const open = await openPacket({
    packet: A5_PACKET,
    keys,
    aead: CHACHA20_POLY1305,
    headerProtection: 'chacha20',
    connectionIdLength: 0,
    largestReceived: A5_PACKET_NUMBER - 1n,
  });
  const matches = bytesEqual(trace.packet, A5_PACKET);

  /**
   * The same packet with one ciphertext bit flipped.
   *
   * This is here because the mutation runner found that nothing on the page
   * could see a missing tag check. Invariant 3 - "opened" is shown only when
   * the authentication tag verifies - is enforced by WebCrypto on the
   * AES-128-GCM path, which simply will not return unverified plaintext. On
   * THIS path it is enforced by a byte comparison in this repository's own
   * `chachaPolyOpen`, and until this exhibit existed the page never once
   * exercised it: every ChaCha20 state it rendered had a correct tag.
   */
  const tampered = A5_PACKET.slice();
  // Byte 4 is the single ciphertext byte, and it is the ONE byte of this packet
  // that the header-protection sample does not cover. That matters: the sample
  // runs from byte 5 to byte 20, which on a 21-byte packet is the whole
  // Poly1305 tag — so flipping a tag bit would change the sample, change the
  // mask, and leave the packet number recovered as nonsense, muddling two
  // failures into one. Flipping the ciphertext instead leaves header
  // protection working perfectly and isolates the tag check, which is the
  // thing this state exists to show.
  tampered[4] ^= 0x01;
  const tamperedOpen = await openPacket({
    packet: tampered,
    keys,
    aead: CHACHA20_POLY1305,
    headerProtection: 'chacha20',
    connectionIdLength: 0,
    largestReceived: A5_PACKET_NUMBER - 1n,
  });

  const derived = await Promise.all([
    hkdfExpandLabel(A5_SECRET, 'quic key', 32),
    hkdfExpandLabel(A5_SECRET, 'quic iv', 12),
    hkdfExpandLabel(A5_SECRET, 'quic hp', 32),
    hkdfExpandLabel(A5_SECRET, 'quic ku', 32),
  ]);
  const scheduleMatches =
    bytesEqual(derived[0], A5_KEY) &&
    bytesEqual(derived[1], A5_IV) &&
    bytesEqual(derived[2], A5_HP) &&
    bytesEqual(derived[3], A5_KU);

  const counter = new DataView(A5_SAMPLE.buffer, A5_SAMPLE.byteOffset, 4).getUint32(0, true);
  const truncated = encodePacketNumber(A5_PACKET_NUMBER, 3);

  return card('A.5 - a short header under ChaCha20-Poly1305', [
    note(
      'The last worked packet is a 1-RTT packet: a short header, an empty connection ID, one PING frame, and the other cipher suite. Twenty-one bytes, the smallest a QUIC packet can be.',
    ),
    note(
      'WebCrypto will not hand over a raw ChaCha20 key - measured, not assumed; see the table below - so the ChaCha20 and Poly1305 for this packet are implemented in TypeScript in this repository, verified against RFC 8439’s own vectors before being pointed at this packet.',
    ),
    el('h4', { text: 'The key schedule, from a published application secret' }),
    compare([
      { label: 'secret', value: toHex(A5_SECRET), claim: 'a5-secret' },
      { label: 'key (32)', value: toHex(derived[0]), claim: 'a5-key' },
      { label: 'iv (12)', value: toHex(derived[1]), claim: 'a5-iv' },
      { label: 'hp (32)', value: toHex(derived[2]), claim: 'a5-hp' },
      { label: 'ku (32)', value: toHex(derived[3]), claim: 'a5-ku' },
    ]),
    note(
      `The same HKDF-Expand-Label as exhibit 1, with 32-byte outputs instead of 16. "quic ku" is the secret that would be used after a key update; the RFC prints it, this page checks it, and nothing here uses it - key update is not built. ${scheduleMatches ? 'All four match Appendix A.5.' : 'A value does NOT match Appendix A.5, which is a defect in this lab.'}`,
    ),
    el('h4', { text: 'The packet number: 654360564, encoded in three bytes' }),
    compare([
      { label: 'full packet number', value: String(A5_PACKET_NUMBER), claim: 'a5-packet-number' },
      { label: 'in hex', value: `0x${A5_PACKET_NUMBER.toString(16)}`, claim: 'a5-packet-number-hex' },
      {
        label: 'low 24 bits on the wire',
        value: `${toHex(truncated)} = ${Number(A5_PACKET_NUMBER & 0xffffffn)} decimal`,
        claim: 'a5-truncated',
      },
      { label: 'reconstructed', value: String(open.packetNumber), claim: 'a5-reconstructed' },
    ]),
    note(
      'Only the low 24 bits travel. The receiver reconstructs the rest from the largest packet number it has already seen - RFC 9000 Appendix A.3 - and the full 62-bit value, not the truncated one, goes into the nonce. That is the one worked reconstruction this lab does; a receive-window walkthrough is out of scope.',
    ),
    el('h4', { text: 'The other mask construction' }),
    compare([
      { label: 'sample', value: toHex(A5_SAMPLE), claim: 'a5-sample' },
      {
        label: 'counter (little-endian)',
        value: `${toHex(A5_SAMPLE.subarray(0, 4))} = ${counter}`,
        claim: 'a5-counter',
      },
      { label: 'nonce', value: toHex(A5_SAMPLE.subarray(4, 16)), claim: 'a5-hp-nonce' },
      { label: 'mask = ChaCha20(hp, counter, nonce, 00000000 00)', value: toHex(trace.mask), claim: 'a5-mask' },
    ]),
    note(
      `The first four sample bytes are the block counter, read LITTLE-endian - RFC 9001 section 5.4.4 says so in as many words. Read big-endian they would be ${new DataView(A5_SAMPLE.buffer, A5_SAMPLE.byteOffset, 4).getUint32(0, false)} instead of ${counter}, and the mask would be plausible and wrong.`,
    ),
    hexView({
      title: 'The 21-byte packet, with its sample window',
      bytes: trace.packet,
      spans: [
        { start: 0, end: 1, className: 'f-first', label: 'first byte (short header; five low bits protected)' },
        { start: 1, end: 4, className: 'f-pn', label: 'Packet Number (3 bytes, protected)' },
        { start: 4, end: 5, className: 'f-ct', label: 'ciphertext of the PING frame' },
        { start: 5, end: 21, className: 'f-tag', label: 'Poly1305 tag' },
        sampleSpan(5),
      ],
      ariaLabel: 'The 21-byte ChaCha20-Poly1305 packet with its sample window bracketed',
    }),
    note(
      'One byte of ciphertext is skipped before the sample, because the packet number is three bytes and the sample starts four bytes after the field begins. With a one-byte plaintext the whole ciphertext is 17 bytes, so the sample is the tag and one byte short of it - the minimum the RFC’s padding rule allows.',
    ),
    verdict({
      id: 'a5-result',
      tone: matches && scheduleMatches ? 'pass' : 'fail',
      headline: matches
        ? `BUILT - the ${trace.packet.length}-byte packet matches RFC 9001 Appendix A.5 byte for byte`
        : 'BUILT - but the packet does NOT match RFC 9001 Appendix A.5',
      body: matches
        ? `And opened again: packet number ${open.packetNumber}, plaintext ${toHex(open.plaintext ?? new Uint8Array(0))} - a single PING frame.`
        : 'That is a defect in this lab.',
    }),
    el('h4', { text: 'And the same packet with one tag bit flipped' }),
    note(
      'On the AES-128-GCM packets, refusing to show plaintext without a verified tag is WebCrypto\u2019s doing - it will not hand back unverified bytes however it is asked. Here it is this repository\u2019s own byte comparison, in `chachaPolyOpen`, and the tag is checked before the keystream is ever applied: a failure has no plaintext to leak even by accident.',
    ),
    compare([
      { label: 'tag on the wire', value: toHex(tampered.subarray(-16)), claim: 'a5-tampered-tag' },
      {
        label: 'packet number recovered',
        value: String(tamperedOpen.packetNumber),
        claim: 'a5-tampered-packet-number',
      },
      {
        label: 'plaintext shown',
        value: tamperedOpen.opened ? toHex(tamperedOpen.plaintext ?? new Uint8Array(0)) : 'none',
        claim: 'a5-tampered-plaintext',
      },
    ]),
    verdict({
      id: 'a5-tampered',
      tone: tamperedOpen.opened ? 'fail' : 'pass',
      headline: tamperedOpen.opened
        ? 'OPENED WITH A BROKEN TAG - that would be a defect in this lab'
        : 'NOT OPENED - the Poly1305 tag did not verify, and no plaintext is shown',
      body: tamperedOpen.opened
        ? 'A packet whose authentication tag does not verify must never produce plaintext.'
        : `Header protection still came off - that needs no authentication at all - so the packet number ${tamperedOpen.packetNumber} was recovered before anything was checked. Only then did the tag fail. The flipped bit is the single ciphertext byte, which is also the only byte of this 21-byte packet the sample does not cover: the sample runs from byte 5 to byte 20, which here is the whole tag.`,
    }),
    disclosure('A seam that is shaped and not built', [
      note(
        'Two extensions are marked in the source and deliberately left unbuilt. A Version record holds the salt and the four labels, which is all RFC 9369 (QUIC version 2) changes - add a second record and version 2 works. A KeyPhase seam would carry the "quic ku" value above through a key update. Neither is built here, and the page says so rather than implying completeness.',
      ),
    ]),
  ]);
}

async function capabilityCard(): Promise<HTMLElement> {
  const support = await probeWebCrypto();
  return card('What this browser’s WebCrypto will actually do', [
    note(
      'Measured here, in your browser, just now - not asserted. The lab’s architecture turns on these answers: two of the primitives are the platform’s, one is reached through a trick, and two are hand-rolled in this repository because the platform refuses them.',
    ),
    el('div', { class: 'table-wrap', role: 'region', 'aria-label': 'WebCrypto algorithm support measured in this browser', tabindex: 0 }, [
      el('table', {}, [
        el('thead', {}, [
          el('tr', {}, [
            el('th', { scope: 'col', text: 'algorithm' }),
            el('th', { scope: 'col', text: 'available here' }),
            el('th', { scope: 'col', text: 'what this lab uses it for' }),
          ]),
        ]),
        el(
          'tbody',
          {},
          support.map((entry) =>
            el('tr', {}, [
              el('td', {}, [el('code', { text: entry.name })]),
              el('td', {}, [
                el('span', {
                  class: entry.available ? 'yes' : 'no',
                  'data-claim': `webcrypto-${entry.name.toLowerCase()}`,
                  text: entry.available ? 'yes' : 'no',
                }),
              ]),
              el('td', { text: entry.what }),
            ]),
          ),
        ),
      ]),
    ]),
    note(
      'AES-ECB is not in the WebCrypto registry at all, which is why the header-protection mask is taken from AES-CTR with the sample as the counter block and cross-checked against AES-CBC with a zero IV. Those two must agree or the panels above refuse to draw.',
    ),
    disclosure('Why the refusals are reported rather than asserted', [
      note(
        'A comment claiming "WebCrypto has no ChaCha20" ages into a false statement the moment a browser ships it. This table is a dated measurement instead: if the two bottom rows ever read yes, the reason this repository hand-rolls those primitives has gone away, and the page will say so before anyone reads the comment.',
      ),
      el('div', { class: 'compare' }, support.map((entry) =>
        el('div', { class: 'compare-row' }, [
          el('span', { class: 'compare-label', text: entry.name }),
          claim(`webcrypto-detail-${entry.name.toLowerCase()}`, entry.detail),
        ]),
      )),
    ]),
  ]);
}
