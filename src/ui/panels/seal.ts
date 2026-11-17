import {
  A2_CRYPTO_FRAME,
  A2_PACKET_NUMBER,
  A2_PAYLOAD,
  A2_PROTECTED_PACKET,
  A2_UNPROTECTED_HEADER,
  CONNECTION_ID,
  INITIAL_SALT,
} from '../../fixtures/rfc9001';
import { AES_128_GCM, aeadNonce } from '../../quic/aead';
import { bytesEqual, concat, toHex } from '../../quic/bytes';
import { deriveInitialKeys, quicV1 } from '../../quic/initial';
import { parseHeader } from '../../quic/packet';
import { sealPacket } from '../../quic/protect';
import { card, clear, compare, disclosure, el, liveRegion, note } from '../dom';
import { hexView, longHeaderSpans } from '../hexview';
import { claim, verdict } from '../verdict';

/**
 * Exhibit 2 — seal the payload.
 *
 * Three things have to come across, and each one is a mutation in the ledger:
 * the nonce is the IV XORed with the packet number (not concatenated), the
 * associated data is the WHOLE unprotected header INCLUDING the packet-number
 * bytes, and the tag is 16 bytes after the ciphertext.
 *
 * The nonce is shown as a three-row XOR so the operation is visible rather
 * than asserted.
 */

export async function renderSealPanel(panel: HTMLElement): Promise<void> {
  clear(panel);

  const output = liveRegion('seal-output', 'AES-128-GCM packet protection');

  const keys = await deriveInitialKeys(CONNECTION_ID, quicV1(INITIAL_SALT));
  const header = parseHeader(A2_UNPROTECTED_HEADER);
  const trace = await sealPacket({
    header: A2_UNPROTECTED_HEADER,
    payload: A2_PAYLOAD,
    packetNumber: A2_PACKET_NUMBER,
    keys: keys.client,
    aead: AES_128_GCM,
    headerProtection: 'aes',
  });

  const sealedMatches = bytesEqual(
    concat(trace.ciphertext, trace.tag),
    A2_PROTECTED_PACKET.subarray(A2_UNPROTECTED_HEADER.length),
  );

  const paddedIv = (() => {
    const bytes = new Uint8Array(12);
    const pn = new Uint8Array(8);
    new DataView(pn.buffer).setBigUint64(0, A2_PACKET_NUMBER);
    bytes.set(pn, 4);
    return bytes;
  })();

  output.append(
    verdict({
      id: 'seal-result',
      tone: sealedMatches ? 'pass' : 'fail',
      headline: sealedMatches
        ? 'SEALED - the 1178 ciphertext-and-tag bytes match RFC 9001 Appendix A.2'
        : 'SEALED - but the bytes do NOT match RFC 9001 Appendix A.2',
      body: sealedMatches
        ? 'AES-128-GCM ran in your browser through WebCrypto, over the payload below, with the whole unprotected header as associated data.'
        : 'That is a defect in this lab. The comparison is a byte comparison against the RFC text checked into this repository.',
    }),
  );

  output.append(
    el('h4', { text: 'The nonce: the IV XORed with the packet number' }),
    note(
      'RFC 9001 section 5.3 left-pads the reconstructed packet number with zeros to the length of the IV and XORs the two. Not concatenated - the nonce is exactly as long as the IV, and every byte of the IV can change.',
    ),
    el('div', { class: 'compare' }, [
      el('div', { class: 'compare-row' }, [
        el('span', { class: 'compare-label', text: 'iv' }),
        claim('seal-iv', toHex(keys.client.iv)),
      ]),
      el('div', { class: 'compare-row' }, [
        el('span', { class: 'compare-label', text: `packet number ${A2_PACKET_NUMBER}` }),
        claim('seal-padded-pn', toHex(paddedIv)),
      ]),
      el('div', { class: 'compare-row' }, [
        el('span', { class: 'compare-label', text: 'XOR = nonce' }),
        claim('seal-nonce', toHex(trace.nonce)),
      ]),
    ]),
    note(
      `The packet number occupies only the last few bytes, so most of the nonce is the IV unchanged - which is exactly why the IV must never be reused across connections. Computed independently: ${toHex(aeadNonce(keys.client.iv, A2_PACKET_NUMBER))}.`,
    ),
  );

  output.append(
    el('h4', { text: 'The associated data: the whole unprotected header' }),
    note(
      'Including the packet-number bytes, which the sender is about to hide. The receiver has to recover them before it can rebuild this - which is why header protection has to come off first.',
    ),
    hexView({
      title: 'Associated data (A), 22 bytes',
      bytes: trace.associatedData,
      spans: longHeaderSpans({
        dcidLength: header.destinationConnectionId.length,
        scidLength: header.form === 'long' ? header.sourceConnectionId.length : 0,
        tokenLengthBytes: 1,
        lengthFieldBytes: 2,
        packetNumberOffset: trace.packetNumberOffset,
        packetNumberLength: trace.packetNumberLength,
      }),
      ariaLabel: 'The associated data: the 22-byte unprotected header, annotated by field',
    }),
  );

  output.append(
    el('h4', { text: 'The plaintext: the frames' }),
    note(
      `Appendix A.2 prints a ${A2_CRYPTO_FRAME.length}-byte CRYPTO frame and says "plus enough PADDING frames to make a ${A2_PAYLOAD.length}-byte payload". A PADDING frame is the single byte 0x00 (RFC 9000 section 19.1), so the rest is ${A2_PAYLOAD.length - A2_CRYPTO_FRAME.length} zero bytes. The padding is not decorative: an Initial packet must be at least 1200 bytes so a server cannot be used to amplify traffic.`,
    ),
    hexView({
      title: 'Plaintext (P)',
      bytes: A2_PAYLOAD,
      limit: 96,
      meta: `${A2_PAYLOAD.length} bytes: ${A2_CRYPTO_FRAME.length} of CRYPTO frame, then PADDING`,
      ariaLabel: 'The plaintext payload: a CRYPTO frame followed by PADDING frames',
    }),
  );

  output.append(
    el('h4', { text: 'The output: ciphertext, then a 16-byte tag' }),
    compare([
      { label: 'ciphertext bytes', value: String(trace.ciphertext.length), claim: 'seal-ciphertext-length' },
      { label: 'tag', value: toHex(trace.tag), claim: 'seal-tag' },
      { label: 'tag bytes', value: String(trace.tag.length), claim: 'seal-tag-length' },
    ]),
    hexView({
      title: 'Ciphertext (C) with its tag',
      bytes: concat(trace.ciphertext, trace.tag),
      limit: 96,
      spans: [
        {
          start: trace.ciphertext.length,
          end: trace.ciphertext.length + trace.tag.length,
          className: 'f-tag',
          label: 'authentication tag',
        },
      ],
      meta: `${trace.ciphertext.length} + 16 bytes`,
      ariaLabel: 'The ciphertext and its 16-byte authentication tag',
    }),
    note(
      'The tag is what makes this authenticated encryption rather than encryption. It commits to the ciphertext AND to the associated data, so a single flipped bit anywhere in the header or the payload makes the packet refuse to open - which is exhibit 6.',
    ),
  );

  output.append(
    disclosure('Why the tag is integrity and not secrecy here', [
      note(
        'The tag proves the packet reached you exactly as it was sent by someone holding the key. For an Initial packet that is a weaker statement than it sounds, because the key came from a published salt and a connection ID on the wire - so "someone holding the key" is anyone on the path. RFC 9001 section 7 says it plainly: QUIC "provides protection against attackers that cannot read packets but does not attempt to provide additional protection against attacks where the attacker can observe and inject packets." Exhibit 4 is that sentence, as bytes.',
      ),
    ]),
  );

  panel.append(
    card('Seal the payload with AES-128-GCM', [
      note(
        'This is the Appendix A.2 client Initial, sealed in your browser with WebCrypto. The three inputs are below: a nonce built from the IV and the packet number, the whole unprotected header as associated data, and the frames as plaintext.',
      ),
      output,
    ]),
  );
}
