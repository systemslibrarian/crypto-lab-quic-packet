import {
  A2_PAYLOAD,
  A2_PROTECTED_PACKET,
  A2_UNPROTECTED_HEADER,
  CONNECTION_ID,
  INITIAL_SALT,
} from '../../fixtures/rfc9001';
import { AES_128_GCM } from '../../quic/aead';
import { bytesEqual, fromHex, toHex } from '../../quic/bytes';
import { deriveInitialKeys, quicV1 } from '../../quic/initial';
import { PacketFormatError } from '../../quic/packet';
import { type OpenTrace, openPacket } from '../../quic/protect';
import { button, card, clear, compare, el, liveRegion, note } from '../dom';
import { differenceSpans, hexView } from '../hexview';
import { claim, retired, verdict } from '../verdict';

/**
 * Exhibit 6 — break it on purpose.
 *
 * Each break runs the REAL open path against the REAL AEAD. Nothing here is a
 * canned failure message: the verdict is whatever `openPacket` returned, and
 * the plaintext row says "none" because there is no plaintext to show, not
 * because the panel declines to show it.
 *
 * The five breaks are chosen so each one fails at a DIFFERENT stage, which is
 * the teaching point: a packet can fail before the AEAD is reached at all.
 */

interface Break {
  readonly id: string;
  readonly label: string;
  readonly what: string;
  readonly expect: string;
  apply(packet: Uint8Array): Uint8Array;
  /** A different connection ID to derive keys from, for the wrong-keys break. */
  readonly connectionId?: string;
}

const BREAKS: readonly Break[] = [
  {
    id: 'intact',
    label: 'Nothing (the RFC’s packet)',
    what: 'The packet exactly as Appendix A.2 prints it, under the keys derived from the connection ID inside it.',
    expect: 'Opens. Packet number 2, 1162 bytes of frames.',
    apply: (packet) => packet,
  },
  {
    id: 'ciphertext-bit',
    label: 'Flip a ciphertext bit',
    what: 'One bit of payload byte 600 - deep inside the frames, far from the header and the tag.',
    expect:
      'Header protection still comes off, so the packet number is still recovered. Then the tag fails and there is no plaintext.',
    apply: (packet) => {
      const out = packet.slice();
      out[600] ^= 0x01;
      return out;
    },
  },
  {
    id: 'tag-bit',
    label: 'Flip a tag bit',
    what: 'The last bit of the 16-byte authentication tag.',
    expect: 'The tag fails. Identical outcome to the previous break, which is the point of a tag.',
    apply: (packet) => {
      const out = packet.slice();
      out[out.length - 1] ^= 0x01;
      return out;
    },
  },
  {
    id: 'masked-header-bit',
    label: 'Flip a masked header bit',
    what: 'The low bit of the first byte, which after unmasking is part of the packet-number LENGTH field.',
    expect:
      'The receiver unmasks a first byte that lies about how long the packet number is, unmasks the wrong number of bytes, rebuilds associated data that never existed, and the tag fails.',
    apply: (packet) => {
      const out = packet.slice();
      out[0] ^= 0x01;
      return out;
    },
  },
  {
    id: 'wrong-connection-id',
    label: 'Use the wrong connection ID',
    what: 'Leave the packet alone and derive the keys from a connection ID one bit different.',
    expect:
      'Different keys, so a different mask: the packet number comes out as nonsense and the tag fails. Nothing about the packet changed - only what the receiver thought the keys were.',
    apply: (packet) => packet,
    connectionId: (() => {
      const other = CONNECTION_ID.slice();
      other[0] ^= 0x01;
      return toHex(other);
    })(),
  },
  {
    id: 'too-short',
    label: 'Truncate the packet',
    what: 'Cut the packet to 30 bytes - shorter than the 16-byte sample needs.',
    expect:
      'Refused before any AEAD runs. RFC 9001 section 5.4.2: an endpoint "MUST discard packets that are not long enough to contain a complete sample".',
    apply: (packet) => packet.slice(0, 30),
  },
  {
    id: 'unknown-version',
    label: 'Change the version field',
    what: 'Set the Version to 0x6b3343cf, which is QUIC version 2 (RFC 9369).',
    expect:
      'Refused with the version shown, and NO keys derived. Version 2 uses a different salt and different labels, so version-1 keys would be meaningless.',
    apply: (packet) => {
      const out = packet.slice();
      out[1] = 0x6b;
      out[2] = 0x33;
      out[3] = 0x43;
      out[4] = 0xcf;
      return out;
    },
  },
];

export async function renderBreakPanel(panel: HTMLElement): Promise<void> {
  clear(panel);

  const output = liveRegion('break-output', 'What happens when the packet is broken');
  let chosen: Break = BREAKS[0];

  const select = el('select', { id: 'break-select', 'aria-describedby': 'break-help' }, []);
  for (const item of BREAKS) {
    select.append(el('option', { value: item.id, text: item.label }));
  }

  // Which break the verdict on screen was produced for. The no-op guard needs
  // this: `change` fires on a re-selection of the SAME option in several
  // browsers (and in Playwright's `selectOption`), and retiring then would
  // have the page claim it has not checked something it has.
  let shown: string | null = null;

  const run = async (): Promise<void> => {
    clear(output);
    shown = chosen.id;
    const packet = chosen.apply(A2_PROTECTED_PACKET);
    const connectionIdHex = chosen.connectionId ?? toHex(CONNECTION_ID);
    const keys = await deriveInitialKeys(fromHex(connectionIdHex), quicV1(INITIAL_SALT));

    output.append(
      el('p', { class: 'note' }, [el('strong', { text: 'What was changed: ' }), el('span', { text: chosen.what })]),
      compare([
        { label: 'keys from', value: connectionIdHex, claim: 'break-connection-id' },
        { label: 'packet length', value: `${packet.length} bytes`, claim: 'break-packet-length' },
      ]),
    );

    if (packet.length === A2_PROTECTED_PACKET.length && !bytesEqual(packet, A2_PROTECTED_PACKET)) {
      output.append(
        hexView({
          title: 'The bytes that changed',
          bytes: packet,
          limit: 32,
          spans: differenceSpans(packet, A2_PROTECTED_PACKET, 'changed from the RFC’s packet'),
          meta: `${differenceSpans(packet, A2_PROTECTED_PACKET, '').length} byte(s) differ from the RFC’s packet`,
          ariaLabel: 'The packet with the changed bytes marked',
        }),
      );
    }

    let trace: OpenTrace | null = null;
    let refusal: string | null = null;
    try {
      trace = await openPacket({
        packet,
        keys: keys.client,
        aead: AES_128_GCM,
        headerProtection: 'aes',
      });
    } catch (error) {
      refusal =
        error instanceof PacketFormatError ? error.message : `unexpected failure: ${String(error)}`;
    }

    if (trace === null) {
      output.append(
        verdict({
          id: 'break-result',
          tone: 'refused',
          headline: 'REFUSED - the packet was discarded before any decryption was attempted',
          body: refusal ?? 'No reason was recorded, which would itself be a defect.',
        }),
        compare([
          { label: 'packet number', value: 'never recovered', claim: 'break-packet-number' },
          { label: 'plaintext shown', value: 'none', claim: 'break-plaintext-shown' },
        ]),
        note(
          'This is the failure mode worth noticing: the packet never reached the AEAD. A parser that pressed on here would be reading past the end of a buffer.',
        ),
      );
      return;
    }

    const opened = trace.opened;
    const matchesOriginal = bytesEqual(packet, A2_PROTECTED_PACKET);

    output.append(
      verdict({
        id: 'break-result',
        tone: opened ? (matchesOriginal ? 'pass' : 'fail') : 'fail',
        headline: opened
          ? matchesOriginal
            ? 'OPENED - packet number 2, and the payload matches RFC 9001 Appendix A.2'
            : 'OPENED - a modified packet opened, which would be a defect in this lab'
          : 'NOT OPENED - and no plaintext is shown, because none was produced',
        body: opened
          ? matchesOriginal
            ? 'The baseline. Every break below is measured against this.'
            : 'A modified packet should never open.'
          : (trace.reason ?? 'No reason recorded.'),
      }),
      el('h4', { text: 'What the receiver got anyway' }),
      compare([
        {
          label: 'packet-number length',
          value: `${trace.packetNumberLength} byte(s), from unmasked first byte ${trace.unprotectedFirstByte.toString(16).padStart(2, '0')}`,
          claim: 'break-pn-length',
        },
        { label: 'mask', value: toHex(trace.mask), claim: 'break-mask' },
        {
          label: 'packet number',
          value: String(trace.packetNumber),
          claim: 'break-packet-number',
        },
        {
          label: 'plaintext shown',
          value: opened ? `${trace.plaintext?.length ?? 0} bytes` : 'none',
          claim: 'break-plaintext-shown',
        },
      ]),
      note(
        opened
          ? bytesEqual(trace.plaintext ?? new Uint8Array(0), A2_PAYLOAD)
            ? 'The recovered payload is byte-identical to the one Appendix A.2 describes.'
            : 'The recovered payload differs from Appendix A.2, which would be a defect.'
          : `Header protection is unauthenticated, so the receiver recovered a packet-number length and a packet number before anything was checked - here ${trace.packetNumber}, ${trace.packetNumber === 2n ? 'which happens to be right' : 'which is wrong'}. Only then did the tag fail. That asymmetry is why RFC 9001 keeps header protection and packet protection in separate sections with separate keys.`,
      ),
      el('p', { class: 'note' }, [
        el('strong', { text: 'Expected: ' }),
        el('span', { text: chosen.expect }),
      ]),
    );
  };

  select.addEventListener('change', () => {
    const next = BREAKS.find((item) => item.id === select.value);
    if (!next || next.id === shown) return; // the no-op guard
    chosen = next;
    shown = null;
    clear(output);
    output.append(
      retired('break-result', `Selection changed to "${chosen.label}" - run it to see what happens.`),
    );
  });

  panel.append(
    card('Break it on purpose', [
      note(
        'Every break below runs the real open path against the real AES-128-GCM in your browser. No outcome here is written in advance: the verdict is whatever the AEAD returned, and where it says no plaintext is shown, that is because none was produced.',
      ),
      el('div', { class: 'controls' }, [
        el('div', { class: 'field' }, [
          el('label', { for: 'break-select', text: 'What to break' }),
          select,
        ]),
        button({ id: 'break-run', label: 'Run it', primary: true, onClick: () => void run() }),
      ]),
      el('p', {
        id: 'break-help',
        class: 'note',
        text: 'Each of the seven fails at a different stage, and two of them are refused before any decryption is attempted.',
      }),
      output,
    ]),
    card('The unprotected header, for reference', [
      note(
        'The packet-number length lives in the two lowest bits of the first byte, which is why flipping one of those bits is more interesting than flipping a bit anywhere else in the header.',
      ),
      hexView({
        title: 'A.2 header, unprotected',
        bytes: A2_UNPROTECTED_HEADER,
        spans: [
          { start: 0, end: 1, className: 'f-first', label: 'first byte - low two bits are the packet-number length' },
          { start: 1, end: 5, className: 'f-version', label: 'Version' },
          { start: 6, end: 14, className: 'f-dcid', label: 'Destination Connection ID' },
          { start: 18, end: 22, className: 'f-pn', label: 'Packet Number' },
        ],
        ariaLabel: 'The unprotected A.2 header for reference',
      }),
      el('p', {}, [
        el('span', { class: 'compare-label', text: 'first byte: ' }),
        claim(
          'break-reference-first-byte',
          `${toHex(A2_UNPROTECTED_HEADER.subarray(0, 1))} = ${A2_UNPROTECTED_HEADER[0].toString(2).padStart(8, '0')} binary, so the packet-number length is ${(A2_UNPROTECTED_HEADER[0] & 0x03) + 1} bytes`,
        ),
      ]),
    ]),
  );

  await run();
}
