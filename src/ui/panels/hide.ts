import {
  A2_MASK,
  A2_PACKET_NUMBER,
  A2_PAYLOAD,
  A2_PROTECTED_PACKET,
  A2_SAMPLE,
  A2_UNPROTECTED_HEADER,
  CONNECTION_ID,
  INITIAL_SALT,
} from '../../fixtures/rfc9001';
import { AES_128_GCM } from '../../quic/aead';
import { bytesEqual, concat, toHex } from '../../quic/bytes';
import { aesBlock } from '../../quic/hp';
import { deriveInitialKeys, quicV1 } from '../../quic/initial';
import { firstByteMaskBits, parseHeader } from '../../quic/packet';
import { type SealTrace, openPacket, sealPacket } from '../../quic/protect';
import { button, card, clear, compare, disclosure, el, liveRegion, note } from '../dom';
import { differenceSpans, hexView, longHeaderSpans, sampleSpan } from '../hexview';
import { claim, verdict } from '../verdict';

/**
 * Exhibit 3 — hide the packet number. THE HEADLINE MECHANISM, STEPPED.
 *
 * The idea this lab exists to teach is a circle: the mask that hides the
 * packet number is computed from the ciphertext, and the ciphertext was
 * produced over a header that contains that packet number. Prose cannot carry
 * that and neither can a static hex dump, so it is a five-stage stepper the
 * reader drives — each press does one real operation and the view redraws
 * with what that operation produced.
 *
 * The motion here is the only animation on the page: a newly-completed stage
 * fades in by 0.22s, which marks WHICH thing just changed in a view that
 * redraws wholesale. It is tied to a button press and illustrates the order
 * of operations, so it is purposeful rather than decorative; a reduced-motion
 * preference cancels it and the static rule already paints the end state.
 */

interface Stage {
  readonly title: string;
  readonly what: string;
}

const STAGES: readonly Stage[] = [
  {
    title: 'Build the unprotected header',
    what: 'The packet number is sitting in the clear, in bytes 18 to 21. Anyone watching the wire can read it.',
  },
  {
    title: 'Seal the payload',
    what: 'AES-128-GCM over the frames, with that whole header as associated data. This has to happen first, because the next step needs the ciphertext.',
  },
  {
    title: 'Sample the ciphertext you just produced',
    what: 'Sixteen bytes, starting four bytes after the packet number field BEGINS - not after it ends. The receiver does not yet know how long the packet number is, so the offset cannot depend on it.',
  },
  {
    title: 'Encrypt the sample into a five-byte mask',
    what: 'One AES block under the header-protection key. The key is a third value from the same HKDF ladder, separate from the packet-protection key.',
  },
  {
    title: 'XOR the mask into the header',
    what: 'Four low bits of the first byte, then the packet-number bytes. The packet number is now hidden - by a mask derived from a ciphertext that was itself produced over the packet number.',
  },
];

export async function renderHidePanel(panel: HTMLElement): Promise<void> {
  clear(panel);

  const keys = await deriveInitialKeys(CONNECTION_ID, quicV1(INITIAL_SALT));
  const trace: SealTrace = await sealPacket({
    header: A2_UNPROTECTED_HEADER,
    payload: A2_PAYLOAD,
    packetNumber: A2_PACKET_NUMBER,
    keys: keys.client,
    aead: AES_128_GCM,
    headerProtection: 'aes',
  });
  const header = parseHeader(A2_UNPROTECTED_HEADER);
  const fullBlock = await aesBlock(keys.client.hp, trace.sample);

  let stage = 0;

  const stageList = el('div', { class: 'stepper', id: 'hp-stages' });
  const output = liveRegion('hide-output', 'Header protection, step by step');
  const count = el('span', { class: 'stepper-count', id: 'hp-count' });

  const headerSpans = longHeaderSpans({
    dcidLength: header.destinationConnectionId.length,
    scidLength: header.form === 'long' ? header.sourceConnectionId.length : 0,
    tokenLengthBytes: 1,
    lengthFieldBytes: 2,
    packetNumberOffset: trace.packetNumberOffset,
    packetNumberLength: trace.packetNumberLength,
  });

  const draw = (animate: boolean): void => {
    count.textContent = `step ${stage} of ${STAGES.length}`;

    clear(stageList);
    STAGES.forEach((item, index) => {
      const done = index < stage;
      const current = index === stage - 1;
      const node = el(
        'div',
        {
          class: current && animate ? 'stepper-stage reveal' : 'stepper-stage',
          'data-current': current ? 'true' : 'false',
          'data-stage': String(index + 1),
        },
        [
          el('h4', {}, [
            el('span', {
              class: done ? 'stepper-done' : 'stepper-pending',
              'aria-hidden': 'true',
              text: done ? '[done] ' : '[    ] ',
            }),
            el('span', { text: `${index + 1}. ${item.title}` }),
            el('span', {
              class: 'note',
              text: done ? ' (done)' : ' (not yet run)',
            }),
          ]),
          el('p', { text: item.what }),
        ],
      );
      stageList.append(node);
    });

    clear(output);

    // Stage 1+: the header, unprotected until stage 5.
    const masked = stage >= 5;
    const shownHeader = masked ? trace.protectedHeader : trace.unprotectedHeader;
    output.append(
      hexView({
        title: masked ? 'Header, protected' : 'Header, unprotected',
        bytes: shownHeader,
        spans: masked
          ? [...headerSpans, ...differenceSpans(trace.protectedHeader, trace.unprotectedHeader, 'masked by this step')]
          : headerSpans,
        ariaLabel: masked
          ? 'The protected header, with the masked bytes marked'
          : 'The unprotected header, annotated by field',
      }),
      el('p', {}, [
        el('span', { class: 'compare-label', text: 'packet number on the wire: ' }),
        claim(
          'hide-wire-packet-number',
          masked
            ? `${toHex(trace.protectedHeader.subarray(trace.packetNumberOffset, trace.packetNumberOffset + trace.packetNumberLength))} (hidden)`
            : `${toHex(trace.unprotectedHeader.subarray(trace.packetNumberOffset, trace.packetNumberOffset + trace.packetNumberLength))} (readable: packet number ${A2_PACKET_NUMBER})`,
        ),
      ]),
    );

    if (stage >= 2) {
      output.append(
        hexView({
          title: 'Ciphertext, as produced by step 2',
          bytes: concat(trace.ciphertext, trace.tag),
          limit: 48,
          spans:
            stage >= 3
              ? [sampleSpan(trace.sampleStart - trace.unprotectedHeader.length)]
              : [],
          meta:
            stage >= 3
              ? `sample starts at packet byte ${trace.sampleStart}, which is ciphertext byte ${trace.sampleStart - trace.unprotectedHeader.length}`
              : `${trace.ciphertext.length + trace.tag.length} bytes`,
          ariaLabel: 'The ciphertext, with the header-protection sample window marked by brackets',
        }),
      );
    }

    if (stage >= 3) {
      output.append(
        compare([
          {
            label: 'packet number at',
            value: `byte ${trace.packetNumberOffset}`,
            claim: 'hide-pn-offset',
          },
          {
            label: 'sample starts at',
            value: `byte ${trace.sampleStart} = ${trace.packetNumberOffset} + 4`,
            claim: 'hide-sample-offset',
          },
          { label: 'sample', value: toHex(trace.sample), claim: 'hide-sample' },
        ]),
      );
    }

    if (stage >= 4) {
      output.append(
        el('h4', { text: 'mask = AES-ECB(hp, sample), first five bytes' }),
        compare([
          { label: 'hp key', value: toHex(keys.client.hp), claim: 'hide-hp-key' },
          { label: 'AES block out', value: toHex(fullBlock), claim: 'hide-aes-block' },
          { label: 'mask (5 bytes)', value: toHex(trace.mask), claim: 'hide-mask' },
        ]),
        note(
          'WebCrypto has no AES-ECB, so this single block is taken from AES-CTR with the sample as the counter block over sixteen zero bytes, and cross-checked against AES-CBC with a zero IV. Both routes must agree or this panel refuses to draw.',
        ),
      );
    }

    if (stage >= 5) {
      const firstByteMask = trace.mask[0] & firstByteMaskBits(trace.unprotectedHeader[0]);
      output.append(
        el('h4', { text: 'The two fields the mask touches' }),
        el('div', { class: 'compare' }, [
          el('div', { class: 'compare-row' }, [
            el('span', { class: 'compare-label', text: 'first byte' }),
            claim(
              'hide-first-byte',
              `${toHex(trace.unprotectedHeader.subarray(0, 1))} XOR (${toHex(trace.mask.subarray(0, 1))} AND 0f) = ${toHex(trace.protectedHeader.subarray(0, 1))}`,
            ),
          ]),
          el('div', { class: 'compare-row' }, [
            el('span', { class: 'compare-label', text: 'packet number' }),
            claim(
              'hide-packet-number-bytes',
              `${toHex(trace.unprotectedHeader.subarray(trace.packetNumberOffset, trace.packetNumberOffset + trace.packetNumberLength))} XOR ${toHex(trace.mask.subarray(1, 1 + trace.packetNumberLength))} = ${toHex(trace.protectedHeader.subarray(trace.packetNumberOffset, trace.packetNumberOffset + trace.packetNumberLength))}`,
            ),
          ]),
        ]),
        note(
          `Only four low bits of the first byte move on a long header, and five on a short one - RFC 9001 section 5.4. Here the effective first-byte mask is 0x${firstByteMask.toString(16).padStart(2, '0')}, so the Version, the type nibble and the connection IDs are all untouched. A middlebox can still route the packet; it just cannot read the packet number.`,
        ),
      );

      const matches = bytesEqual(trace.packet, A2_PROTECTED_PACKET);
      output.append(
        verdict({
          id: 'hide-result',
          tone: matches ? 'pass' : 'fail',
          headline: matches
            ? `PROTECTED - the assembled ${trace.packet.length}-byte packet matches RFC 9001 Appendix A.2 byte for byte`
            : 'PROTECTED - but the assembled packet does NOT match RFC 9001 Appendix A.2',
          body: matches
            ? 'Header, ciphertext and tag, built here in five steps from the published salt and the connection ID.'
            : 'That is a defect in this lab. The comparison is a byte comparison against the RFC text checked into this repository.',
        }),
        compare([
          { label: 'built here', value: `${trace.packet.length} bytes, sha of hex ends ${toHex(trace.packet.subarray(-8))}`, claim: 'hide-built-tail' },
          { label: "the RFC's", value: `${A2_PROTECTED_PACKET.length} bytes, ends ${toHex(A2_PROTECTED_PACKET.subarray(-8))}`, claim: 'hide-rfc-tail' },
        ]),
      );
    }
  };

  const next = button({
    id: 'hp-next',
    label: 'Run the next step',
    primary: true,
    onClick: () => {
      if (stage < STAGES.length) {
        stage++;
        draw(true);
        syncButtons();
      }
    },
  });
  const reset = button({
    id: 'hp-reset',
    label: 'Start over',
    onClick: () => {
      stage = 0;
      draw(false);
      syncButtons();
    },
  });
  const all = button({
    id: 'hp-all',
    label: 'Run all five',
    onClick: () => {
      stage = STAGES.length;
      draw(false);
      syncButtons();
    },
  });

  function syncButtons(): void {
    next.disabled = stage >= STAGES.length;
    all.disabled = stage >= STAGES.length;
    reset.disabled = stage === 0;
  }

  panel.append(
    card('A protocol that encrypts its own packet numbers', [
      note(
        'The packet number has to be hidden, because a watcher who can count packets per connection can track a device across networks. But it also has to be readable by the receiver before the receiver can decrypt anything, since the nonce depends on it. QUIC resolves that with a second key and a mask taken from the ciphertext it has just produced. Press through the five steps and watch the circle close.',
      ),
      el('div', { class: 'stepper-bar' }, [next, all, reset, count]),
      stageList,
      output,
    ]),
    await receiverCard(keys.client, trace),
    card('Why the sample starts where it does', [
      note(
        'The sample begins four bytes after the packet-number field starts, as if the packet number were always four bytes long - its maximum. It has to: the receiver reads the sample BEFORE it has unmasked the bits that say how long the packet number really is. If the offset depended on the real length, the receiver would need the answer before it could ask the question.',
      ),
      note(
        'That is also why a packet must be long enough to supply a complete sample, and why RFC 9001 section 5.4.2 says an endpoint "MUST discard packets that are not long enough". Exhibit 6 tries exactly that.',
      ),
      disclosure('And the other cipher', [
        note(
          'When ChaCha20-Poly1305 is negotiated, the mask comes from the raw ChaCha20 keystream instead: the first four sample bytes are the block counter, read LITTLE-endian, and the remaining twelve are the nonce; the mask is ChaCha20 applied to five zero bytes. Exhibit 5 runs that one on the Appendix A.5 packet.',
        ),
      ]),
    ]),
  );

  draw(false);
  syncButtons();
}

/** The receiving side: the same five operations, in a different order. */
async function receiverCard(
  keys: { key: Uint8Array; iv: Uint8Array; hp: Uint8Array },
  sealed: SealTrace,
): Promise<HTMLElement> {
  const open = await openPacket({
    packet: A2_PROTECTED_PACKET,
    keys,
    aead: AES_128_GCM,
    headerProtection: 'aes',
  });

  const sameSample = bytesEqual(open.sample, A2_SAMPLE);
  const sameMask = bytesEqual(open.mask, A2_MASK);
  const recovered = bytesEqual(open.unprotectedHeader, A2_UNPROTECTED_HEADER);

  return card('The receiver runs the same steps in a different order', [
    note(
      'A sender masks LAST. A receiver has to unmask FIRST, and it has to do it in two halves, because after the first byte comes off it knows something it did not know before.',
    ),
    el('ol', { class: 'ladder', role: 'list' }, [
      el('li', { class: 'ladder-step', role: 'listitem' }, [
        el('div', { class: 'ladder-op', text: '1. Find the packet-number OFFSET without any key' }),
        el('div', { class: 'ladder-detail' }, [
          el('span', { text: 'Readable from the Version, the connection-ID lengths, the Token Length and the Length field - none of which is protected.' }),
          claim('open-pn-offset', `offset = byte ${open.packetNumberOffset}`, 'ladder-out'),
        ]),
      ]),
      el('li', { class: 'ladder-step', role: 'listitem' }, [
        el('div', { class: 'ladder-op', text: '2. Sample and build the same mask' }),
        el('div', { class: 'ladder-detail' }, [
          claim('open-sample', `sample = ${toHex(open.sample)}${sameSample ? ' (same window the sender used)' : ' (DIFFERENT from the sender)'}`, 'ladder-out'),
          claim('open-mask', `mask   = ${toHex(open.mask)}${sameMask ? ' (identical)' : ' (DIFFERENT)'}`, 'ladder-out'),
        ]),
      ]),
      el('li', { class: 'ladder-step', role: 'listitem' }, [
        el('div', { class: 'ladder-op', text: '3. Unmask the first byte - and only now learn the length' }),
        el('div', { class: 'ladder-detail' }, [
          claim(
            'open-first-byte',
            `on the wire ${open.protectedFirstByte.toString(16).padStart(2, '0')} says "${(open.protectedFirstByte & 0x03) + 1}-byte packet number"`,
            'ladder-out',
          ),
          claim(
            'open-length',
            `unmasked ${open.unprotectedFirstByte.toString(16).padStart(2, '0')} says "${open.packetNumberLength}-byte packet number" - which is the truth`,
            'ladder-out',
          ),
        ]),
      ]),
      el('li', { class: 'ladder-step', role: 'listitem' }, [
        el('div', { class: 'ladder-op', text: '4. Unmask that many packet-number bytes, then rebuild the associated data' }),
        el('div', { class: 'ladder-detail' }, [
          claim('open-packet-number', `packet number = ${open.packetNumber}`, 'ladder-out'),
          claim(
            'open-recovered-header',
            `header = ${toHex(open.unprotectedHeader)}${recovered ? ' (identical to the sender’s)' : ' (DIFFERENT from the sender’s)'}`,
            'ladder-out',
          ),
        ]),
      ]),
      el('li', { class: 'ladder-step', role: 'listitem' }, [
        el('div', { class: 'ladder-op', text: '5. Open the payload' }),
        el('div', { class: 'ladder-detail' }, [
          claim(
            'open-payload',
            open.opened
              ? `opened: ${open.plaintext?.length ?? 0} bytes of frames, tag verified`
              : `not opened: ${open.reason}`,
            'ladder-out',
          ),
        ]),
      ]),
    ]),
    verdict({
      id: 'open-result',
      tone: open.opened && recovered ? 'pass' : 'fail',
      headline:
        open.opened && recovered
          ? 'OPENED - and the recovered header is byte-identical to the one the sender sealed over'
          : 'NOT OPENED',
      body:
        open.opened && recovered
          ? `Round trip closed: the sender's ${sealed.packet.length}-byte packet went out and came back as packet number ${open.packetNumber} with ${open.plaintext?.length ?? 0} bytes of frames.`
          : open.reason ?? 'The recovered header did not match.',
    }),
    note(
      'Notice what step 3 means for an attacker: removing header protection needs no authentication at all. A packet whose tag will fail still gives up its packet number first. The mask hides the number from a passive watcher; it does not prove anything about the packet.',
    ),
  ]);
}
