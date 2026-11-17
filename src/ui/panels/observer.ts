import {
  A2_PAYLOAD,
  A2_PROTECTED_PACKET,
  INITIAL_SALT,
} from '../../fixtures/rfc9001';
import { AES_128_GCM } from '../../quic/aead';
import { bytesEqual, fromHex, toHex } from '../../quic/bytes';
import { deriveInitialKeys, quicV1 } from '../../quic/initial';
import { type ObserverResult, observe } from '../../quic/observer';
import { buildInitialHeader } from '../../quic/packet';
import { sealPacket } from '../../quic/protect';
import { button, card, clear, compare, disclosure, el, liveRegion, note } from '../dom';
import { hexView } from '../hexview';
import { claim, retired, verdict } from '../verdict';

/**
 * A connection ID the RFC never used, for the "a connection it has never seen"
 * control below. Any 8-byte value would do; a fixed one keeps the exhibit
 * reproducible and the claims suite able to name the key it produces.
 */
const FOREIGN_CONNECTION_ID = fromHex('0badc0ffee1dea00');

/**
 * Exhibit 4 — the observer. Also the lab's NEGATIVE CLAIM fixture (§4.1d).
 *
 * The evidence fixture is the RFC's own client Initial: every check the page
 * performs reports success — the packet matches the RFC byte for byte, the
 * authentication tag verifies, the header protection comes off cleanly, the
 * ClientHello parses — and the named property is violated anyway, because an
 * observer with no key read the server name out of it. The verdict therefore
 * has to read as success and failure at once.
 *
 * THE FUNCTION SIGNATURE IS THE INVARIANT. `observe(packet)` takes the bytes
 * and nothing else: there is no parameter it could be handed a key or a
 * connection ID through. The panel passes a packet; everything else it shows
 * came out of that packet or out of RFC 9001.
 */

const NEGATIVE_CLAIM =
  'This packet is encrypted and its authentication tag verifies. That says nothing about secrecy: its keys come from a published constant and a value in the packet itself, and anyone on the path can open it.';

export async function renderObserverPanel(panel: HTMLElement): Promise<void> {
  clear(panel);

  const output = liveRegion('observer-output', 'What an observer with no key recovers');

  let packet = A2_PROTECTED_PACKET;

  const run = async (): Promise<void> => {
    clear(output);
    const result = await observe(packet);
    render(output, result, bytesEqual(packet, A2_PROTECTED_PACKET));
  };

  panel.append(
    card('An observer on the path, holding no key at all', [
      note(
        'This is the RFC’s own 1200-byte client Initial, exactly as Appendix A.2 prints it. Hand it to a function whose only argument is the packet bytes, and watch what comes back.',
      ),
      hexView({
        title: 'The packet, as it appears on the wire',
        bytes: A2_PROTECTED_PACKET,
        limit: 64,
        meta: `${A2_PROTECTED_PACKET.length} bytes, from RFC 9001 Appendix A.2`,
        ariaLabel: 'The protected client Initial packet as it appears on the wire',
      }),
      el('div', { class: 'controls' }, [
        button({
          id: 'observe-btn',
          label: 'Open it',
          primary: true,
          onClick: () => void run(),
        }),
        button({
          id: 'observe-flip-btn',
          label: 'Flip one payload bit first',
          onClick: () => {
            const tampered = A2_PROTECTED_PACKET.slice();
            tampered[600] ^= 0x01;
            packet = tampered;
            clear(output);
            output.append(
              retired(
                'observer-result',
                'Packet changed - one bit of payload byte 600 is flipped. Open it again.',
              ),
            );
          },
        }),
        button({
          id: 'observe-foreign-btn',
          label: 'Rebuild it under a connection it has never seen',
          onClick: () => {
            void (async () => {
              const keys = await deriveInitialKeys(FOREIGN_CONNECTION_ID, quicV1(INITIAL_SALT));
              const header = buildInitialHeader({
                destinationConnectionId: FOREIGN_CONNECTION_ID,
                sourceConnectionId: new Uint8Array(0),
                packetNumber: 7n,
                packetNumberLength: 4,
                payloadLength: A2_PAYLOAD.length,
                tagLength: 16,
              });
              const sealed = await sealPacket({
                header,
                payload: A2_PAYLOAD,
                packetNumber: 7n,
                keys: keys.client,
                aead: AES_128_GCM,
                headerProtection: 'aes',
              });
              packet = sealed.packet;
              clear(output);
              output.append(
                retired(
                  'observer-result',
                  `Packet rebuilt under connection ID ${toHex(FOREIGN_CONNECTION_ID)} and packet number 7, sealed with keys derived from that ID. Open it again.`,
                ),
              );
            })();
          },
        }),
        button({
          id: 'observe-restore-btn',
          label: "Restore the RFC's packet",
          onClick: () => {
            packet = A2_PROTECTED_PACKET;
            clear(output);
            output.append(
              retired('observer-result', "Packet restored to the RFC's bytes. Open it again."),
            );
          },
        }),
      ]),
      output,
    ]),
    card('This is by design, and the RFC says so', [
      note(
        'RFC 9001 section 7, "Security of Initial Messages", in full: "Initial packets are not protected with a secret key, so they are subject to potential tampering by an attacker. QUIC provides protection against attackers that cannot read packets but does not attempt to provide additional protection against attacks where the attacker can observe and inject packets."',
      ),
      note(
        'So what does the encryption buy? Two real things. An off-path attacker who cannot see your packets cannot forge one that opens, because they do not know the connection ID. And a packet corrupted anywhere in flight - by a bad cable, a buggy middlebox, a cosmic ray - fails its tag rather than being processed as garbage. Neither of those is secrecy, and QUIC does not claim it. Secrecy starts with the Handshake keys, which come from the TLS key exchange this lab does not run.',
      ),
      disclosure('What an observer cannot do, even here', [
        note(
          'It cannot read a Handshake or 1-RTT packet: those keys come from the TLS key exchange, and nothing on the wire yields them. It cannot forge a Retry packet for a connection it has not seen, because the Retry tag commits to the original connection ID, which is not in the Retry packet (exhibit 5). And an observer that modifies an Initial packet breaks the TLS transcript, so the handshake fails - RFC 9001 section 7 notes that tampering with the TLS messages themselves is detectable, while tampering with an ACK is not.',
        ),
      ]),
    ]),
  );

  await run();
}

function render(output: HTMLElement, result: ObserverResult, isRfcPacket: boolean): void {
  if (result.refusal !== null && result.serverName === null && !result.open?.opened) {
    output.append(
      verdict({
        id: 'observer-result',
        tone: 'refused',
        headline: result.open
          ? 'NOT OPENED - no plaintext, and no server name'
          : 'REFUSED - the observer would not even try',
        body: result.refusal,
      }),
    );
    if (result.connectionId !== null) {
      output.append(
        compare([
          {
            label: 'connection ID',
            value: toHex(result.connectionId),
            claim: 'observer-connection-id',
          },
        ]),
      );
    }
    if (result.open) {
      output.append(
        note(
          `Header protection still came off: the observer learned the packet number was ${result.open.packetNumber} before the tag failed. Removing the mask needs no authentication, so a packet that will be discarded gives up its packet number first.`,
        ),
        compare([
          { label: 'packet number', value: String(result.open.packetNumber), claim: 'observer-packet-number' },
          { label: 'plaintext shown', value: 'none', claim: 'observer-plaintext-shown' },
          { label: 'server name', value: 'none', claim: 'observer-server-name' },
        ]),
      );
    }
    output.append(walk(result));
    return;
  }

  if (result.serverName === null) {
    output.append(
      verdict({
        id: 'observer-result',
        tone: 'refused',
        headline: 'OPENED - but no server name was found',
        body:
          result.refusal ??
          'The authentication tag verified and the payload was recovered, but the walk to a server_name extension did not complete. Nothing is guessed here: the parser reports how far it got.',
      }),
      compare([
        { label: 'server name', value: 'not found', claim: 'observer-server-name' },
      ]),
      walk(result),
    );
    return;
  }

  // The negative-claim fixture: everything succeeded, and that is the problem.
  output.append(
    verdict({
      id: 'observer-result',
      tone: 'alarm',
      headline: 'AUTHENTICATED AND ENCRYPTED - AND OPENED BY AN OBSERVER WITH NO KEY',
      body: `Every check this page performs reported success. The ${A2_PROTECTED_PACKET.length}-byte packet matches the RFC byte for byte, the AES-128-GCM tag verifies, header protection came off cleanly, and the ClientHello parsed. The server name below came out of the decrypted bytes.`,
    }),
    el(
      'div',
      {
        class: 'negative-claim',
        'data-verdict': 'observer-negative-claim',
        // Its own tone: this is not a judgement about this run, it is a
        // standing statement about what the construction does not buy. Giving
        // it a verdict tone would make it read as an outcome.
        'data-tone': 'caveat',
      },
      [
        el('span', { class: 'negative-claim-label', text: 'WHAT THIS DOES NOT BUY' }),
        el('p', { text: NEGATIVE_CLAIM }),
      ],
    ),
    el('h4', { text: 'What came back' }),
    el('div', { class: 'compare' }, [
      el('div', { class: 'compare-row' }, [
        el('span', { class: 'compare-label', text: 'server name' }),
        claim('observer-server-name', result.serverName),
      ]),
      el('div', { class: 'compare-row' }, [
        el('span', { class: 'compare-label', text: 'connection ID' }),
        claim('observer-connection-id', toHex(result.connectionId ?? new Uint8Array(0))),
      ]),
      el('div', { class: 'compare-row' }, [
        el('span', { class: 'compare-label', text: 'packet number' }),
        claim('observer-packet-number', String(result.open?.packetNumber ?? '')),
      ]),
      el('div', { class: 'compare-row' }, [
        el('span', { class: 'compare-label', text: 'payload bytes' }),
        claim('observer-payload-length', String(result.open?.plaintext?.length ?? 0)),
      ]),
      el('div', { class: 'compare-row' }, [
        el('span', { class: 'compare-label', text: 'frames' }),
        claim('observer-frames', result.frames.join(', ')),
      ]),
      el('div', { class: 'compare-row' }, [
        el('span', { class: 'compare-label', text: 'client key used' }),
        claim('observer-client-key', toHex(result.keys?.client.key ?? new Uint8Array(0))),
      ]),
    ]),
    note(
      isRfcPacket
        ? `The key above is the one RFC 9001 Appendix A.1 prints. The observer did not have it: it read the connection ID ${toHex(result.connectionId ?? new Uint8Array(0))} out of the packet, combined it with the salt from section 5.2, and derived the key itself.`
        : 'The key above was derived from the connection ID in the packet you supplied, not from anything the observer was told.',
    ),
    walk(result),
    disclosure('The ClientHello bytes, with the name in them', [
      note(
        'The server name is in the clear inside the CRYPTO frame, because TLS 1.3 sends the ClientHello before any key exchange has happened. Encrypted Client Hello (ECH) is the mechanism that closes this; see the Blind Hello lab linked at the foot of the page.',
      ),
      ...(result.open?.plaintext
        ? [
            hexView({
              title: 'Decrypted payload, first 112 bytes',
              bytes: result.open.plaintext.subarray(0, 112),
              limit: 112,
              spans: nameSpan(result.open.plaintext.subarray(0, 112), result.serverName),
              meta: `the name is ASCII ${toHex(new TextEncoder().encode(result.serverName))}`,
              ariaLabel: 'The decrypted payload with the server name highlighted',
            }),
          ]
        : []),
    ]),
  );
}

function nameSpan(
  bytes: Uint8Array,
  name: string,
): Array<{ start: number; end: number; className: string; label: string; bracket?: boolean }> {
  const needle = new TextEncoder().encode(name);
  outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    return [
      {
        start: i,
        end: i + needle.length,
        className: 'f-sample',
        label: `the server name, in ASCII: ${name}`,
        bracket: true,
      },
    ];
  }
  return [];
}

/** How far the walk got, step by step, in either outcome. */
function walk(result: ObserverResult): HTMLElement {
  return disclosure('Every step the observer took', [
    note(
      'The observer is handed the packet bytes and nothing else - that is enforced by the function signature, not by convention. Everything here it either read out of the packet or read out of RFC 9001.',
    ),
    el(
      'ol',
      { class: 'ladder', role: 'list' },
      result.path.map((step, index) =>
        el('li', { class: 'ladder-step', role: 'listitem' }, [
          el('div', { class: 'ladder-detail' }, [
            claim(`observer-step-${index}`, step, 'ladder-out'),
          ]),
        ]),
      ),
    ),
    ...(result.refusal === null
      ? []
      : [note(`Then it stopped: ${result.refusal}`)]),
  ]);
}

export { NEGATIVE_CLAIM };
