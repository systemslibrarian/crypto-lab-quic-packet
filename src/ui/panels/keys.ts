import {
  CONNECTION_ID,
  EXPECTED_CLIENT_KEYS,
  EXPECTED_HKDF_LABELS,
  EXPECTED_INITIAL_SECRET,
  EXPECTED_SERVER_KEYS,
  INITIAL_SALT,
} from '../../fixtures/rfc9001';
import { bytesEqual, fromHex, toHex } from '../../quic/bytes';
import { type InitialKeysTrace, deriveInitialKeys, quicV1 } from '../../quic/initial';
import { button, card, clear, compare, disclosure, el, liveRegion, note, textField } from '../dom';
import { claim, retired, verdict } from '../verdict';

/**
 * Exhibit 1 — keys from nothing secret.
 *
 * The one thing this panel has to make unmissable: both inputs are public. So
 * the connection ID is EDITABLE. Change it and every key changes, which is the
 * fastest way to see that the ID is the only thing separating one connection's
 * Initial keys from another's — and that nothing secret was ever involved.
 */

const version = quicV1(INITIAL_SALT);

export function renderKeysPanel(panel: HTMLElement): void {
  clear(panel);

  const { field, input } = textField({
    id: 'cid-input',
    label: 'Destination Connection ID (hex, 8-20 bytes)',
    value: toHex(CONNECTION_ID),
    size: 42,
    describedBy: 'cid-help',
  });

  const output = liveRegion('keys-output', 'Derived Initial keys');

  const derive = async (): Promise<void> => {
    clear(output);
    let connectionId: Uint8Array;
    try {
      connectionId = fromHex(input.value);
    } catch (error) {
      input.setAttribute('aria-invalid', 'true');
      output.append(
        verdict({
          id: 'keys-derivation',
          tone: 'refused',
          headline: 'REFUSED - that is not hexadecimal',
          body: error instanceof Error ? error.message : String(error),
        }),
      );
      return;
    }

    let keys: InitialKeysTrace;
    try {
      keys = await deriveInitialKeys(connectionId, version);
    } catch (error) {
      input.setAttribute('aria-invalid', 'true');
      output.append(
        verdict({
          id: 'keys-derivation',
          tone: 'refused',
          headline: 'REFUSED - no keys derived',
          body: error instanceof Error ? error.message : String(error),
        }),
      );
      return;
    }
    input.setAttribute('aria-invalid', 'false');

    const isRfcCase = bytesEqual(connectionId, CONNECTION_ID);
    const matchesRfc =
      isRfcCase &&
      bytesEqual(keys.initialSecret, EXPECTED_INITIAL_SECRET) &&
      bytesEqual(keys.client.secret, EXPECTED_CLIENT_KEYS.secret) &&
      bytesEqual(keys.client.key, EXPECTED_CLIENT_KEYS.key) &&
      bytesEqual(keys.client.iv, EXPECTED_CLIENT_KEYS.iv) &&
      bytesEqual(keys.client.hp, EXPECTED_CLIENT_KEYS.hp) &&
      bytesEqual(keys.server.secret, EXPECTED_SERVER_KEYS.secret) &&
      bytesEqual(keys.server.key, EXPECTED_SERVER_KEYS.key) &&
      bytesEqual(keys.server.iv, EXPECTED_SERVER_KEYS.iv) &&
      bytesEqual(keys.server.hp, EXPECTED_SERVER_KEYS.hp);

    output.append(
      verdict({
        id: 'keys-derivation',
        tone: isRfcCase ? (matchesRfc ? 'pass' : 'fail') : 'alarm',
        headline: isRfcCase
          ? matchesRfc
            ? 'DERIVED - and all nine values match RFC 9001 Appendix A.1'
            : 'DERIVED - but a value does NOT match RFC 9001 Appendix A.1'
          : 'DERIVED - from a connection ID of your own, with nothing secret',
        body: isRfcCase
          ? matchesRfc
            ? 'Every value below was computed here from the salt and the connection ID, then compared byte for byte against the one the RFC prints.'
            : 'That is a defect in this lab, not in the RFC. The comparison is a byte comparison against the RFC text checked into this repository.'
          : 'The RFC prints expected values only for its own connection ID, so there is nothing to compare these against - but they came from exactly the same two public inputs.',
      }),
    );

    output.append(
      el('h4', { text: 'Step 1 - HKDF-Extract, with a salt anyone can read' }),
      compare([
        { label: 'initial_salt', value: toHex(keys.salt), claim: 'keys-salt' },
        { label: 'connection ID', value: toHex(keys.connectionId), claim: 'keys-connection-id' },
        { label: 'initial_secret', value: toHex(keys.initialSecret), claim: 'keys-initial-secret' },
      ]),
      note(
        'HKDF-Extract(salt, IKM) is one HMAC-SHA-256 call: the salt is the HMAC key and the connection ID is the message. RFC 9001 section 5.2 prints the salt; the connection ID travels in the clear in the packet header.',
      ),
    );

    output.append(
      el('h4', { text: 'Step 2 - eight HKDF-Expand-Label steps, with their label bytes' }),
      el(
        'ol',
        { class: 'ladder', role: 'list' },
        keys.steps.map((step, index) =>
          el('li', { class: 'ladder-step', role: 'listitem' }, [
            el('div', {
              class: 'ladder-op',
              text: `${index + 1}. HKDF-Expand-Label(.., "${step.label}", "", ${step.outputLength})`,
            }),
            el('div', { class: 'ladder-detail' }, [
              el('span', { text: `info = ${toHex(step.info)}` }),
              claim(`keys-step-${index}`, `out  = ${toHex(step.output)}`, 'ladder-out'),
            ]),
          ]),
        ),
      ),
      note(
        'The info string is the TLS 1.3 HkdfLabel: a two-byte output length, the label length, the six ASCII bytes of "tls13 " followed by the label, then a zero context length. All of that is readable in the hex above.',
      ),
    );

    output.append(
      el('h4', { text: 'The six values that protect packets' }),
      el('div', { class: 'two-col' }, [
        el('div', {}, [
          el('h4', { text: 'client' }),
          compare([
            { label: 'secret', value: toHex(keys.client.secret), claim: 'keys-client-secret' },
            { label: 'key', value: toHex(keys.client.key), claim: 'keys-client-key' },
            { label: 'iv', value: toHex(keys.client.iv), claim: 'keys-client-iv' },
            { label: 'hp', value: toHex(keys.client.hp), claim: 'keys-client-hp' },
          ]),
        ]),
        el('div', {}, [
          el('h4', { text: 'server' }),
          compare([
            { label: 'secret', value: toHex(keys.server.secret), claim: 'keys-server-secret' },
            { label: 'key', value: toHex(keys.server.key), claim: 'keys-server-key' },
            { label: 'iv', value: toHex(keys.server.iv), claim: 'keys-server-iv' },
            { label: 'hp', value: toHex(keys.server.hp), claim: 'keys-server-hp' },
          ]),
        ]),
      ]),
      note(
        'Both directions come out of one initial_secret, separated only by the labels "client in" and "server in". A server reading a client Initial therefore derives the client keys itself - and so can anyone else.',
      ),
    );

    output.append(
      disclosure('The five HkdfLabel encodings the RFC prints, compared', [
        note(
          'Appendix A.1 prints these five info strings. They are the only QUIC-specific part of HKDF-Expand-Label, and getting the length field or the "tls13 " prefix wrong changes every key that follows.',
        ),
        compare(
          EXPECTED_HKDF_LABELS.map((label) => ({
            label: `"${label.label}"`,
            value: toHex(label.info),
            claim: `keys-label-${label.label.replace(/\s+/g, '-')}`,
          })),
        ),
      ]),
    );
  };

  input.addEventListener('input', () => {
    clear(output);
    output.append(
      retired('keys-derivation', 'Connection ID changed - derive again to see the keys for it.'),
    );
  });

  panel.append(
    card('Nothing secret goes in', [
      note(
        'QUIC derives its Initial packet keys with HKDF from two values: a salt printed in RFC 9001 section 5.2, and the Destination Connection ID the client wrote in the clear in its first packet. No shared secret, no handshake, no entropy either end keeps to itself. Edit the connection ID and watch all nine values move.',
      ),
      el('div', { class: 'controls' }, [
        field,
        button({
          id: 'derive-btn',
          label: 'Derive the Initial keys',
          primary: true,
          onClick: () => void derive(),
        }),
        button({
          id: 'reset-cid-btn',
          label: "Use the RFC's connection ID",
          onClick: () => {
            input.value = toHex(CONNECTION_ID);
            void derive();
          },
        }),
      ]),
      el('p', {
        id: 'cid-help',
        class: 'note',
        text: 'Hexadecimal, 16 to 40 characters; whitespace is ignored. RFC 9000 section 17.2 caps a connection ID at 20 bytes and section 7.2 requires a client’s first Initial to use at least 8, so anything else is refused here rather than silently derived.',
      }),
      output,
    ]),
  );

  void derive();
}
