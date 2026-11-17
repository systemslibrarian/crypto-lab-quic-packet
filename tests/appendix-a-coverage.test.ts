import { describe, expect, it } from 'vitest';

import * as fx from '../src/fixtures/rfc9001';
import { toHex } from '../src/quic/bytes';
import { rfcText, section } from './rfc-text';

/**
 * How many of the values RFC 9001 Appendix A prints does this lab actually
 * reproduce?
 *
 * The README states a number, and a stated number with nothing checking it is
 * the sort of claim that drifts. So the number is COUNTED here, from two
 * directions that have to agree:
 *
 *   - the forward count: every value the fixtures parse out of the appendix,
 *     each of which some suite compares a computed result against;
 *   - the backward count: every hex-looking value the appendix text contains,
 *     so a value the lab quietly ignores shows up as a gap rather than as
 *     nothing.
 */

const APPENDIX = section(
  rfcText('rfc9001.txt'),
  'Appendix A.  Sample Packet Protection',
  'Appendix B.  AEAD Algorithm Analysis',
);

/**
 * Every Appendix A value this lab parses and checks. Each entry names the
 * suite that compares a COMPUTED value against it — a fixture nobody computes
 * against is a transcription, not a reproduction, so an entry with no owner
 * is a defect this test is meant to expose.
 */
const REPRODUCED: ReadonlyArray<{ section: string; name: string; value: Uint8Array; by: string }> = [
  // A.1 — the five HkdfLabel encodings.
  ...fx.EXPECTED_HKDF_LABELS.map((label) => ({
    section: 'A.1',
    name: `HkdfLabel for "${label.label}"`,
    value: label.info,
    by: 'hkdf.test.ts',
  })),
  // A.1 — the nine key values.
  { section: 'A.1', name: 'initial_secret', value: fx.EXPECTED_INITIAL_SECRET, by: 'initial.test.ts' },
  { section: 'A.1', name: 'client_initial_secret', value: fx.EXPECTED_CLIENT_KEYS.secret, by: 'initial.test.ts' },
  { section: 'A.1', name: 'client key', value: fx.EXPECTED_CLIENT_KEYS.key, by: 'initial.test.ts' },
  { section: 'A.1', name: 'client iv', value: fx.EXPECTED_CLIENT_KEYS.iv, by: 'initial.test.ts' },
  { section: 'A.1', name: 'client hp', value: fx.EXPECTED_CLIENT_KEYS.hp, by: 'initial.test.ts' },
  { section: 'A.1', name: 'server_initial_secret', value: fx.EXPECTED_SERVER_KEYS.secret, by: 'initial.test.ts' },
  { section: 'A.1', name: 'server key', value: fx.EXPECTED_SERVER_KEYS.key, by: 'initial.test.ts' },
  { section: 'A.1', name: 'server iv', value: fx.EXPECTED_SERVER_KEYS.iv, by: 'initial.test.ts' },
  { section: 'A.1', name: 'server hp', value: fx.EXPECTED_SERVER_KEYS.hp, by: 'initial.test.ts' },
  // A.2 — the client Initial.
  { section: 'A.2', name: 'CRYPTO frame', value: fx.A2_CRYPTO_FRAME, by: 'clienthello.test.ts' },
  { section: 'A.2', name: 'unprotected header', value: fx.A2_UNPROTECTED_HEADER, by: 'packet.test.ts, protect.test.ts' },
  { section: 'A.2', name: 'sample', value: fx.A2_SAMPLE, by: 'protect.test.ts' },
  { section: 'A.2', name: 'mask', value: fx.A2_MASK, by: 'protect.test.ts' },
  { section: 'A.2', name: 'masked first byte', value: fx.A2_MASKED_FIRST_BYTE, by: 'protect.test.ts' },
  { section: 'A.2', name: 'masked packet-number bytes', value: fx.A2_MASKED_PACKET_NUMBER, by: 'protect.test.ts' },
  { section: 'A.2', name: 'protected header', value: fx.A2_PROTECTED_HEADER, by: 'protect.test.ts' },
  { section: 'A.2', name: 'protected packet (1200 bytes)', value: fx.A2_PROTECTED_PACKET, by: 'protect.test.ts' },
  // A.3 — the server Initial.
  { section: 'A.3', name: 'payload', value: fx.A3_PAYLOAD, by: 'protect.test.ts' },
  { section: 'A.3', name: 'unprotected header', value: fx.A3_UNPROTECTED_HEADER, by: 'packet.test.ts, protect.test.ts' },
  { section: 'A.3', name: 'sample', value: fx.A3_SAMPLE, by: 'protect.test.ts' },
  { section: 'A.3', name: 'mask', value: fx.A3_MASK, by: 'protect.test.ts' },
  { section: 'A.3', name: 'protected header', value: fx.A3_PROTECTED_HEADER, by: 'protect.test.ts' },
  { section: 'A.3', name: 'protected packet (135 bytes)', value: fx.A3_PROTECTED_PACKET, by: 'protect.test.ts' },
  // A.4 — Retry.
  { section: 'A.4', name: 'Retry packet and its integrity tag', value: fx.A4_RETRY_PACKET, by: 'retry.test.ts' },
  // A.5 — the ChaCha20-Poly1305 short-header packet.
  { section: 'A.5', name: 'secret', value: fx.A5_SECRET, by: 'protect.test.ts' },
  { section: 'A.5', name: 'key', value: fx.A5_KEY, by: 'protect.test.ts' },
  { section: 'A.5', name: 'iv', value: fx.A5_IV, by: 'protect.test.ts' },
  { section: 'A.5', name: 'hp', value: fx.A5_HP, by: 'protect.test.ts' },
  { section: 'A.5', name: 'ku', value: fx.A5_KU, by: 'protect.test.ts' },
  { section: 'A.5', name: 'nonce', value: fx.A5_NONCE, by: 'protect.test.ts' },
  { section: 'A.5', name: 'unprotected header', value: fx.A5_UNPROTECTED_HEADER, by: 'packet.test.ts, protect.test.ts' },
  { section: 'A.5', name: 'payload plaintext', value: fx.A5_PLAINTEXT, by: 'protect.test.ts' },
  { section: 'A.5', name: 'payload ciphertext', value: fx.A5_CIPHERTEXT, by: 'protect.test.ts' },
  { section: 'A.5', name: 'sample', value: fx.A5_SAMPLE, by: 'protect.test.ts' },
  { section: 'A.5', name: 'mask', value: fx.A5_MASK, by: 'protect.test.ts' },
  { section: 'A.5', name: 'protected header', value: fx.A5_PROTECTED_HEADER, by: 'protect.test.ts' },
  { section: 'A.5', name: 'protected packet (21 bytes)', value: fx.A5_PACKET, by: 'protect.test.ts' },
];

/**
 * The count the README quotes. If a value is added or removed, this fails and
 * the README has to move with it.
 */
export const APPENDIX_A_VALUES_REPRODUCED = 42;

describe('Appendix A coverage', () => {
  it(`reproduces ${APPENDIX_A_VALUES_REPRODUCED} of the values Appendix A prints`, () => {
    expect(REPRODUCED.length).toBe(APPENDIX_A_VALUES_REPRODUCED);
  });

  it('every reproduced value is non-empty and really appears in the appendix text', () => {
    const appendixHex = APPENDIX.replace(/[^0-9a-f]/g, '');
    for (const entry of REPRODUCED) {
      expect(entry.value.length, `${entry.section} ${entry.name}`).toBeGreaterThan(0);
      // A.2's payload is the CRYPTO frame plus PADDING the RFC does not print,
      // so the frame is what is checked here; A.5's one-byte plaintext is too
      // short to be a meaningful substring search.
      if (entry.value.length >= 4) {
        expect(appendixHex, `${entry.section} ${entry.name}`).toContain(toHex(entry.value));
      }
    }
  });

  it('every reproduced value names the suite that computes against it', () => {
    for (const entry of REPRODUCED) {
      expect(entry.by, `${entry.section} ${entry.name}`).toMatch(/\.test\.ts/);
    }
  });

  it('covers all five appendix sections', () => {
    const sections = new Set(REPRODUCED.map((e) => e.section));
    expect([...sections].sort()).toEqual(['A.1', 'A.2', 'A.3', 'A.4', 'A.5']);
  });

  it('counts per section as the README states', () => {
    const counts: Record<string, number> = {};
    for (const entry of REPRODUCED) counts[entry.section] = (counts[entry.section] ?? 0) + 1;
    expect(counts).toEqual({ 'A.1': 14, 'A.2': 8, 'A.3': 6, 'A.4': 1, 'A.5': 13 });
  });

  /**
   * The backward direction: what does the appendix print that this lab does
   * NOT reproduce? The answer should be nothing but the A.2 payload's printed
   * CRYPTO frame (already covered under its own name) and the prose.
   */
  it('leaves no multi-line hex block in the appendix unaccounted for', () => {
    const reproduced = REPRODUCED.map((e) => toHex(e.value));
    const blocks = [...APPENDIX.matchAll(/(?:^ {3,}[0-9a-f ]{20,}\n){1,}/gm)].map((m) =>
      m[0].replace(/[^0-9a-f]/g, ''),
    );
    expect(blocks.length, 'found no hex blocks at all — the parser is broken').toBeGreaterThan(5);
    const unaccounted = blocks.filter(
      (block) => !reproduced.some((value) => value === block || value.includes(block) || block.includes(value)),
    );
    expect(unaccounted).toEqual([]);
  });
});
