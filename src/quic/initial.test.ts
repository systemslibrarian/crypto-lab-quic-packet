import { describe, expect, it } from 'vitest';

import {
  CONNECTION_ID,
  EXPECTED_CLIENT_KEYS,
  EXPECTED_INITIAL_SECRET,
  EXPECTED_SERVER_KEYS,
  INITIAL_SALT,
} from '../fixtures/rfc9001';
import { toHex } from './bytes';
import { deriveInitialKeys, keySetFingerprint, quicV1 } from './initial';

/**
 * RFC 9001 Appendix A.1 — the nine key values, all nine of them.
 *
 * Every expected value here comes out of the RFC text (see
 * src/fixtures/rfc9001.ts); none is typed into this file.
 */

const version = quicV1(INITIAL_SALT);

describe('Initial key derivation (RFC 9001 section 5.2, Appendix A.1)', () => {
  it('derives the initial_secret A.1 prints', async () => {
    const keys = await deriveInitialKeys(CONNECTION_ID, version);
    expect(toHex(keys.initialSecret)).toBe(toHex(EXPECTED_INITIAL_SECRET));
  });

  for (const [who, expected] of [
    ['client', EXPECTED_CLIENT_KEYS],
    ['server', EXPECTED_SERVER_KEYS],
  ] as const) {
    describe(`the ${who} direction`, () => {
      for (const field of ['secret', 'key', 'iv', 'hp'] as const) {
        it(`derives the ${field} A.1 prints`, async () => {
          const keys = await deriveInitialKeys(CONNECTION_ID, version);
          expect(toHex(keys[who][field])).toBe(toHex(expected[field]));
        });
      }
    });
  }

  it('produces values of the lengths RFC 9001 section 5.1 requires', async () => {
    const keys = await deriveInitialKeys(CONNECTION_ID, version);
    for (const direction of [keys.client, keys.server]) {
      expect(direction.secret.length).toBe(32);
      expect(direction.key.length).toBe(16);
      expect(direction.iv.length).toBe(12);
      expect(direction.hp.length).toBe(16);
    }
  });

  it('records all eight HKDF-Expand-Label steps with the info bytes used', async () => {
    const keys = await deriveInitialKeys(CONNECTION_ID, version);
    expect(keys.steps.map((s) => s.label)).toEqual([
      'client in',
      'quic key',
      'quic iv',
      'quic hp',
      'server in',
      'quic key',
      'quic iv',
      'quic hp',
    ]);
    for (const step of keys.steps) {
      expect(step.output.length).toBe(step.outputLength);
      // The two-byte big-endian length field opens every info string.
      expect(step.info[0] * 256 + step.info[1]).toBe(step.outputLength);
    }
  });

  it('takes nothing secret: the salt is published and the ID is on the wire', async () => {
    // Not a tautology — it is the claim exhibit 1 makes, checked against the
    // signature. `deriveInitialKeys` has exactly two inputs, and this asserts
    // they are the two public ones.
    const keys = await deriveInitialKeys(CONNECTION_ID, version);
    expect(toHex(keys.salt)).toBe(toHex(INITIAL_SALT));
    expect(toHex(keys.connectionId)).toBe(toHex(CONNECTION_ID));
  });

  it('gives a different connection ID different keys', async () => {
    const other = CONNECTION_ID.slice();
    other[0] ^= 0x01;
    const mine = await deriveInitialKeys(CONNECTION_ID, version);
    const theirs = await deriveInitialKeys(other, version);
    expect(keySetFingerprint(theirs)).not.toBe(keySetFingerprint(mine));
    expect(toHex(theirs.client.key)).not.toBe(toHex(mine.client.key));
  });

  it('gives the client and the server different keys from one secret', async () => {
    const keys = await deriveInitialKeys(CONNECTION_ID, version);
    expect(toHex(keys.client.key)).not.toBe(toHex(keys.server.key));
    expect(toHex(keys.client.hp)).not.toBe(toHex(keys.server.hp));
  });

  it('refuses a connection ID longer than RFC 9000 section 17.2 allows', async () => {
    await expect(deriveInitialKeys(new Uint8Array(21), version)).rejects.toThrow(/at most 20/);
  });

  it('refuses a connection ID shorter than a client\'s first Initial may use', async () => {
    await expect(deriveInitialKeys(new Uint8Array(7), version)).rejects.toThrow(/at least 8/);
    await expect(deriveInitialKeys(new Uint8Array(0), version)).rejects.toThrow(/at least 8/);
  });

  it('shapes a Version record so another version could be added', () => {
    // [extension] point. QUIC v2 (RFC 9369) keeps this construction and
    // changes the salt and the four labels; nothing here builds it.
    expect(version.number).toBe(0x00000001);
    expect(Object.keys(version.labels).sort()).toEqual([
      'clientInitial',
      'headerProtection',
      'iv',
      'key',
      'serverInitial',
    ]);
  });
});
