import { toHex } from './bytes';
import { hkdfExpandLabel, hkdfExtract, hkdfLabel } from './hkdf';

/**
 * RFC 9001 section 5.2 — Initial secrets.
 *
 * The whole point of this module, and of the lab's first exhibit, is that
 * NOTHING SECRET GOES IN. The salt is printed in the RFC; the connection ID is
 * on the wire in the clear, in the very packet these keys will open. So any
 * observer can run exactly this function.
 */

/**
 * A QUIC version's key-derivation parameters.
 *
 * [extension] point — RFC 9369 (QUIC version 2) keeps this construction and
 * changes only the salt and the four label strings. Giving the version a
 * record rather than hard-coding v1's constants is the seam where it would
 * attach. It is NOT built here; see the README's non-goals.
 */
export interface QuicVersion {
  readonly name: string;
  readonly number: number;
  readonly initialSalt: Uint8Array;
  readonly labels: {
    readonly clientInitial: string;
    readonly serverInitial: string;
    readonly key: string;
    readonly iv: string;
    readonly headerProtection: string;
  };
}

/**
 * QUIC version 1. The salt is `initial_salt` from RFC 9001 section 5.2; it is
 * parsed out of the checked-in RFC text rather than typed, so that no value in
 * this lab can drift from the document it claims to implement.
 */
export function quicV1(initialSalt: Uint8Array): QuicVersion {
  return {
    name: 'QUIC v1',
    number: 0x00000001,
    initialSalt,
    labels: {
      clientInitial: 'client in',
      serverInitial: 'server in',
      key: 'quic key',
      iv: 'quic iv',
      headerProtection: 'quic hp',
    },
  };
}

/** One direction's packet-protection material. */
export interface DirectionKeys {
  readonly secret: Uint8Array;
  readonly key: Uint8Array;
  readonly iv: Uint8Array;
  readonly hp: Uint8Array;
}

export interface InitialKeys {
  readonly connectionId: Uint8Array;
  readonly initialSecret: Uint8Array;
  readonly client: DirectionKeys;
  readonly server: DirectionKeys;
}

/**
 * One derivation step, kept as data so the UI can show the label bytes that
 * actually went into HKDF rather than a prose description of them.
 */
export interface DerivationStep {
  readonly label: string;
  readonly outputLength: number;
  readonly info: Uint8Array;
  readonly output: Uint8Array;
}

export interface InitialKeysTrace extends InitialKeys {
  readonly salt: Uint8Array;
  readonly steps: readonly DerivationStep[];
}

const KEY_LENGTH = 16;
const IV_LENGTH = 12;
const HP_LENGTH = 16;
const SECRET_LENGTH = 32;

async function directionKeys(
  version: QuicVersion,
  initialSecret: Uint8Array,
  label: string,
  steps: DerivationStep[],
): Promise<DirectionKeys> {
  const record = async (
    secret: Uint8Array,
    stepLabel: string,
    length: number,
  ): Promise<Uint8Array> => {
    const output = await hkdfExpandLabel(secret, stepLabel, length);
    steps.push({ label: stepLabel, outputLength: length, info: hkdfLabel(length, stepLabel), output });
    return output;
  };

  const secret = await record(initialSecret, label, SECRET_LENGTH);
  return {
    secret,
    key: await record(secret, version.labels.key, KEY_LENGTH),
    iv: await record(secret, version.labels.iv, IV_LENGTH),
    hp: await record(secret, version.labels.headerProtection, HP_LENGTH),
  };
}

/**
 * Derive both directions' Initial keys from the salt and the client's
 * Destination Connection ID, recording every HKDF step on the way.
 *
 * RFC 9000 section 17.2 caps a connection ID at 20 bytes; a longer one is a
 * malformed packet, and this refuses rather than deriving keys nobody could
 * have used. A zero-length connection ID is legal on the wire in general, but
 * not as the client's FIRST Destination Connection ID: RFC 9000 section 7.2
 * requires at least 8 bytes there, and keys derived from nothing would be the
 * same for every connection.
 */
export async function deriveInitialKeys(
  connectionId: Uint8Array,
  version: QuicVersion,
): Promise<InitialKeysTrace> {
  if (connectionId.length > 20) {
    throw new Error(
      `Destination Connection ID is ${connectionId.length} bytes; RFC 9000 section 17.2 allows at most 20.`,
    );
  }
  if (connectionId.length < 8) {
    throw new Error(
      `Destination Connection ID is ${connectionId.length} bytes; RFC 9000 section 7.2 requires a client's first Initial to use at least 8.`,
    );
  }
  const steps: DerivationStep[] = [];
  const initialSecret = await hkdfExtract(version.initialSalt, connectionId);
  const client = await directionKeys(version, initialSecret, version.labels.clientInitial, steps);
  const server = await directionKeys(version, initialSecret, version.labels.serverInitial, steps);
  return {
    connectionId,
    salt: version.initialSalt,
    initialSecret,
    client,
    server,
    steps,
  };
}

/** A short identity for a key set, used to show two derivations differ. */
export function keySetFingerprint(keys: InitialKeys): string {
  return toHex(keys.initialSecret).slice(0, 8);
}
