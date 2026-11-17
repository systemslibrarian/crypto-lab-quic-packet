import { AES_128_GCM } from './aead';
import { toHex } from './bytes';
import { cryptoStreamFromPayload, findServerName } from './clienthello';
import { type InitialKeysTrace, deriveInitialKeys, quicV1 } from './initial';
import { INITIAL_SALT } from '../fixtures/rfc9001';
import { type OpenTrace, openPacket } from './protect';
import { PacketFormatError, assertKnownVersion, destinationConnectionId } from './packet';

/**
 * An on-path observer with no key material at all.
 *
 * THE SIGNATURE IS THE INVARIANT. `observe` takes the packet bytes and nothing
 * else — no keys, no connection ID, no hint from the caller. Everything it
 * needs it either reads out of the packet (the Destination Connection ID) or
 * reads out of RFC 9001 (the version-1 initial salt, which is printed in
 * section 5.2 and is therefore not a secret in any sense). That is the whole
 * point of exhibit 4: this is not a weakness someone missed, it is what the
 * specification says Initial packets are.
 *
 * RFC 9001 section 7 puts it plainly: "Initial packets are not protected with
 * a secret key, so they are subject to potential tampering by an attacker.
 * QUIC provides protection against attackers that cannot read packets but does
 * not attempt to provide additional protection against attacks where the
 * attacker can observe and inject packets."
 */

export interface ObserverResult {
  /** The connection ID the observer read out of the packet, never given to it. */
  readonly connectionId: Uint8Array | null;
  readonly keys: InitialKeysTrace | null;
  readonly open: OpenTrace | null;
  /** The CRYPTO frames the payload turned out to contain. */
  readonly frames: readonly string[];
  /** Non-null only when the AEAD tag verified AND the parse completed. */
  readonly serverName: string | null;
  /** How far the walk got, step by step, in both outcomes. */
  readonly path: readonly string[];
  readonly refusal: string | null;
}

/**
 * Derive, unmask, open, and parse far enough to read the server name.
 *
 * Every stage can refuse, and a refusal carries the reason rather than a
 * silent null. `serverName` is only ever set when `open.opened` is true, which
 * is invariant 3 expressed where it cannot be forgotten: there is no code path
 * that reads a name out of unverified bytes.
 */
export async function observe(packet: Uint8Array): Promise<ObserverResult> {
  const empty: ObserverResult = {
    connectionId: null,
    keys: null,
    open: null,
    frames: [],
    serverName: null,
    path: [],
    refusal: null,
  };

  // The version comes FIRST. An unknown version must be refused before any
  // key is derived (and the brief's edge-case list says so): deriving
  // version-1 keys for a version-2 packet would put a key set on screen for a
  // packet those keys cannot read.
  let connectionId: Uint8Array;
  try {
    assertKnownVersion(packet);
    connectionId = destinationConnectionId(packet);
  } catch (error) {
    return {
      ...empty,
      refusal:
        error instanceof PacketFormatError
          ? error.message
          : `the packet's Destination Connection ID could not be read: ${String(error)}`,
    };
  }

  const path = [`read the Destination Connection ID off the wire: ${toHex(connectionId)}`];

  let keys: InitialKeysTrace;
  try {
    keys = await deriveInitialKeys(connectionId, quicV1(INITIAL_SALT));
  } catch (error) {
    return {
      ...empty,
      connectionId,
      path,
      refusal: error instanceof Error ? error.message : String(error),
    };
  }
  path.push(
    `derived the client Initial keys from the published salt and that ID alone: key ${toHex(keys.client.key)}`,
  );

  let open: OpenTrace;
  try {
    open = await openPacket({
      packet,
      keys: keys.client,
      aead: AES_128_GCM,
      headerProtection: 'aes',
    });
  } catch (error) {
    return {
      ...empty,
      connectionId,
      keys,
      path,
      refusal:
        error instanceof PacketFormatError
          ? error.message
          : `the packet could not be unprotected: ${String(error)}`,
    };
  }
  path.push(
    `removed header protection with mask ${toHex(open.mask)}: packet number ${open.packetNumber}`,
  );

  if (!open.opened || open.plaintext === null) {
    return {
      ...empty,
      connectionId,
      keys,
      open,
      path,
      refusal: open.reason,
    };
  }
  path.push(`the authentication tag verified: ${open.plaintext.length} payload bytes recovered`);

  const stream = cryptoStreamFromPayload(open.plaintext);
  const frames = stream.frames;
  path.push(`frames: ${frames.join(', ')}`);

  if (stream.bytes.length === 0) {
    return {
      ...empty,
      connectionId,
      keys,
      open,
      frames,
      path,
      refusal: stream.stoppedAt ?? 'the payload carries no CRYPTO frame, so there is no ClientHello to read',
    };
  }

  const sni = findServerName(stream.bytes);
  if (!sni.found) {
    return {
      connectionId,
      keys,
      open,
      frames,
      serverName: null,
      path: [...path, ...sni.path],
      refusal: `server name not found: ${sni.reason}`,
    };
  }

  return {
    connectionId,
    keys,
    open,
    frames,
    serverName: sni.serverName,
    path: [...path, ...sni.path, `host_name: ${sni.serverName}`],
    refusal: null,
  };
}
