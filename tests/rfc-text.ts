import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { fromHex } from '../src/quic/bytes';

/**
 * Readers for the RFC texts checked in under tests/rfc/.
 *
 * These files are the lab's source of truth for every expected value, and
 * every suite here reads them rather than carrying a transcription. Each one
 * was fetched from rfc-editor.org on 2026-11-17 and its SHA-256 recorded in
 * DIGESTS below; `rfc-digests.test.ts` fails if one changes, so a silent edit
 * cannot turn a test green.
 */

export const DIGESTS: Record<string, string> = {
  'rfc5869.txt': '7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c',
  'rfc8439.txt': '25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c',
  'rfc9000.txt': 'f88aae47f8b18e102024916e975e919201d8dde689cba79b01079eaedd402e22',
  'rfc9001.txt': '3bbaecdf5afd278052a2c48348ce118c4ff8d0cf6b9915549858171b3f98a591',
};

export function rfcPath(name: string): string {
  return fileURLToPath(new URL(`./rfc/${name}`, import.meta.url));
}

export function rfcBytes(name: string): Buffer {
  return readFileSync(rfcPath(name));
}

export function rfcText(name: string): string {
  return rfcBytes(name).toString('utf8');
}

export function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * A section body, from a heading at column 0 up to the next heading at column
 * 0, INCLUDING the newline that ends the last line.
 *
 * Anchoring at column 0 is what keeps the table of contents from shadowing the
 * body: the TOC lists `A.2.  Client Initial` too, indented, and a plain
 * `indexOf` finds that one first — which is how the first version of
 * `src/fixtures/rfc9001.ts` ended up slicing a few lines of the TOC and
 * parsing nothing out of them.
 */
export function section(text: string, heading: string, nextHeading: string): string {
  const start = text.indexOf(`\n${heading}`);
  const end = text.indexOf(`\n${nextHeading}`);
  if (start < 0) throw new Error(`heading not found at column 0: ${heading}`);
  if (end < 0 || end <= start) {
    throw new Error(`heading ${nextHeading} not found after ${heading}`);
  }
  return text.slice(start + 1, end + 1);
}

/**
 * An RFC 8439 hexdump block: a label line ending in `:`, then rows of
 *
 *     000  4c 61 64 69 65 73 20 61 ...  Ladies and ...
 *
 * The trailing ASCII gutter is discarded by taking only the byte pairs that
 * follow the offset. Rows must run consecutively from offset 0 in steps of 16,
 * which is what stops this quietly joining two different dumps.
 */
export function hexDump(block: string, label: string): Uint8Array {
  const lines = block.split('\n');
  // The colon is optional because RFC 8439 is not consistent about it:
  // Appendix A.5 heads its key with `The ChaCha20 Key` and no colon at all,
  // and heads its plaintext `Plaintext::` with two.
  const start = lines.findIndex((line) => {
    const trimmed = line.trim();
    return trimmed === label || trimmed === `${label}:`;
  });
  if (start < 0) throw new Error(`hexdump label not found: ${label}`);

  const bytes: number[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    const row = /^\s+(\d{3})\s{2}((?:[0-9a-f]{2} ?)+)(?:\s{2,}.*)?$/.exec(lines[i]);
    if (!row) {
      if (lines[i].trim() === '') {
        if (bytes.length > 0) break;
        continue;
      }
      // Page furniture inside a long dump: a footer, a header, a blank run.
      if (/\[Page \d+\]|^RFC 8439|^Nir & Langley/.test(lines[i])) continue;
      break;
    }
    if (Number(row[1]) !== bytes.length) {
      throw new Error(
        `hexdump ${label}: row offset ${row[1]} does not continue from byte ${bytes.length}`,
      );
    }
    for (const pair of row[2].trim().split(/\s+/)) bytes.push(Number.parseInt(pair, 16));
  }
  if (bytes.length === 0) throw new Error(`hexdump ${label}: no rows`);
  return new Uint8Array(bytes);
}

/**
 * A colon-separated inline value, as RFC 8439 writes its keys and nonces:
 *
 *     o  Key = 00:01:02:03:...:1d:1e:1f.  The key is a sequence of
 *        octets with no particular structure before we copy it ...
 *     o  Nonce = (00:00:00:09:00:00:00:4a:00:00:00:00)
 *
 * The value may wrap mid-run, may be parenthesised, and — as the first bullet
 * shows — may be followed on the SAME line by prose. A first attempt here
 * stripped every non-hex character from the span and read 45 bytes for that
 * 32-byte key, because `sequence`, `before` and `state` are all spelled with
 * hex digits. So the run is matched STRUCTURALLY instead: pairs separated by
 * colons, ending the moment that shape stops.
 */
export function colonHex(block: string, label: string): Uint8Array {
  // RFC 8439 introduces these runs two ways — `Key = 00:01:…` in section 2.3.2
  // and `Key Material: 85:d6:…` in 2.5.2 — so both separators are accepted.
  const marker = [`${label} = `, `${label}: `].find((candidate) => block.includes(candidate));
  if (marker === undefined) throw new Error(`inline value not found: ${label}`);
  const at = block.indexOf(marker);
  const span = block.slice(at + marker.length).replace(/\s+/g, '').replace(/^\(/, '');
  const run = /^(?:[0-9a-f]{2}:)*[0-9a-f]{2}/.exec(span);
  if (!run) throw new Error(`inline value ${label} does not start with a colon-separated byte run`);
  return fromHex(run[0].replace(/:/g, ''));
}

/** RFC 5869 Appendix A prints `IKM  = 0x0b0b…` with wrapped continuations. */
export function rfc5869Value(block: string, label: string): Uint8Array {
  const lines = block.split('\n');
  const index = lines.findIndex((line) => line.trim().startsWith(`${label} `) && line.includes('='));
  if (index < 0) throw new Error(`RFC 5869 value not found: ${label}`);
  const first = lines[index].slice(lines[index].indexOf('=') + 1).trim();
  if (/^\(0 octets\)/.test(first)) return new Uint8Array(0);
  const pieces = [first];
  for (let i = index + 1; i < lines.length; i++) {
    const candidate = lines[i].trim();
    if (!/^[0-9a-f]+( \(\d+ octets\))?$/.test(candidate)) break;
    pieces.push(candidate);
  }
  const hex = pieces
    .join('')
    .replace(/\(\d+ octets\)/g, '')
    .replace(/^0x/, '')
    .replace(/[^0-9a-f]/g, '');
  return fromHex(hex);
}

/**
 * A `Label:` line followed by colon-separated hex rows, which is how RFC 8439
 * section 2.4.2 prints its keystream (while the plaintext and ciphertext two
 * paragraphs away are hexdumps). Two formats for three values in one section
 * is why both readers exist.
 */
export function colonBlock(block: string, label: string): Uint8Array {
  const lines = block.split('\n');
  const start = lines.findIndex((line) => line.trim() === `${label}:`);
  if (start < 0) throw new Error(`colon block label not found: ${label}:`);
  const pieces: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    const candidate = lines[i].trim();
    if (candidate === '') {
      if (pieces.length > 0) break;
      continue;
    }
    if (!/^(?:[0-9a-f]{2}:)*[0-9a-f]{2}:?$/.test(candidate)) break;
    pieces.push(candidate);
  }
  if (pieces.length === 0) throw new Error(`colon block ${label}: no rows`);
  return fromHex(pieces.join('').replace(/:/g, ''));
}

/**
 * A `Label:` line followed by rows of space-separated hex with NO offset
 * column, which is the third format RFC 8439 uses — Appendix A.3's vectors 5
 * to 11 print `R:` / `S:` / `data:` / `tag:` this way, in upper case, while
 * vectors 1 to 4 a few lines above use offset hexdumps. Three formats in one
 * appendix is why this file has three readers rather than one clever one.
 */
export function spacedHex(block: string, label: string): Uint8Array {
  const lines = block.split('\n');
  const start = lines.findIndex((line) => line.trim() === `${label}:`);
  if (start < 0) throw new Error(`spaced hex label not found: ${label}:`);
  const pieces: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    const candidate = lines[i].trim();
    if (candidate === '') {
      if (pieces.length > 0) break;
      continue;
    }
    if (!/^(?:[0-9a-fA-F]{2} )*[0-9a-fA-F]{2}$/.test(candidate)) break;
    pieces.push(candidate.replace(/ /g, ''));
  }
  if (pieces.length === 0) throw new Error(`spaced hex ${label}: no rows`);
  return fromHex(pieces.join('').toLowerCase());
}

/** The NIST CAVP response-file excerpt checked in under tests/nist/. */
export function nistText(name: string): string {
  return readFileSync(fileURLToPath(new URL(`./nist/${name}`, import.meta.url)), 'utf8');
}

export interface CavpCase {
  readonly group: Readonly<Record<string, number>>;
  readonly count: number;
  readonly fields: Readonly<Record<string, Uint8Array>>;
}

/**
 * Parse a CAVP `.rsp` excerpt: `[Name = value]` group headers, then
 * `Count = n` records of `Field = hex` lines. An empty value is a zero-length
 * field, which is how CAVP writes `PT = ` for a zero-length plaintext.
 */
export function cavpCases(text: string): CavpCase[] {
  const cases: CavpCase[] = [];
  let group: Record<string, number> = {};
  let current: { count: number; fields: Record<string, Uint8Array> } | null = null;

  const flush = (): void => {
    if (current) cases.push({ group: { ...group }, count: current.count, fields: current.fields });
    current = null;
  };

  for (const line of text.split('\n')) {
    const header = /^\[(\w+) = (\d+)\]$/.exec(line.trim());
    if (header) {
      flush();
      group[header[1]] = Number(header[2]);
      continue;
    }
    const count = /^Count = (\d+)$/.exec(line.trim());
    if (count) {
      flush();
      current = { count: Number(count[1]), fields: {} };
      continue;
    }
    const field = /^(\w+) = ([0-9a-fA-F]*)$/.exec(line.trim());
    if (field && current) {
      current.fields[field[1]] = fromHex(field[2]);
    }
  }
  flush();
  return cases;
}
