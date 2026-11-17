import { toHex } from '../quic/bytes';
import { el, scroller } from './dom';

/**
 * Packets as annotated hex.
 *
 * The rules this follows, from §3's visual semantics:
 *
 *  - EVERY FIELD IS LABELLED IN TEXT. The colours are a second channel on top
 *    of a legend that names each field in words and gives its byte range, so
 *    the view is readable in grayscale and under deuteranopia.
 *  - THE SAMPLE WINDOW IS MARKED BY PRINTED BRACKETS as well as a tint. It is
 *    the one span whose exact boundaries are the teaching point, and a tint
 *    alone would make "where does it start" a question about colour
 *    perception.
 *  - LONG VALUES SCROLL INSIDE THEIR OWN REGION, which is keyboard-reachable
 *    and named. A 1200-byte packet is 2400 hex characters; wrapping it makes
 *    byte offsets unfindable.
 */

export interface Span {
  /** Inclusive byte offset where this span starts. */
  readonly start: number;
  /** Exclusive byte offset where it ends. */
  readonly end: number;
  /** The CSS class carrying this field's tint. */
  readonly className: string;
  /** The field's name, in words, for the legend. */
  readonly label: string;
  /** Printed brackets around the span, for a boundary that must be exact. */
  readonly bracket?: boolean;
}

export interface HexViewOptions {
  readonly title: string;
  readonly bytes: Uint8Array;
  readonly spans?: readonly Span[];
  /** How many bytes to show before eliding the middle. */
  readonly limit?: number;
  readonly meta?: string;
  readonly ariaLabel?: string;
}

const BYTES_PER_ROW = 16;

/**
 * Which span covers a byte. The LAST matching span wins, so a sample window
 * declared after the field spans paints over them — which is what the eye
 * needs, since the sample deliberately straddles field boundaries.
 */
function spanAt(spans: readonly Span[], offset: number): Span | undefined {
  let found: Span | undefined;
  for (const span of spans) {
    if (offset >= span.start && offset < span.end) found = span;
  }
  return found;
}

export function hexView(options: HexViewOptions): HTMLElement {
  const spans = options.spans ?? [];
  const limit = options.limit ?? 256;
  const total = options.bytes.length;

  // A long packet is shown head and tail with a counted elision in between.
  // Eliding silently would be the kind of small dishonesty that makes a
  // reader distrust everything else on the page.
  const elide = total > limit;
  const headBytes = elide ? Math.ceil(limit / 2) : total;
  const tailStart = elide ? total - Math.floor(limit / 2) : total;

  const rows: Array<Node | string> = [];

  const emitRange = (from: number, to: number): void => {
    for (let rowStart = from - (from % BYTES_PER_ROW); rowStart < to; rowStart += BYTES_PER_ROW) {
      const line: Array<Node | string> = [];
      line.push(
        el('span', {
          class: 'f-length',
          text: `${rowStart.toString(10).padStart(5, ' ')}  `,
        }),
      );
      for (let i = rowStart; i < rowStart + BYTES_PER_ROW; i++) {
        if (i < from || i >= to) {
          line.push('   ');
          continue;
        }
        const span = spanAt(spans, i);
        const openBracket = span?.bracket === true && i === span.start;
        const closeBracket = span?.bracket === true && i === span.end - 1;
        const text = toHex(options.bytes.subarray(i, i + 1));
        const piece = span
          ? el('span', { class: span.className, text })
          : document.createTextNode(text);
        if (openBracket) line.push(el('span', { class: 'f-bracket', text: '[' }));
        line.push(piece);
        if (closeBracket) line.push(el('span', { class: 'f-bracket', text: ']' }));
        else line.push(' ');
      }
      rows.push(el('div', {}, line), '\n');
    }
  };

  emitRange(0, headBytes);
  if (elide) {
    rows.push(
      el('div', {
        class: 'f-length',
        text: `       … ${total - headBytes - (total - tailStart)} bytes not shown …`,
      }),
      '\n',
    );
    emitRange(tailStart, total);
  }

  const legendEntries = spans.map((span) =>
    el('li', {}, [
      el('span', { class: `legend-key ${span.className}`, text: span.bracket ? '[ … ]' : '■' }),
      el('span', {
        text: `${span.label} — bytes ${span.start}${span.end - span.start > 1 ? `–${span.end - 1}` : ''}`,
      }),
    ]),
  );

  return el('div', { class: 'hexview' }, [
    el('div', { class: 'hexview-title' }, [
      el('h4', { text: options.title }),
      el('span', {
        class: 'hexview-meta',
        text: options.meta ?? `${total} byte${total === 1 ? '' : 's'}`,
      }),
    ]),
    scroller(options.ariaLabel ?? `${options.title}, ${total} bytes of hexadecimal`, [
      el('div', { class: 'hexview-rows' }, rows),
    ]),
    ...(legendEntries.length > 0
      ? [el('ul', { class: 'hexview-legend', role: 'list' }, legendEntries.map((e) => {
          e.setAttribute('role', 'listitem');
          return e;
        }))]
      : []),
  ]);
}

/**
 * The field spans of an Initial packet's long header, computed from the packet
 * rather than hard-coded, so an edited connection ID moves them.
 */
export function longHeaderSpans(options: {
  dcidLength: number;
  scidLength: number;
  tokenLengthBytes: number;
  lengthFieldBytes: number;
  packetNumberOffset: number;
  packetNumberLength: number;
}): Span[] {
  const dcidStart = 6;
  const scidLengthAt = dcidStart + options.dcidLength;
  const scidStart = scidLengthAt + 1;
  const tokenLengthAt = scidStart + options.scidLength;
  const lengthFieldAt = tokenLengthAt + options.tokenLengthBytes;
  return [
    { start: 0, end: 1, className: 'f-first', label: 'first byte (form, type, reserved, packet-number length)' },
    { start: 1, end: 5, className: 'f-version', label: 'Version' },
    { start: 5, end: 6, className: 'f-length', label: 'Destination Connection ID Length' },
    { start: dcidStart, end: dcidStart + options.dcidLength, className: 'f-dcid', label: 'Destination Connection ID' },
    { start: scidLengthAt, end: scidLengthAt + 1, className: 'f-length', label: 'Source Connection ID Length' },
    ...(options.scidLength > 0
      ? [{ start: scidStart, end: scidStart + options.scidLength, className: 'f-scid', label: 'Source Connection ID' }]
      : []),
    { start: tokenLengthAt, end: tokenLengthAt + options.tokenLengthBytes, className: 'f-length', label: 'Token Length' },
    { start: lengthFieldAt, end: lengthFieldAt + options.lengthFieldBytes, className: 'f-length', label: 'Length' },
    {
      start: options.packetNumberOffset,
      end: options.packetNumberOffset + options.packetNumberLength,
      className: 'f-pn',
      label: 'Packet Number',
    },
  ];
}

/** The sample window, drawn last so it paints over the field tints. */
export function sampleSpan(start: number, length = 16): Span {
  return {
    start,
    end: start + length,
    className: 'f-sample',
    label: 'header-protection sample (16 bytes, starting 4 bytes after the packet number begins)',
    bracket: true,
  };
}

/** A span marking the bytes that differ between two equal-length values. */
export function differenceSpans(a: Uint8Array, b: Uint8Array, label: string): Span[] {
  const spans: Span[] = [];
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    if (a[i] !== b[i]) spans.push({ start: i, end: i + 1, className: 'f-changed', label });
  }
  return spans;
}
