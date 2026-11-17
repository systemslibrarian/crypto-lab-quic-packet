import { el } from './dom';

/**
 * Rendered verdicts and measurements, each carrying a stable marker id.
 *
 * `data-verdict` marks a judgement the page has reached; `data-claim` marks a
 * measurement it is showing. Those markers are what §4.1c's mutation ledger
 * names, and `e2e/verdict-coverage.spec.ts` fails the run if the page renders
 * one that no recorded mutation covers.
 *
 * VISUAL SEMANTICS. The tone tracks SYSTEM INTEGRITY rather than the return
 * value, which is why `alarm` exists: exhibit 4 succeeds at everything it
 * attempts and that is the alarming part. Every verdict carries words, a
 * monospace icon and a colour — never colour alone (WCAG 1.4.1), and the
 * wording stands on its own in grayscale.
 */

export type VerdictTone = 'pass' | 'fail' | 'alarm' | 'refused';

const ICONS: Record<VerdictTone, string> = {
  pass: '[OK]',
  fail: '[NO]',
  alarm: '[!!]',
  refused: '[--]',
};

export function verdict(options: {
  id: string;
  tone: VerdictTone;
  headline: string;
  body?: string | Node;
}): HTMLElement {
  const children: Array<Node | string> = [
    el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: ICONS[options.tone] }),
    el('div', {}, [
      el('span', { text: options.headline }),
      ...(options.body === undefined
        ? []
        : [
            typeof options.body === 'string'
              ? el('p', { class: 'verdict-body', text: options.body })
              : el('p', { class: 'verdict-body' }, [options.body]),
          ]),
    ]),
  ];
  return el(
    'div',
    {
      class: `verdict verdict-${options.tone}`,
      'data-verdict': options.id,
      'data-tone': options.tone,
    },
    children,
  );
}

/**
 * The stale-evidence marker.
 *
 * When an input changes, the verdict it produced is REMOVED and this takes its
 * place. A page that leaves an old verdict on screen beside a new input is
 * telling the reader something it has not checked.
 */
export function retired(id: string, what: string): HTMLElement {
  return el('div', { class: 'evidence-retired', 'data-verdict': id, 'data-tone': 'retired' }, [
    el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: '[..]' }),
    el('span', { text: what }),
  ]);
}

/** A measurement the page is showing, marked so a test can find it. */
export function claim(id: string, text: string, className = 'compare-value'): HTMLElement {
  return el('span', { class: className, 'data-claim': id, text });
}
