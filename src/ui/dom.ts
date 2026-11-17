/**
 * Small DOM helpers. No framework: the page is six panels of structured text,
 * and the honesty of the lab is easier to read when the rendering is literal.
 */

type Attributes = Record<string, string | number | boolean | undefined>;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attributes: Attributes = {},
  children: Array<Node | string> = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (value === undefined || value === false) continue;
    if (name === 'class') node.className = String(value);
    else if (name === 'text') node.textContent = String(value);
    else if (value === true) node.setAttribute(name, '');
    else node.setAttribute(name, String(value));
  }
  for (const child of children) {
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function card(heading: string, children: Array<Node | string>): HTMLElement {
  return el('section', { class: 'card' }, [el('h3', { text: heading }), ...children]);
}

export function note(text: string): HTMLElement {
  return el('p', { class: 'note', text });
}

/**
 * A labelled, keyboard-reachable scroll region.
 *
 * WCAG 2.1.1: a scroller holding no focusable content needs `tabindex="0"` so
 * arrow keys can reach it, plus a role and an accessible name. Every long hex
 * value on this page goes through here rather than relying on wrapping,
 * because a 1200-byte packet does not wrap into anything readable.
 */
export function scroller(label: string, children: Array<Node | string>): HTMLElement {
  return el(
    'div',
    { class: 'hexview-scroll', role: 'region', 'aria-label': label, tabindex: 0 },
    children,
  );
}

/** A labelled text input with its own `<label>`, never a placeholder. */
export function textField(options: {
  id: string;
  label: string;
  value: string;
  size?: number;
  describedBy?: string;
}): { field: HTMLElement; input: HTMLInputElement } {
  const input = el('input', {
    id: options.id,
    type: 'text',
    value: options.value,
    size: options.size ?? 24,
    spellcheck: false,
    autocomplete: 'off',
    'aria-describedby': options.describedBy,
  });
  const field = el('div', { class: 'field' }, [
    el('label', { for: options.id, text: options.label }),
    input,
  ]);
  return { field, input };
}

export function button(options: {
  id?: string;
  label: string;
  primary?: boolean;
  onClick: () => void;
}): HTMLButtonElement {
  const node = el('button', {
    id: options.id,
    type: 'button',
    class: options.primary ? 'btn btn-primary' : 'btn',
    text: options.label,
  });
  node.addEventListener('click', options.onClick);
  return node;
}

/**
 * A live region for asynchronously-rendered output.
 *
 * `role="status"` with `aria-live="polite"` so a screen reader is told when a
 * verdict appears — every computation here is async, because WebCrypto is.
 */
export function liveRegion(id: string, label: string): HTMLElement {
  return el('div', { id, role: 'status', 'aria-live': 'polite', 'aria-label': label });
}

export function disclosure(summary: string, children: Array<Node | string>): HTMLElement {
  return el('details', {}, [el('summary', { text: summary }), ...children]);
}

/** A two-column labelled value list. */
export function compare(rows: Array<{ label: string; value: string; claim?: string }>): HTMLElement {
  return el(
    'div',
    { class: 'compare' },
    rows.map((row) =>
      el('div', { class: 'compare-row' }, [
        el('span', { class: 'compare-label', text: row.label }),
        el('span', {
          class: 'compare-value',
          text: row.value,
          'data-claim': row.claim,
        }),
      ]),
    ),
  );
}
