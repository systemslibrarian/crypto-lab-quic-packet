import './style.css';

import { renderBreakPanel } from './ui/panels/break';
import { renderHidePanel } from './ui/panels/hide';
import { renderKeysPanel } from './ui/panels/keys';
import { renderObserverPanel } from './ui/panels/observer';
import { renderOthersPanel } from './ui/panels/others';
import { renderSealPanel } from './ui/panels/seal';
import { clear, el } from './ui/dom';

/**
 * Entry point and tab controller.
 *
 * Panels render LAZILY, on first activation. Two consequences worth knowing,
 * both of which the accessibility gate relies on:
 *
 *  - an unvisited panel is `hidden` AND EMPTY, so "empty" is this page's tell
 *    that a renderer threw — an empty region is exactly what an axe scan
 *    reports as perfectly accessible;
 *  - the gate must drive the real tab buttons rather than stripping `hidden`,
 *    because a panel that was never clicked is not in the DOM at all.
 *
 * Every renderer here is async because WebCrypto is. A failure is caught and
 * PAINTED into the panel rather than left to the console, so a broken panel is
 * visibly broken instead of silently blank.
 */

type Renderer = (panel: HTMLElement) => void | Promise<void>;

const PANELS: Record<string, Renderer> = {
  keys: renderKeysPanel,
  seal: renderSealPanel,
  hide: renderHidePanel,
  observer: renderObserverPanel,
  others: renderOthersPanel,
  break: renderBreakPanel,
};

const rendered = new Set<string>();

async function render(name: string): Promise<void> {
  const panel = document.getElementById(`panel-${name}`);
  if (!panel) return;
  if (rendered.has(name)) return;
  rendered.add(name);
  try {
    await PANELS[name](panel);
  } catch (error) {
    rendered.delete(name);
    clear(panel);
    panel.append(
      el('section', { class: 'card' }, [
        el('h3', { text: 'This exhibit failed to render' }),
        el('p', {
          class: 'note',
          text: 'Nothing is being hidden from you: the error is below. Every computation on this page runs in your browser, so a failure here is a failure of this code or of your browser’s WebCrypto, not of a server.',
        }),
        el('pre', { class: 'hexview-rows', text: error instanceof Error ? `${error.name}: ${error.message}` : String(error) }),
      ]),
    );
  }
}

function activate(name: string): void {
  for (const tab of document.querySelectorAll<HTMLButtonElement>('.tab-btn')) {
    const isSelected = tab.dataset.panel === name;
    tab.setAttribute('aria-selected', isSelected ? 'true' : 'false');
    tab.tabIndex = isSelected ? 0 : -1;
  }
  for (const panel of document.querySelectorAll<HTMLElement>('.panel')) {
    panel.hidden = panel.id !== `panel-${name}`;
  }
  void render(name);
}

function wireTabs(): void {
  const tabs = [...document.querySelectorAll<HTMLButtonElement>('.tab-btn')];
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => {
      const name = tab.dataset.panel;
      if (name) activate(name);
    });
    // Arrow-key navigation within a tablist, per the ARIA authoring practices.
    tab.addEventListener('keydown', (event) => {
      const step =
        event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : event.key === 'Home' ? -index : event.key === 'End' ? tabs.length - 1 - index : 0;
      if (step === 0) return;
      event.preventDefault();
      const target = tabs[(index + step + tabs.length) % tabs.length];
      const name = target.dataset.panel;
      if (name) {
        activate(name);
        target.focus();
      }
    });
  });
}

wireTabs();
void render('keys');
