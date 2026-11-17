import { webcrypto } from 'node:crypto';

import { expect, test } from '@playwright/test';

import { boot } from './gate';
import { expectClaim, expectVerdict } from './expect-verdict';

/**
 * The claims suite: what this lab's interface SAYS, and whether it is true.
 * §4.1b and §4.1d of audits/_MASTER-TEMPLATE.md.
 *
 * THE RULE THAT MAKES THESE WORTH ANYTHING. A test that re-runs the same
 * expression the source uses will happily agree with a bug. So the key
 * assertions here RE-DERIVE the page's claims by a different route: HKDF is
 * rebuilt from Node's own `webcrypto.subtle` HMAC below, with its own
 * HkdfLabel encoder, and the packet is opened with Node's own AES-GCM. Neither
 * touches a line of `src/`. Where a cross-check is the honest shape instead —
 * two surfaces that must agree — it says so.
 *
 * Copy assertions live HERE and not in `gate.ts`'s `boot()`. On 2026-09-26
 * crypto-lab-mceliece-gate put three of them in `boot()`; one sentence changed
 * and every accessibility test failed at once under the name "Accessibility
 * gate", while the live site served claims `main` had already corrected.
 */

/* ── An independent HKDF, owing nothing to src/ ──────────────────────────── */

const { subtle } = webcrypto;

/**
 * Node's WebCrypto typings want `Uint8Array<ArrayBuffer>` specifically, not
 * the `Uint8Array<ArrayBufferLike>` a bare `Uint8Array` annotation means since
 * TypeScript 5.7. Naming the concrete type once keeps every call below honest
 * rather than casting at each one.
 */
type Bytes = Uint8Array<ArrayBuffer>;

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const unhex = (text: string): Bytes => {
  const buffer = Buffer.from(text, 'hex');
  const out = new Uint8Array(buffer.length) as Bytes;
  out.set(buffer);
  return out;
};
const bytes = (length: number): Bytes => new Uint8Array(length) as Bytes;

async function hmac(key: Bytes, data: Bytes): Promise<Bytes> {
  const imported = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  return new Uint8Array(await subtle.sign('HMAC', imported, data)) as Bytes;
}

/** HKDF-Expand, written out longhand rather than imported. */
async function expand(prk: Bytes, info: Bytes, length: number): Promise<Bytes> {
  const out: number[] = [];
  let previous: Bytes = bytes(0);
  for (let counter = 1; out.length < length; counter++) {
    const input = bytes(previous.length + info.length + 1);
    input.set(previous, 0);
    input.set(info, previous.length);
    input[input.length - 1] = counter;
    previous = await hmac(prk, input);
    out.push(...previous);
  }
  return unhex(Buffer.from(out.slice(0, length)).toString('hex'));
}

/** The TLS 1.3 HkdfLabel, built here from the RFC's field order. */
function label(length: number, text: string): Bytes {
  const full = Buffer.from(`tls13 ${text}`, 'ascii');
  return unhex(
    Buffer.from([length >> 8, length & 0xff, full.length, ...full, 0]).toString('hex'),
  );
}

const SALT = unhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a');

async function clientKeys(
  connectionId: Bytes,
): Promise<{ key: Bytes; iv: Bytes; hp: Bytes }> {
  const initial = await hmac(SALT, connectionId);
  const secret = await expand(initial, label(32, 'client in'), 32);
  return {
    key: await expand(secret, label(16, 'quic key'), 16),
    iv: await expand(secret, label(12, 'quic iv'), 12),
    hp: await expand(secret, label(16, 'quic hp'), 16),
  };
}

/* ── Displayed copy ──────────────────────────────────────────────────────── */

test.describe('displayed claims', () => {
  test('the hero names QUIC Packet and its spec subtitle', async ({ page }) => {
    await boot(page, 'dark');
    await expect(page.locator('h1.cl-hero-title')).toHaveText('QUIC Packet');
    await expect(page.locator('.cl-hero-sub')).toHaveText(
      'Initial keys from public values · AEAD · header protection',
    );
  });

  test('the connection-ID box arrives holding the RFC 9001 Appendix A value', async ({ page }) => {
    await boot(page, 'dark');
    // A claim about which packet this lab is reproducing. `boot()` asserts the
    // SHAPE of this value; the value itself is copy and belongs here.
    await expect(page.locator('#cid-input')).toHaveValue('8394c8f03e515708');
  });

  test('the page says it is not production software and sends nothing', async ({ page }) => {
    await boot(page, 'dark');
    const scope = page.locator('.scope');
    await expect(scope).toContainText('Not production software');
    await expect(scope).toContainText('It sends nothing');
    await expect(scope).toContainText('no network access');
  });

  test('the page names every non-goal the README names', async ({ page }) => {
    await boot(page, 'dark');
    const scope = page.locator('.scope');
    for (const nonGoal of [
      'The TLS handshake itself',
      'Handshake and 1-RTT keys from a real handshake',
      'Key update',
      'QUIC version 2',
      'Packet-number decoding against a receive window',
      'Loss recovery, streams and flow control',
      'No claim about any particular implementation',
    ]) {
      await expect(scope).toContainText(nonGoal);
    }
  });

  test('the scripture footer is present, verbatim, exactly once', async ({ page }) => {
    await boot(page, 'dark');
    const footer = page.locator('.scripture-footer p', {
      hasText: 'So whether you eat or drink',
    });
    await expect(footer).toHaveCount(1);
    await expect(footer).toHaveText(
      'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    );
  });
});

/* ── Independent re-derivations ──────────────────────────────────────────── */

test.describe('the keys on screen are the right keys', () => {
  test('every key on screen re-derives from the connection ID on screen', async ({ page }) => {
    await boot(page, 'dark');
    const connectionId = await page.locator('#cid-input').inputValue();
    const expected = await clientKeys(unhex(connectionId));

    // Re-derived here with this file's own HMAC calls and its own HkdfLabel
    // encoder. A mutation to src/quic/hkdf.ts moves the page and not this.
    await expectClaim(page, test.info(), 'keys-client-key', hex(expected.key));
    await expectClaim(page, test.info(), 'keys-client-iv', hex(expected.iv));
    await expectClaim(page, test.info(), 'keys-client-hp', hex(expected.hp));

    // And the verdict the page draws from those comparisons.
    await expectVerdict(page, test.info(), 'keys-derivation', {
      tone: 'pass',
      text: 'DERIVED - and all nine values match RFC 9001 Appendix A.1',
    });
  });

  test('editing the connection ID moves the keys, and they still re-derive', async ({ page }) => {
    await boot(page, 'dark');
    const before = await page.locator('[data-claim="keys-client-key"]').textContent();

    await page.locator('#cid-input').fill('0badc0ffee1dea00');
    await page.locator('#derive-btn').click();
    await expect(page.locator('[data-verdict="keys-derivation"][data-tone="alarm"]')).toBeVisible();

    const expected = await clientKeys(unhex('0badc0ffee1dea00'));
    await expectClaim(page, test.info(), 'keys-client-key', hex(expected.key));
    expect(await page.locator('[data-claim="keys-client-key"]').textContent()).not.toBe(before);
  });

  test('the initial_secret on screen is HMAC(salt, connection ID)', async ({ page }) => {
    await boot(page, 'dark');
    const connectionId = await page.locator('#cid-input').inputValue();
    // HKDF-Extract is exactly one HMAC call, so this is the whole derivation
    // computed a second way.
    await expectClaim(page, test.info(), 'keys-initial-secret', hex(await hmac(SALT, unhex(connectionId))));
    await expectClaim(page, test.info(), 'keys-salt', hex(SALT));
  });
});

test.describe('the packet on screen is really sealed under those keys', () => {
  test("the RFC's packet opens in this test with Node's own AES-GCM", async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /The Observer/ }).click();
    await expect(page.locator('[data-verdict="observer-result"]')).toBeVisible();

    const connectionId = unhex(
      (await page.locator('[data-claim="observer-connection-id"]').textContent()) ?? '',
    );
    const keys = await clientKeys(connectionId);

    // The page claims it used this key; re-derived, it agrees.
    await expectClaim(page, test.info(), 'observer-client-key', hex(keys.key));

    // Now open the packet here, with Node's AES-GCM, from the page's own
    // reported packet number — no lab code involved.
    const packetNumber = BigInt(
      (await page.locator('[data-claim="observer-packet-number"]').textContent()) ?? '0',
    );
    // The page does not hand its packet bytes to script, and it should not
    // have to: the packet is read out of the RFC text by this file, so neither
    // side of the comparison comes from `src/`.
    const rfc = await readAppendixA2Packet();
    const nonce = keys.iv.slice() as Bytes;
    const padded = bytes(8);
    Buffer.from(padded.buffer, padded.byteOffset, 8).writeBigUInt64BE(packetNumber);
    for (let i = 0; i < 8; i++) nonce[nonce.length - 8 + i] ^= padded[i];

    const hpBlock = await oneAesBlock(keys.hp, rfc.slice(22, 38) as Bytes);
    const mask = hpBlock.slice(0, 5);
    const unprotected = rfc.slice() as Bytes;
    unprotected[0] ^= mask[0] & 0x0f;
    for (let i = 0; i < 4; i++) unprotected[18 + i] ^= mask[1 + i];
    const header = unprotected.slice(0, 22) as Bytes;

    const imported = await subtle.importKey('raw', keys.key, 'AES-GCM', false, ['decrypt']);
    const opened = new Uint8Array(
      await subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: header, tagLength: 128 },
        imported,
        rfc.slice(22) as Bytes,
      ),
    );

    // Two claims the page makes, checked against bytes this test produced.
    await expectClaim(page, test.info(), 'observer-payload-length', String(opened.length));

    const shownName = (await page.locator('[data-claim="observer-server-name"]').textContent()) ?? '';
    expect(shownName).not.toBe('');
    expect(
      Buffer.from(opened).includes(Buffer.from(shownName, 'ascii')),
      `the name the page shows (${shownName}) must appear in the bytes THIS test decrypted`,
    ).toBe(true);
  });
});

test.describe('the observer reads the connection ID out of the packet', () => {
  test('it opens a packet from a connection it has never seen', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /The Observer/ }).click();
    await expect(page.locator('[data-verdict="observer-result"][data-tone="alarm"]')).toBeVisible();

    // THIS IS THE ONE ASSERTION THAT SEPARATES a real observer from one
    // carrying the RFC's connection ID as a constant. Every other check on
    // this page uses the RFC's own packet, which such an observer reproduces
    // perfectly. So the test is the SUCCESS case: a packet legitimately built
    // under a different connection ID, which a real observer opens because it
    // reads that ID off the wire, and a constant-carrying one cannot.
    await page.locator('#observe-foreign-btn').click();
    await expect(page.locator('[data-verdict="observer-result"][data-tone="retired"]')).toBeVisible();
    await page.locator('#observe-btn').click();

    const foreign = unhex('0badc0ffee1dea00');
    const keys = await clientKeys(foreign);

    await expectVerdict(page, test.info(), 'observer-result', {
      tone: 'alarm',
      text: 'AUTHENTICATED AND ENCRYPTED - AND OPENED BY AN OBSERVER WITH NO KEY',
    });
    await expectClaim(page, test.info(), 'observer-connection-id', hex(foreign));
    // And the key it used is the one THIS test derives from that ID.
    await expectClaim(page, test.info(), 'observer-client-key', hex(keys.key));
    await expectClaim(page, test.info(), 'observer-packet-number', '7');
    await expect(page.locator('[data-claim="observer-server-name"]')).toHaveText('example.com');
  });
});

/* ── The negative claim (§4.1d) ──────────────────────────────────────────── */

const NEGATIVE_CLAIM =
  'This packet is encrypted and its authentication tag verifies. That says nothing about secrecy: its keys come from a published constant and a value in the packet itself, and anyone on the path can open it.';

test.describe('the negative claim', () => {
  test('assertion 1 and 2: the fixture is reachable and everything in it is green', async ({
    page,
  }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /The Observer/ }).click();

    // Assertion 2: EVERY verdict this state renders reports success, asserted
    // against the rendered verdicts rather than a flag the test sets. If any
    // of them failed, the fixture would be demonstrating the mechanism working
    // rather than its limit.
    const failing = page.locator('#panel-observer [data-tone="fail"]');
    await expect(failing).toHaveCount(0);
    await expectVerdict(page, test.info(), 'observer-result', {
      tone: 'alarm',
      text: 'AUTHENTICATED AND ENCRYPTED - AND OPENED BY AN OBSERVER WITH NO KEY',
    });

    // Every check the page performs in this state reported success.
    await expect(page.locator('[data-claim="observer-server-name"]')).toHaveText('example.com');
    await expect(page.locator('[data-claim="observer-payload-length"]')).toHaveText('1162');
    await expect(page.locator('[data-claim="observer-packet-number"]')).toHaveText('2');
  });

  test('assertion 3: the limitation is on screen in that state, not behind a disclosure', async ({
    page,
  }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /The Observer/ }).click();

    const claim = page.locator('[data-verdict="observer-negative-claim"]');
    await expect(claim).toBeVisible();
    await expect(claim).toContainText(NEGATIVE_CLAIM);
    // Recorded through the helper as well, so the mutation ledger's entry for
    // this marker has evidence that this assertion ran.
    await expectVerdict(page, test.info(), 'observer-negative-claim', {
      tone: 'caveat',
      text: 'anyone on the path can open it',
    });
    // Not inside a `<details>` the reader has to open.
    expect(
      await claim.evaluate((node) => node.closest('details') !== null),
      'the negative claim must not be behind a disclosure',
    ).toBe(false);
    // And it is tied to this fixture: the alarm verdict is its sibling.
    await expect(page.locator('#panel-observer [data-verdict="observer-result"][data-tone="alarm"]')).toBeVisible();
  });

  test('the bite: one flipped payload bit removes the name and the alarm', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /The Observer/ }).click();
    await expect(page.locator('[data-verdict="observer-result"][data-tone="alarm"]')).toBeVisible();

    await page.locator('#observe-flip-btn').click();
    await page.locator('#observe-btn').click();

    await expectVerdict(page, test.info(), 'observer-result', {
      tone: 'refused',
      text: 'NOT OPENED - no plaintext, and no server name',
    });
    await expect(page.locator('[data-claim="observer-server-name"]')).toHaveText('none');
    await expect(page.locator('#panel-observer')).not.toContainText('example.com');
    await expect(page.locator('[data-claim="observer-plaintext-shown"]')).toHaveText('none');
  });
});

/* ── "Matches the RFC" badges, each re-checked ───────────────────────────── */

test.describe('every "matches the RFC" verdict is a byte comparison', () => {
  test('exhibit 3 claims the built packet equals the RFC\'s, and it does', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /Hide The Packet Number/ }).click();
    await page.locator('#hp-all').click();

    await expectVerdict(page, test.info(), 'hide-result', {
      tone: 'pass',
      text: 'PROTECTED - the assembled 1200-byte packet matches RFC 9001 Appendix A.2 byte for byte',
    });
    // The reverse direction, on the same panel: the receiver recovers the
    // byte-identical header the sender sealed over. A sender and receiver that
    // disagree about the associated data would still agree with THEMSELVES, so
    // this is the assertion that catches an associated-data defect.
    await expectVerdict(page, test.info(), 'open-result', {
      tone: 'pass',
      text:
        'OPENED - and the recovered header is byte-identical to the one the sender sealed over',
    });

    // The cross-check: the page prints the tail of what it built and the tail
    // of the RFC's packet as two separate claims. They must agree, AND they
    // must agree with the RFC text this test reads itself.
    const built = (await page.locator('[data-claim="hide-built-tail"]').textContent()) ?? '';
    const rfcShown = (await page.locator('[data-claim="hide-rfc-tail"]').textContent()) ?? '';
    const tail = hex((await readAppendixA2Packet()).slice(-8));
    expect(built).toContain(tail);
    expect(rfcShown).toContain(tail);
  });

  test('exhibit 3 shows the mask the RFC prints, re-derived here', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /Hide The Packet Number/ }).click();
    await page.locator('#hp-all').click();

    const connectionId = unhex('8394c8f03e515708');
    const keys = await clientKeys(connectionId);
    const rfc = await readAppendixA2Packet();
    const sample = rfc.slice(22, 38) as Bytes;
    const block = await oneAesBlock(keys.hp, sample);

    await expectClaim(page, test.info(), 'hide-sample', hex(sample));
    await expectClaim(page, test.info(), 'hide-mask', hex(block.slice(0, 5)));
  });

  test('exhibits 5 report the other three packets as matching', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /Other Direction, Other Cipher/ }).click();

    await expectVerdict(page, test.info(), 'a3-result', {
      tone: 'pass',
      text: 'BUILT - the 135-byte server Initial matches RFC 9001 Appendix A.3 byte for byte',
    });
    await expectVerdict(page, test.info(), 'a4-result', {
      tone: 'pass',
      text: 'VERIFIED - the computed tag equals the one RFC 9001 Appendix A.4 prints',
    });
    await expectVerdict(page, test.info(), 'a5-result', {
      tone: 'pass',
      text: 'BUILT - the 21-byte packet matches RFC 9001 Appendix A.5 byte for byte',
    });
  });

  test('exhibit 5 proves the sample is NOT at the start of the ciphertext', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /Other Direction, Other Cipher/ }).click();
    // A.3's header is 20 bytes and its sample starts at 22, so it begins two
    // bytes INTO the ciphertext. This is the number that catches a sample
    // taken from the ciphertext's first byte, which A.2 cannot.
    await expectClaim(page, test.info(), 'a3-header-length', '20 bytes');
    await expectClaim(page, test.info(), 'a3-sample-offset', 'byte 22');
    await expectClaim(page, test.info(), 'a3-sample-into-ciphertext', '2 bytes');
  });

  test('exhibit 2 shows a nonce that is the IV XORed, not extended', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /Seal The Payload/ }).click();

    const keys = await clientKeys(unhex('8394c8f03e515708'));
    const nonce = keys.iv.slice() as Bytes;
    nonce[nonce.length - 1] ^= 2; // packet number 2, right-aligned

    await expectVerdict(page, test.info(), 'seal-result', {
      tone: 'pass',
      text: 'SEALED - the 1178 ciphertext-and-tag bytes match RFC 9001 Appendix A.2',
    });
    await expectClaim(page, test.info(), 'seal-iv', hex(keys.iv));
    await expectClaim(page, test.info(), 'seal-nonce', hex(nonce));
    // A cross-check with a parts-sum-to-whole shape: the nonce is exactly as
    // long as the IV. Concatenation would make it longer.
    const shown = (await page.locator('[data-claim="seal-nonce"]').textContent()) ?? '';
    const ivShown = (await page.locator('[data-claim="seal-iv"]').textContent()) ?? '';
    expect(shown.length).toBe(ivShown.length);
  });
});

test.describe('breaking it on purpose really breaks it', () => {
  test('exhibit 6 opens the intact packet and refuses every break', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /Break It On Purpose/ }).click();

    // The baseline every break is measured against.
    await expectVerdict(page, test.info(), 'break-result', {
      tone: 'pass',
      text: 'OPENED - packet number 2, and the payload matches RFC 9001 Appendix A.2',
    });

    // And then none of the six breaks opens. Asserted against the rendered
    // tone, so a page that reported success on a modified packet fails here
    // rather than merely looking wrong.
    const breaks = await page
      .locator('#break-select option')
      .evaluateAll((nodes) => nodes.map((n) => (n as HTMLOptionElement).value));
    expect(breaks[0]).toBe('intact');
    for (const value of breaks.slice(1)) {
      await page.locator('#break-select').selectOption(value);
      await page.locator('#break-run').click();
      const verdict = page.locator('[data-verdict="break-result"]');
      await expect(verdict, `the "${value}" break must not open`).not.toHaveAttribute(
        'data-tone',
        'pass',
      );
      await expect(verdict).toHaveAttribute('data-tone', /fail|refused/);
      // Invariant 3, per break: no plaintext is shown when nothing opened.
      await expect(page.locator('[data-claim="break-plaintext-shown"]')).toHaveText('none');
    }
  });
});

test.describe('the Retry tag commits to a value never sent', () => {
  test('exhibit 5 shows that a Retry tag commits to a connection ID never sent', async ({
    page,
  }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /Other Direction, Other Cipher/ }).click();

    // The security property of RFC 9001 section 5.8: the Original Destination
    // Connection ID is in the associated data and NOT on the wire, so only an
    // entity that saw the client's Initial can compute this tag.
    await expectVerdict(page, test.info(), 'a4-wrong-odcid', {
      tone: 'pass',
      text: 'A wrong original connection ID does NOT verify',
    });

    // The cross-check: the ODCID really is absent from the transmitted packet,
    // which is what makes the previous assertion mean anything.
    const pseudo = (await page.locator('#panel-others').textContent()) ?? '';
    expect(pseudo).toContain('NOT on the wire');
  });
});

/* ── Retirement, the no-op guard, and the [hidden] probe ─────────────────── */

test.describe('stale evidence is retired', () => {
  test('editing the connection ID retires the key verdict and says so', async ({ page }) => {
    await boot(page, 'dark');
    await expect(page.locator('[data-verdict="keys-derivation"][data-tone="pass"]')).toBeVisible();

    await page.locator('#cid-input').fill('8394c8f03e515709');
    await expect(page.locator('[data-verdict="keys-derivation"][data-tone="pass"]')).toHaveCount(0);
    await expect(page.locator('[data-verdict="keys-derivation"][data-tone="retired"]')).toContainText(
      'Connection ID changed',
    );
  });

  test('changing the packet retires the observer verdict and says so', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /The Observer/ }).click();
    await expect(page.locator('[data-verdict="observer-result"][data-tone="alarm"]')).toBeVisible();

    await page.locator('#observe-flip-btn').click();
    await expect(page.locator('[data-verdict="observer-result"][data-tone="alarm"]')).toHaveCount(0);
    await expect(page.locator('[data-verdict="observer-result"][data-tone="retired"]')).toContainText(
      'Packet changed',
    );
    await expect(page.locator('#panel-observer')).not.toContainText('example.com');
  });

  test('changing the break selection retires its verdict and says so', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /Break It On Purpose/ }).click();
    await expect(page.locator('[data-verdict="break-result"][data-tone="pass"]')).toBeVisible();

    await page.locator('#break-select').selectOption('ciphertext-bit');
    await expect(page.locator('[data-verdict="break-result"][data-tone="pass"]')).toHaveCount(0);
    await expect(page.locator('[data-verdict="break-result"][data-tone="retired"]')).toContainText(
      'Selection changed',
    );
  });

  test('THE NO-OP GUARD: re-selecting the same break does not retire a fresh verdict', async ({
    page,
  }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /Break It On Purpose/ }).click();
    await page.locator('#break-select').selectOption('tag-bit');
    await page.locator('#break-run').click();
    await expect(page.locator('[data-verdict="break-result"][data-tone="fail"]')).toBeVisible();

    // The same option again. A `change` event does not fire, and the verdict
    // must stand — a page that retired here would be claiming it had not
    // checked something it had.
    await page.locator('#break-select').selectOption('tag-bit');
    await expect(page.locator('[data-verdict="break-result"][data-tone="retired"]')).toHaveCount(0);
    await expect(page.locator('[data-verdict="break-result"][data-tone="fail"]')).toBeVisible();
  });

  test('re-deriving the same connection ID does not retire a fresh verdict', async ({ page }) => {
    await boot(page, 'dark');
    await page.locator('#derive-btn').click();
    await expect(page.locator('[data-verdict="keys-derivation"][data-tone="pass"]')).toBeVisible();
    await expect(page.locator('[data-verdict="keys-derivation"][data-tone="retired"]')).toHaveCount(0);
  });
});

test.describe('the [hidden] probe', () => {
  test('a hidden tabpanel is really not rendered, not merely class-hidden', async ({ page }) => {
    await boot(page, 'dark');
    // The `[hidden]` cascade trap: a class rule setting `display` outranks the
    // UA's `[hidden]` rule, so an element can paint while the code believes it
    // is hidden. Asserted as computed style, not as the attribute.
    for (const id of ['seal', 'hide', 'observer', 'others', 'break']) {
      const panel = page.locator(`#panel-${id}`);
      await expect(panel).toHaveAttribute('hidden', '');
      expect(
        await panel.evaluate((node) => getComputedStyle(node).display),
        `#panel-${id} carries [hidden] but still paints`,
      ).toBe('none');
      expect(
        await panel.evaluate((node) => (node as HTMLElement).checkVisibility()),
        `#panel-${id} carries [hidden] but checkVisibility() says it is visible`,
      ).toBe(false);
    }
  });

  test('nothing anywhere carries [hidden] while still painting', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: /Break It On Purpose/ }).click();
    const painting = await page.evaluate(() =>
      [...document.querySelectorAll('[hidden]')]
        .filter((node) => getComputedStyle(node).display !== 'none')
        .map((node) => `${node.tagName.toLowerCase()}#${node.id}`),
    );
    expect(painting).toEqual([]);
  });
});

/* ── Helpers that read the RFC text for themselves ───────────────────────── */

/** One AES block, from Node's AES-CTR, with no lab code involved. */
async function oneAesBlock(key: Bytes, block: Bytes): Promise<Bytes> {
  const imported = await subtle.importKey('raw', key, 'AES-CTR', false, ['encrypt']);
  return new Uint8Array(
    await subtle.encrypt({ name: 'AES-CTR', counter: block, length: 128 }, imported, bytes(16)),
  ) as Bytes;
}

/**
 * The Appendix A.2 protected packet, parsed out of the RFC text under
 * `tests/rfc/` by this file — not imported from `src/fixtures/`, so a mutation
 * to the fixture parser cannot move both sides of a comparison at once.
 */
async function readAppendixA2Packet(): Promise<Bytes> {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const text = readFileSync(
    fileURLToPath(new URL('../tests/rfc/rfc9001.txt', import.meta.url)),
    'utf8',
  );
  const start = text.indexOf('\nA.2.  Client Initial');
  const end = text.indexOf('\nA.3.  Server Initial');
  const body = text.slice(start, end);
  const after = body.indexOf('The resulting protected packet is:');
  const lines = body
    .slice(after)
    .split('\n')
    .filter((line) => /^ {3,}(?:[0-9a-f]{2,})(?: [0-9a-f]{2,})*\s*$/.test(line));
  const packet = unhex(lines.join('').replace(/\s+/g, ''));
  expect(packet.length, "the RFC's A.2 packet must parse to 1200 bytes").toBe(1200);
  return packet;
}
