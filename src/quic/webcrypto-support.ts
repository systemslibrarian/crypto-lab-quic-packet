/**
 * What WebCrypto in this runtime will actually do, measured rather than
 * assumed.
 *
 * This exists because the lab's architecture turns on three facts about
 * WebCrypto, and all three are the kind that quietly change under a browser
 * update:
 *
 *   - HMAC and AES-GCM are available, so HKDF and packet protection are real
 *     platform primitives;
 *   - AES-ECB is NOT in the algorithm registry, so the header-protection mask
 *     is reached through AES-CTR or AES-CBC instead;
 *   - a raw ChaCha20 or ChaCha20-Poly1305 key is REFUSED, so Appendix A.5
 *     needs the TypeScript implementation in this repo.
 *
 * The page reports what it measured here rather than printing the claim, and
 * `webcrypto-support.test.ts` asserts the same probe under the test runner.
 * If a browser ever ships raw ChaCha20 keys, this turns the lab's reason for
 * hand-rolling it from an assertion into a dated measurement.
 */

export interface AlgorithmSupport {
  readonly name: string;
  readonly what: string;
  readonly available: boolean;
  readonly detail: string;
}

async function probe(name: string, what: string, run: () => Promise<unknown>): Promise<AlgorithmSupport> {
  try {
    await run();
    return { name, what, available: true, detail: 'importKey and one operation both succeeded' };
  } catch (error) {
    const reason = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    return { name, what, available: false, detail: reason };
  }
}

export async function probeWebCrypto(): Promise<AlgorithmSupport[]> {
  const key16 = new Uint8Array(16);
  const key32 = new Uint8Array(32);
  const block = new Uint8Array(16);

  return Promise.all([
    probe('HMAC-SHA-256', 'HKDF-Extract and HKDF-Expand', async () => {
      const imported = await crypto.subtle.importKey(
        'raw',
        key32 as BufferSource,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
      );
      return crypto.subtle.sign('HMAC', imported, block as BufferSource);
    }),
    probe('AES-GCM', 'packet protection and the Retry tag', async () => {
      const imported = await crypto.subtle.importKey('raw', key16 as BufferSource, 'AES-GCM', false, [
        'encrypt',
      ]);
      return crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: new Uint8Array(12) as BufferSource, tagLength: 128 },
        imported,
        block as BufferSource,
      );
    }),
    probe('AES-CTR', 'one AES block, for the header-protection mask', async () => {
      const imported = await crypto.subtle.importKey('raw', key16 as BufferSource, 'AES-CTR', false, [
        'encrypt',
      ]);
      return crypto.subtle.encrypt(
        { name: 'AES-CTR', counter: block as BufferSource, length: 128 },
        imported,
        block as BufferSource,
      );
    }),
    probe('AES-CBC', 'the cross-check on that AES block', async () => {
      const imported = await crypto.subtle.importKey('raw', key16 as BufferSource, 'AES-CBC', false, [
        'encrypt',
      ]);
      return crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: new Uint8Array(16) as BufferSource },
        imported,
        block as BufferSource,
      );
    }),
    probe('AES-ECB', 'the mask construction RFC 9001 section 5.4.3 names', async () =>
      crypto.subtle.importKey('raw', key16 as BufferSource, 'AES-ECB' as unknown as AlgorithmIdentifier, false, [
        'encrypt',
      ]),
    ),
    probe('ChaCha20-Poly1305', 'the Appendix A.5 packet', async () =>
      crypto.subtle.importKey(
        'raw',
        key32 as BufferSource,
        'ChaCha20-Poly1305' as unknown as AlgorithmIdentifier,
        false,
        ['encrypt'],
      ),
    ),
    probe('ChaCha20', 'the Appendix A.5 header-protection mask', async () =>
      crypto.subtle.importKey(
        'raw',
        key32 as BufferSource,
        'ChaCha20' as unknown as AlgorithmIdentifier,
        false,
        ['encrypt'],
      ),
    ),
  ]);
}
