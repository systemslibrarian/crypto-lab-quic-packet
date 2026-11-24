# QUIC Packet

**Initial keys from public values · AEAD · header protection**

A browser-only lab that rebuilds the four worked packets of RFC 9001 Appendix A byte for byte. Derive the Initial keys from a published salt and the connection ID on the wire, seal the payload with AES-128-GCM, hide the packet number under a separate mask sampled from the ciphertext you have just produced — then open the first packet as an observer with no key at all and read the server name out of it.

> **Not production software — a teaching demo.** It sends nothing: there is no network access anywhere in the page, and no packet built here goes anywhere. Keys exist per session in memory and are never stored. For real QUIC, use a maintained implementation; this exists so you can read every intermediate value.

## What It Is

QUIC is the transport under HTTP/3. A QUIC v1 Initial packet has an encrypted payload that an observer can read by deriving its public Initial keys. Other packet types have different protections. Retry carries an integrity tag over visible data, and Version Negotiation has no packet protection (RFC 9000 §12.1). RFC 9001 §5.2 derives the Initial keys from two values anyone can see:

```
initial_secret        = HKDF-Extract(initial_salt, client's Destination Connection ID)
client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
key / iv / hp         = HKDF-Expand-Label(client_initial_secret, "quic key" / "quic iv" / "quic hp", "", 16 / 12 / 16)
```

The salt is printed in the standard. The connection ID travels in the clear, in the header of the very packet those keys will open. Nothing secret goes in, so anyone on the path can run the same derivation.

**What the encryption buys, then, is integrity and not secrecy** — and RFC 9001 says so in section 7, "Security of Initial Messages":

> Initial packets are not protected with a secret key, so they are subject to potential tampering by an attacker. QUIC provides protection against attackers that cannot read packets but does not attempt to provide additional protection against attacks where the attacker can observe and inject packets.

Along the way QUIC does something genuinely clever, and it is the mechanism this lab exists to show. The packet number has to be hidden — a watcher who can count packets per connection can track a device across networks — but it also has to be readable by the receiver before the receiver can decrypt anything, because the AEAD nonce depends on it. QUIC resolves that circle with a second key and a mask taken from **the ciphertext it has just finished producing**: sixteen bytes sampled four bytes after the packet-number field *begins*, encrypted under the header-protection key, XORed into the header. Exhibit 3 steps through it.

That construction has a name in the literature. **"A Security Model and Fully Verified Implementation for the IETF QUIC Record Layer"** — Antoine Delignat-Lavaud, Cédric Fournet, Bryan Parno, Jonathan Protzenko, Tahina Ramananandro, Jay Bosamiya, Joseph Lallemand, Itsaka Rakotonirina and Yi Zhou, 2021 IEEE Symposium on Security and Privacy, pp. 1162–1178, [doi:10.1109/SP40001.2021.00039](https://doi.org/10.1109/SP40001.2021.00039) — models it as **authenticated encryption with *semi-implicit nonces*** and gives it a security definition and an F\* proof. Only its abstract and opening sections were read for this lab, so that is all it is cited for; note also that it studies IETF **draft 30**, not the published RFC, and its abstract reports finding "interesting limitations of nonce confidentiality, due to the malleability of short headers and the ability to choose the number of least significant bits included in the packet counter". Nothing on this page rests on that paper, and nothing here reproduces its results.

**The specifications.** [RFC 9001](https://www.rfc-editor.org/info/rfc9001) (Using TLS to Secure QUIC) sections 5.1–5.4, 5.8 and Appendix A; [RFC 9000](https://www.rfc-editor.org/info/rfc9000) (QUIC transport) sections 16–17 and Appendices A.1–A.3 for the header layouts, variable-length integers and packet-number encoding. Both are Proposed Standards, neither obsoleted nor updated as of 17 November 2026. HKDF is [RFC 5869](https://www.rfc-editor.org/info/rfc5869) with the [RFC 8446](https://www.rfc-editor.org/info/rfc8446) section 7.1 HKDF-Expand-Label construction; ChaCha20 and Poly1305 are [RFC 8439](https://www.rfc-editor.org/info/rfc8439).

**Which primitives come from where.** HMAC-SHA-256 and AES-128-GCM are WebCrypto's. AES-ECB — the primitive RFC 9001 section 5.4.3 names for the header-protection mask — **is not in the WebCrypto registry at all**, so one AES block is reached two ways and required to agree: AES-CTR with the sample as the counter block over sixteen zero bytes, cross-checked against AES-CBC with a zero IV. WebCrypto also refuses a raw ChaCha20 or ChaCha20-Poly1305 key, so **ChaCha20 and Poly1305 are written out** in [`src/quic/chacha20.ts`](src/quic/chacha20.ts) and [`src/quic/poly1305.ts`](src/quic/poly1305.ts), verified against RFC 8439's own vectors before Appendix A.5 is attempted. None of that is asserted in a comment: exhibit 5 **probes this browser and prints what it measured**, so the day a browser ships raw ChaCha20 keys the page says so.

**No expected value in this repository is typed by hand.** [`src/fixtures/rfc9001-excerpt.txt`](src/fixtures/rfc9001-excerpt.txt) carries RFC 9001 sections 5.2, 5.8 and Appendix A verbatim with a provenance header, [`src/fixtures/rfc9001.ts`](src/fixtures/rfc9001.ts) parses every value out of it at load time, and a test rebuilds the excerpt from the full RFC text under [`tests/rfc/`](tests/rfc/) and requires a byte-exact match. The RFC texts themselves are pinned by SHA-256.

## Exhibits

1. **Keys From Nothing Secret** — The salt, an **editable** connection ID, and all eight HKDF-Expand-Label steps with the exact info bytes that went into each. Edit the connection ID and every one of the nine values moves, which is the fastest way to see that the ID is the only thing separating one connection's Initial keys from another's. A non-hex or out-of-range ID is refused by name with no keys derived.
2. **Seal The Payload** — AES-128-GCM over the Appendix A.2 payload, with the nonce shown as a three-row XOR (IV, zero-padded packet number, result) rather than asserted; the whole unprotected header as associated data, annotated field by field; and the 16-byte tag after 1,162 bytes of ciphertext.
3. **Hide The Packet Number** — The headline mechanism, as five steps you drive. Build the header with the packet number in the clear; seal; watch the sample window appear in the ciphertext you just produced, bracketed as well as tinted; encrypt it into a five-byte mask; XOR four low bits of the first byte and the packet-number bytes. Then the **receiving** side runs the same five operations in a different order, because after the first byte comes off it knows something it did not know before — how long the packet number is.
4. **The Observer** — The RFC's own 1,200-byte client Initial, handed to a function whose only argument is the packet bytes. It reads the connection ID off the wire, derives the keys from the published salt, removes header protection, opens the payload, and parses the ClientHello far enough to print `example.com`. A third button rebuilds the packet under a connection ID the RFC never used, which is the one state that separates a real observer from one carrying a constant. Flip a payload bit and the verdict becomes "not opened" with no server name anywhere.
5. **Other Direction, Other Cipher** — The server Initial (A.3), whose **two-byte** packet number puts the sample two bytes into the ciphertext and so catches a sample taken from the ciphertext's start, which A.2 cannot. The Retry packet (A.4), which encrypts nothing at all and commits its tag to a connection ID that never travelled. The ChaCha20-Poly1305 short-header packet (A.5), with the other mask construction and its little-endian block counter — and the same packet with one ciphertext bit flipped, which is invariant 3 on the only path where this repository's own code decides.
6. **Break It On Purpose** — Seven breaks against the real AEAD, each failing at a different stage: a ciphertext bit, a tag bit, a masked header bit that lies about the packet-number length, the wrong connection ID, a truncated packet and an unknown version field — the last two refused before any decryption is attempted. Where it says no plaintext is shown, that is because none was produced.

## When to Use It

- **Use** it to understand what QUIC's Initial keys do and do not buy, and to see the header-protection circle close.
- **Use** it to check an implementation's intuition: the sample offset, the nonce construction and the order of operations are the three things implementations get wrong, and each has its own exhibit.
- **Do NOT** read exhibit 4 as a flaw someone missed. RFC 9001 section 7 says Initial packets are not protected with a secret key and that QUIC does not attempt to protect against an attacker who can observe packets — quoted in full on the page, beside the exhibit. Secrecy starts with the Handshake keys, which come from the TLS key exchange this lab does not run.
- **Do NOT** use this code in production. It is written for transparency: nothing here is constant time, the ChaCha20 and Poly1305 implementations are teaching implementations and say so, and the parsing is deliberately strict rather than interoperable.
- **Do NOT** take the ClientHello parse as a TLS implementation. It walks CRYPTO frame → ClientHello → extensions → server_name → host_name with a length check at every step and refuses the moment the bytes stop matching, which is the opposite of what an interoperable parser does.

## Live Demo

**https://systemslibrarian.github.io/crypto-lab-quic-packet/**

Edit the connection ID and watch nine keys move. Step the header-protection stepper and watch the mask come out of the ciphertext it was used to hide. Open the RFC's first packet with no key and read the server name. Then break it seven ways.

## What Can Go Wrong

These are the three mistakes the specification's own worked examples exist to catch, and each has a recorded mutation proving a test notices it:

- **The nonce.** RFC 9001 section 5.3 left-pads the reconstructed packet number to the IV's length and **XORs**. Appending instead produces a nonce longer than the IV; truncating the packet number to its encoded length produces the wrong one. Note that the **full 62-bit** packet number goes in, not the bytes on the wire — erratum 7785 proposed narrowing that to 32 bits and was rejected in 2024.
- **The sample position.** Sixteen bytes starting four bytes after the packet-number field **begins**, as if the packet number were always four bytes — because the receiver reads the sample before it has unmasked the bits that say how long the packet number really is. For Appendix A.2's four-byte packet number that is the first ciphertext byte, so an implementation that samples from the start of the ciphertext reproduces A.2 perfectly and fails on A.3.
- **The order of operations.** A sender builds the header, seals, samples, then masks. A receiver unmasks the first byte, *then* learns the packet-number length, then unmasks that many bytes, then rebuilds the associated data, then opens. Get the order wrong in either direction and you have an implementation that agrees with itself and with nothing else.

And one that is not a mistake but a property worth knowing: **removing header protection needs no authentication at all.** A packet whose tag will fail gives up its packet number first. That asymmetry is why RFC 9001 keeps header protection and packet protection in separate sections with separate keys, and it is visible in exhibits 4 and 6.

### Two errata this lab implements rather than the published text

- **RFC 9000 erratum 9281** (Verified 2026-11-13) corrects Appendix A.2's packet-number-length pseudocode from `ceil(min_bits / 8)` to `floor(min_bits / 8) + 1`. Section 17.1 requires an encoding of *n* bits where 2ⁿ > 2·*d*; the published form yields exactly 2·*d* when the number of unacknowledged packets is 2⁷, 2¹⁵ or 2²³. [`packetNumberLength`](src/quic/packet.ts) implements the correction, and a test checks the inequality across every range the two formulas disagree on.
- **RFC 9001 erratum 9272** (Verified 2026-11-05) corrects section 5.4.3's opening sentence from "packet protection algorithm" to "header protection algorithm". A wording fix; the algorithm is as published.

Two more are worth knowing and change nothing here. **RFC 9001 erratum 9231** (Held for Document Update) proposes regenerating Appendix A.2 with a one-byte packet number and a Source Connection ID, the verifier noting that the current example's missing SCID is a real inconsistency with RFC 9000 section 7.3 but that "the right fix is to regenerate all four examples if the RFC is ever updated" — so the published values stand, and this lab reproduces them. **RFC 9001 erratum 7785** is the rejected 62-bit one above.

## Real-World Usage

QUIC version 1 is specified in RFC 9000 and RFC 9001, both Proposed Standards published May 2021, and HTTP/3 is specified over it in [RFC 9114](https://www.rfc-editor.org/info/rfc9114). QUIC version 2 is [RFC 9369](https://www.rfc-editor.org/info/rfc9369), which keeps this construction and changes the salt and the four labels; it is not built here.

No figure for how much of the web runs on HTTP/3 appears in this README, and that is deliberate: the ones in circulation come from undated vendor dashboards, and the brief for this lab required a dated primary source for any such number. There isn't one here, so there is no number.

What the specifications themselves say about the mechanism this lab shows, which is a claim about QUIC and not about any deployment: header protection exists so that on-path elements cannot read the packet number (RFC 9001 section 5.4), and its security is analysed in section 9.4, with the timing side channel in section 9.5.

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173/crypto-lab-quic-packet/
```

```bash
npm test           # 226 unit tests, including every RFC known-answer vector
npm run build      # typecheck, then production build
npm run test:a11y  # the WCAG 2.1 AA gate, against the production build
npm run mutate     # list the recorded mutations; `run` judges them
```

## Related Demos

- [crypto-lab-tls-handshake](https://systemslibrarian.github.io/crypto-lab-tls-handshake/) — the TLS 1.3 handshake this lab deliberately does not run, and the key schedule the Handshake keys come from.
- [crypto-lab-blind-hello](https://systemslibrarian.github.io/crypto-lab-blind-hello/) — Encrypted Client Hello: the mechanism that closes the hole exhibit 4 walks through.
- [crypto-lab-kdf-chain](https://systemslibrarian.github.io/crypto-lab-kdf-chain/) — HKDF itself, Extract and Expand, at more length than exhibit 1 can give it.
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES-GCM and the other modes, including why one AES block is reachable from CTR.
- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — what happens when an AEAD nonce repeats, which is what QUIC's IV-XOR-packet-number construction exists to prevent.
- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — the ChaCha20 keystream that becomes the A.5 header-protection mask.
- [crypto-lab-poly1305-mac](https://systemslibrarian.github.io/crypto-lab-poly1305-mac/) — the one-time authenticator behind the A.5 tag.

## Build & Verify

**226 unit tests** (Vitest) and **33 browser tests** (Playwright), all passing.

**Every one of the 42 values RFC 9001 Appendix A prints is reproduced** — the five HkdfLabel encodings, the nine A.1 key values, and all four worked packets built forwards and opened backwards. [`tests/appendix-a-coverage.test.ts`](tests/appendix-a-coverage.test.ts) counts them from two directions that have to agree: forward, every value the fixtures parse and some suite computes against; backward, every multi-line hex block in the appendix text, so a value this lab quietly ignored would show up as a gap rather than as nothing.

**Primitive known-answer vectors, all read out of the specification texts rather than transcribed:**

| Primitive | Vectors | Source |
|---|---|---|
| HKDF | Test Cases 1 and 3 (the SHA-256 ones) | RFC 5869 Appendix A |
| HKDF-Expand-Label | the five encodings Appendix A.1 prints | RFC 9001 |
| ChaCha20 block function | section 2.3.2 | RFC 8439 |
| ChaCha20 cipher | section 2.4.2, plaintext, keystream and ciphertext | RFC 8439 |
| Poly1305 | section 2.5.2, plus all 11 Appendix A.3 reduction-edge vectors | RFC 8439 |
| ChaCha20-Poly1305 AEAD | section 2.8.2 and the Appendix A.5 decryption vector | RFC 8439 |
| AES-128-GCM | 45 cases, every one with a non-empty AAD and a plaintext longer than one block | NIST CAVP `gcmEncryptExtIV128.rsp` |
| QUIC variable-length integers | all five of Appendix A.1's worked decodings | RFC 9000 |

The NIST excerpt under [`tests/nist/`](tests/nist/) carries the SHA-256 of the complete 2.9 MB CAVP file it was cut from, and the groups it keeps are asserted to be the ones with a 96-bit IV, a 128-bit tag, a non-empty AAD and a plaintext over one block — so a future re-cut cannot quietly narrow it.

**The accessibility gate** is `@axe-core/playwright` against the production build, WCAG 2.1 A/AA, at desktop and 380px width, over roughly 35 driven states: every refusal, every retired verdict, all six stepper states, all seven breaks, every disclosure opened through its own `<summary>`, plus hover and focus states. Zero violations, zero unexplained `incomplete` results, and an empty non-text-contrast baseline. It also carries four oracles axe has no rule for — arithmetic composite-aware contrast, non-text contrast against the surround, reflow, and keyboard reachability of scroll regions. Its own first full drive found four defects in this page: the `[hidden]` cascade trap on `.panel`, a missing `box-sizing: border-box` that made the template's own hero snippet overflow by 36px, an input whose `size="42"` pushed the document to a 434px scroll width at 380px, and a selector that retired a verdict on a re-selection of the same option.

**The mutation ledger.** [`e2e/verdict-mutations.json`](e2e/verdict-mutations.json) records **15 mutations** as concrete patches — a file, an anchor that must occur exactly once, a replacement — covering **62 owning assertions**. `node scripts/mutate.mjs run` applies each in an isolated `git archive HEAD` tree, builds, runs both suites whole, and classifies the result: a patch that does not compile is DOES NOT BUILD and never a kill, a red run matching a build error or a server that never started is NOT A KILL, and a kill requires the owning test to have passed unmutated in the same run and the built bundle's hash to have moved and returned. **15 of 15 are killed.** Six of those fifteen exist, or were re-aimed, *because* the loop reported them surviving — including one that had no browser-visible effect at all until exhibit 5 gained a broken-tag state, and one that found the page printing a hardcoded `0f` where it should have printed the mask width it computed.

Two registry pins are outstanding and belong to a catalog session rather than to this repository: this lab's Playwright port (4248) in `tools/playwright-ports.json`, and its row in `tools/dispatch-census.json`. Until then `port-sync check` and `dispatch-sync check` report it as unpinned, which is the correct answer.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
