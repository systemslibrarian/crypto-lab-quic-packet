# Build brief — crypto-lab-quic-packet

Written 15 November 2026. Paste this whole file to the coding agent, or save it as `brief.md`
in the new repo. It is self-contained apart from `_MASTER-TEMPLATE.md`, which must be in the
repo root (or readable at `audits/_MASTER-TEMPLATE.md` in the crypto-lab catalog repo).

The governing documents are RFCs: fetch them from rfc-editor.org
(`https://www.rfc-editor.org/rfc/rfc9001.txt`, `rfc9000.txt`). One analysis paper is on the
owner's machine at `~/Downloads/crypto-lab-brief-sources/crypto-lab-quic-packet/`; read it
there, do not copy it into the repo, do not commit it.

---

## KICKOFF (read this first)

Build a new Crypto Lab browser demo (Vite + TypeScript, static site, no backend) in the
repository **`crypto-lab-quic-packet`**.

Read `_MASTER-TEMPLATE.md` in full and treat it as the BINDING spec for build, teaching,
look, accessibility, README and deploy. If `audits/kickoff.md` has been given to you, it
governs how you work inside this repo. This brief supplies only the demo-specific facts and
the acceptance checks. Where the template and this brief disagree on build/teach/look/a11y,
the template wins. Where this brief states cryptographic facts, check them against the cited
primary sources and by computation; if you find one wrong, do not silently deviate: write
"Brief said X; that is wrong because Y (source or computation)" in your report and build the
correct thing.

Build to every standard in the template, in its order: §1 Build, §3 Look, §2 Teach,
§4 Accessibility (including §4.1a setup rules, §4.1b claims suite, §4.1c mutation
discipline run from a script, §4.1d negative claim), §5 README, §6 Deploy with §6.1 and §6.2.

Hard rules (from the template; repeated because they are the ones that get broken):
real computation only, never a canned or simulated verdict; honest scoping in the page and
the README; do NOT weaken a gate to get a green run; if something cannot pass honestly,
leave it failing and say so. Do not touch the shared catalog files. Copy the top bar from an
existing lab. Copy the accessibility gate and `claims.spec.ts` shape from
`crypto-lab-schnorr-forge` and rewrite every lab-specific passage.

When done, report: one-line summary with the test count; the mutation ledger (each mutation,
killed or not); how many of RFC 9001 Appendix A's values your tests reproduce; which
ChaCha20 implementation you used for A.5 and how it was verified; confirmation that
grouping / auto-merge / PR gate / workflow_dispatch are all present; and the card metadata
listed at the end of this brief.

---

## NEW DEMO BRIEF

- Repo name:         crypto-lab-quic-packet
- Short name (H1):   QUIC Packet
- Subtitle:          Initial keys from public values · AEAD · header protection
- One-liner:         Browser-based QUIC packet protection — the RFC 9001 worked packets rebuilt byte for byte: Initial keys derived from a published salt and the connection ID on the wire, the payload sealed with AES-128-GCM, the packet number hidden under a separate header-protection mask, and an observer on the path opening the first packet and reading the server name
- Concept to teach:  Encryption with a key everyone can derive gives integrity against accidents and off-path attackers, not secrecy; and a protocol can encrypt its own packet numbers by sampling the ciphertext it has just produced.
- Primitives/spec:   RFC 9001 (Using TLS to Secure QUIC), sections 5.1 to 5.4 and Appendix A; RFC 9000 (packet formats, packet-number encoding); HKDF (RFC 5869) with the TLS 1.3 HKDF-Expand-Label construction; AES-128-GCM; AES for the header-protection mask; ChaCha20-Poly1305 and ChaCha20 (RFC 8439) for the last worked packet.
- Accent (--accent): #d08c60   (not used by any of the 203 labs whose accent is recorded in the 12 November 2026 snapshot; confirm against the live catalog and against neighbouring cards)
- Favicon emoji:     📦
- In scope:          see SCOPE below
- Non-goals:         see SCOPE below

GitHub "About" line: use the one-liner above.

---

## PRE-FLIGHT (verify, do not assume)

1. Confirm the repository name is free under `systemslibrarian` and no catalog card is titled
   "QUIC Packet".
2. In the catalog repo, search `CATALOG.md` and the lab READMEs for `QUIC`, `HTTP/3`,
   `header protection`, `RFC 9001`, `RFC 9000`. What the brief author found (12 November
   2026 snapshot): QUIC appears in no exhibit; several labs cover the TLS 1.3 handshake and
   one covers Encrypted Client Hello. If a lab already protects QUIC packets, STOP and
   report. Link the TLS handshake labs, the Encrypted Client Hello lab, the AES-GCM and
   nonce labs and the HKDF lab you actually find under Related Demos.
3. Check whether RFC 9001 or RFC 9000 has been updated or obsoleted (rfc-editor.org info
   pages) and whether errata touch Appendix A; cite what is current.
4. Playwright port: ask the catalog tool (`node tools/port-sync.js` in the catalog repo). If you
   cannot reach the catalog repo, stop and ask the owner for a port. Never 4173.

---

## SOURCES AND WHAT EACH IS FOR

- **RFC 9001.** A helper fetched the text and reproduced all 36 values printed in
  Appendix A with a program that parses the expected values out of the RFC itself; the
  brief author re-derived the Initial secrets, keys and the first mask separately. Every
  expected value in this lab must be taken from the RFC text, not from this brief.
- **RFC 9000** for the long and short header layouts and packet-number truncation. Read
  sections 17 and Appendix A.2/A.3 (packet-number encoding and decoding).
- **The analysis paper in the sources folder** (a 2020 study of the QUIC record layer). The
  brief author read its abstract and the opening sections only: it calls the encrypted
  packet number a "semi-implicit nonce". Cite it only for what you read.
- QUIC version 2 (RFC 9369) uses a different salt and labels. Not read; see SCOPE.

---

## FACTS (write tests from these, not from your code)

1. **Initial secrets** (RFC 9001 section 5.2). initial_secret = HKDF-Extract(salt, client's
   Destination Connection ID), with the version-1 salt printed in the RFC.
   client_initial_secret and server_initial_secret come from it by HKDF-Expand-Label with
   labels "client in" and "server in" (32 bytes). From each: key ("quic key", 16 bytes),
   IV ("quic iv", 12 bytes), header-protection key ("quic hp", 16 bytes). Everything that
   goes in is on the wire or in the RFC. No secret is involved.
2. **HKDF-Expand-Label** is the TLS 1.3 construction: info = 2-byte length ‖ 1-byte label
   length ‖ "tls13 " + label ‖ 1-byte context length (0 here). WebCrypto's one-shot HKDF
   always runs Extract first, so the second-level derivations must be built from HMAC.
3. **Packet protection** (section 5.3). AEAD nonce = IV XOR the packet number (left-padded
   to 12 bytes). Associated data = the whole unprotected header, including the unprotected
   packet-number bytes. Plaintext = the frames. The 16-byte tag follows the ciphertext.
4. **Header protection** (section 5.4). Sample = 16 bytes of ciphertext starting 4 bytes
   after the START of the packet-number field, whatever its real length. Mask = AES-ECB of
   the sample under the hp key (first 5 bytes used), or for ChaCha20 the keystream with
   counter = first 4 sample bytes and nonce = the remaining 12. The first header byte is
   XORed with mask[0] & 0x0f for long headers and & 0x1f for short headers; the
   packet-number bytes are XORed with mask[1…].
5. **Order matters.** Sender: build header, seal payload, then mask. Receiver: unmask the
   first byte to learn the packet-number length, unmask the packet number, rebuild the
   associated data, then open.
6. **WebCrypto** (measured by a helper under Node's `crypto.subtle`; confirm in a browser):
   HMAC and AES-GCM are available. AES-ECB is not, but one block of AES can be had from
   AES-CTR (the sample as counter block over 16 zero bytes) or AES-CBC (zero IV, first
   output block); both gave the RFC's mask. Keys for ChaCha20 and ChaCha20-Poly1305 were
   REJECTED, so Appendix A.5 needs a JavaScript implementation, verified against RFC 8439's
   own vectors before use.
7. **What the first packet contains.** The client Initial of Appendix A.2 carries a TLS
   ClientHello in a CRYPTO frame; its bytes include the server name `example.com` in clear
   (ASCII `6578616d706c652e636f6d` is visible in the RFC's hex). Opening the packet with the
   derived keys exposes it.

---

## SCOPE

In scope, as exhibits in this order:

1. **Keys from nothing secret.** Salt + connection ID to initial_secret to the six client
   and server values, each HKDF step shown with its label bytes.
2. **Seal the payload.** Nonce construction, associated data, AES-128-GCM over the
   Appendix A.2 payload; tag shown.
3. **Hide the packet number.** Sample position, mask, first-byte bits and packet-number
   bytes before and after; the assembled 1,200-byte packet compared with the RFC's.
4. **The observer.** Start from the RFC's protected packet and the connection ID only:
   derive, unmask, open, parse the CRYPTO frame far enough to print the server name. State
   plainly that this is by design and say what the encryption is for.
5. **The other direction and the other cipher.** The server Initial (A.3), the Retry
   integrity tag (A.4) and the ChaCha20-Poly1305 short-header packet (A.5), each compared
   with the RFC.
6. **Break it on purpose.** Flip a ciphertext bit (tag fails); flip a masked header bit
   (wrong packet-number length, then tag fails); use the wrong connection ID (keys differ,
   tag fails).

Non-goals (say so on the page and in the README): the TLS handshake itself; Handshake and
1-RTT key derivation from a real handshake; key update; QUIC version 2; packet-number
decoding against a receive window beyond one worked example; loss recovery, streams and
flow control; any claim about a particular implementation.

---

## SECURITY / CORRECTNESS INVARIANTS

1. Every expected value in tests is read from the RFC text checked into the test fixtures
   with its source noted (RFC number, appendix, retrieval date), not typed from this brief.
2. The observer in exhibit 4 receives the packet bytes and nothing else (enforce by
   function signature); the connection ID is parsed from the packet.
3. "Opened" is shown only when the AEAD tag verifies.
4. The ChaCha20 and Poly1305 code passes RFC 8439's test vectors (sections 2.3.2, 2.4.2,
   2.5.2, 2.8.2) before A.5 is attempted.
5. No network access: nothing in this lab sends a packet anywhere.

---

## ARCHITECTURE

Pure modules, no DOM: `hkdf.ts` (Extract, Expand, Expand-Label from WebCrypto HMAC),
`initial.ts`, `aead.ts` (AES-128-GCM via WebCrypto; ChaCha20-Poly1305 in TypeScript),
`hp.ts` (both mask constructions), `packet.ts` (long and short header parse and build,
variable-length integers, packet-number encoding), `observer.ts`, `clienthello.ts` (just
enough parsing to find the server_name extension; fail closed on anything unexpected).

---

## UI AND VISUAL SEMANTICS

Follow §3. Packets as annotated hex: fields labelled in text, protected and unprotected
views side by side, the sample window marked by brackets as well as colour. Long values
scroll inside their region. Verdicts are words.

---

## EDGE CASES (each fails closed and teaches via its message)

- Packet shorter than the sample needs: refused (the RFC requires enough bytes to sample).
- Unknown version field: refused with the version shown; no keys derived.
- Tag failure anywhere: "not opened"; no plaintext shown.
- A ClientHello without a server name, or one the minimal parser cannot follow: "server name
  not found", never a guess.
- Packet-number length bits that imply reading past the end: refused.

---

## EXTENSION SEAMS (shape now, do not build)

A `Version` record (salt, labels) so QUIC version 2 could be added; a `KeyPhase` seam for
key update. Name both on the page as "not built here".

---

## ACCEPTANCE CHECKS — expected outcomes, taken from RFC 9001 Appendix A

The values below are quoted so a mismatch is caught early; the tests must still read the
full values from the RFC.

**A. Primitives.** HKDF: RFC 5869 test cases 1 and 3. AES-GCM: one NIST or McGrew-Viega
vector longer than one block with associated data. ChaCha20, Poly1305 and the combined
AEAD: RFC 8439 vectors (invariant 4).

**B. Appendix A.1.** Connection ID `8394c8f03e515708`.
initial_secret begins `7db5df06` and ends `e9ed0a44`.
Client: secret `c00cf151…6c357aea`; key `1f369613dd76d5467730efcbe3b1a22d`;
IV `fa044b2f42a3fd3b46fb255c`; hp `9f50449e04a0e810283a1e9933adedd2`.
Server: secret `3c199828…cdda951b`; key `cf3a5331653c364c88f0f379b6067e37`;
IV `0ac1493ca1905853b0bba03e`; hp `c206b8d9b9f0f37644430b490eeaa314`.
Also test the five HkdfLabel encodings the RFC prints.

**C. Appendix A.2, client Initial.** Unprotected header
`c300000001088394c8f03e5157080000449e00000002` (packet number 2, 4 bytes); payload 1,162
bytes; sample `d1b1c98dd7689fb8ec11d242b123dc9b`; mask `437b9aec36`; protected header ends
`7b9aec34` and begins `c0`; the protected packet is 1,200 bytes. Required: built packet
equals the RFC's byte for byte; and the reverse (unmask and open the RFC's packet) yields
packet number 2 and the RFC's payload.

**D. Appendix A.3, A.4, A.5.** Server Initial: mask `2ec0d8356a`, 135-byte packet equal to
the RFC's. Retry: integrity tag begins `04a265ba` and ends `0f2496ba`. ChaCha20-Poly1305
short header: unprotected header `4200bff4`, nonce `e0459b3474bdd0e46d417eb0`, ciphertext
and tag `655e5cd55c41f69080575d7999c25a5bfb`, mask `aefefe7d03`, protected header
`4cfe4189`; the three packet-number bytes on the wire are the low 24 bits of 654360564.

**E. Observer.** Given only the RFC's 1,200-byte client Initial, the observer function
returns the string `example.com`.

**F. Mutations that must be killed (§4.1c, run from a script, each a concrete patch).**
(1) label prefix "tls13 " omitted; (2) HkdfLabel length field one byte instead of two;
(3) nonce = IV with the packet number appended instead of XORed; (4) associated data
excludes the packet-number bytes; (5) sample taken from the start of the ciphertext
instead of 4 bytes after the start of the packet-number field (A.3, with its 2-byte packet
number, catches what A.2 cannot); (6) long-header first-byte mask 0x1f instead of 0x0f;
(7) masking applied before sealing; (8) mask from AES decryption instead of encryption;
(9) ChaCha20 header-protection counter read big-endian; (10) "opened" shown when
decryption returns bytes without checking the tag; (11) the observer is handed the
connection ID separately and ignores the one in the packet (killed by a test that passes a
packet with a different connection ID and expects failure). A surviving mutation is
reported, not explained away.

**G. Fail-closed paths, each a NAMED test:** every item under EDGE CASES; invariants 2
and 3.

**H. Claims suite (§4.1b).** At minimum: the keys on screen are re-derived by the test from
the connection ID on screen with the test's own HMAC calls; the packet on screen opens with
WebCrypto AES-GCM in the test under those keys; the server name shown appears in the
decrypted bytes the test produced; each "matches the RFC" badge is backed by a byte
comparison the test repeats against the fixture; stale verdicts are retired when the packet
or connection ID is edited; the no-op guard; the `[hidden]` probe.

---

## NEGATIVE CLAIM (§4.1d)

Claim, scoped to the packet on the page: **"This packet is encrypted and its authentication
tag verifies. That says nothing about secrecy: its keys come from a published constant and
a value in the packet itself, and anyone on the path can open it."**

Evidence fixture: exhibit 4 on the RFC's client Initial. The tag verifies, the packet
matches the RFC, and the verdict reads
`AUTHENTICATED AND ENCRYPTED — AND OPENED BY AN OBSERVER WITH NO KEY`, with the
negative-claim sentence and the recovered server name visible in that state.

Bite fixture for mutation (10): the same packet with one payload bit flipped. The page must
show "not opened" and must not show a server name. The three assertions and two bite tests
are as §4.1d specifies.

---

## README NOTES

Follow §5. "What It Is" names the RFCs, the four worked packets, the primitives and which
come from WebCrypto, and "not production software — a teaching demo; it sends nothing".
"When to Use It" must include a "do NOT": do not read exhibit 4 as a flaw someone missed;
the RFC says Initial packets are not confidential, and the page should quote where. "What
Can Go Wrong" covers nonce construction, the sample position and the order of operations.
"Real-World Usage": cite the RFCs for what QUIC specifies; any figure for how much traffic
uses HTTP/3 needs a dated primary source or is left out. "Build & Verify" states the test
count, how many Appendix A values are reproduced, the RFC 8439 vectors, and the a11y gate.
Link the RFC Editor pages; credit the analysis paper by title and authors with its
publisher's page; no links to PDF copies elsewhere.

---

## CARD METADATA TO REPORT BACK (for the catalog session; do not edit the catalog yourself)

Title: QUIC Packet. Subtitle as above. Suggested categories: PROTOCOLS, SYMMETRIC (confirm
both exist in the catalog's CATEGORIES). Suggested level: intermediate. Chips: only what the
source implements (HKDF-Expand-Label, AES-128-GCM, AES header protection, ChaCha20-Poly1305,
ChaCha20 header protection, QUIC Initial key derivation). Accent #d08c60.

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
