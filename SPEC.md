# Nostr-Mail Protocol Specification

**Version 1.0.0** · Status: ACTIVE
Reference implementation: `nvelope-core` (TypeScript), this repository.
The white paper ("Nostr-Mail") is the non-normative rationale document; THIS
document is the normative protocol definition. The key words **MUST**,
**MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as
described in RFC 2119.

Nostr-Mail is a protocol for longer-form, retained messaging between Nostr
identities (npubs), distinct from chat-style DMs. It defines two message
types — **direct mail** (sealed per-recipient in blinded envelopes) and
**broadcast mail** (passphrase-keyed, topic-filtered lists) — plus the
published profiles, policies, and credentials that make them work.

---

## 1. Concepts and threat model

Nostr-Mail's privacy model is layered:

- **Relays and passive observers** see: envelope events (kind 8500) carrying
  a throwaway pubkey, an opaque ciphertext, a `nonce` tag, and for broadcast
  a `key_info` tag; and profile events (kind 30998) carrying the recipient
  policy JSON and the certificate public key. They see neither message
  content, senders, recipients, subjects, nor conversation structure.
- **Correlating envelopes is infeasible by design**: each direct envelope is
  signed by a fresh throwaway key, encrypted to one recipient, and mined with
  per-recipient proof-of-work. Multiple envelopes produced from one message
  share no observable linkage.
- **Senders are revealed only to intended recipients**, after decryption, via
  the inner event's Nostr signature. Sender authenticity is cryptographic;
  no out-of-band trust is required to know who sent an opened message.
- **The protocol intentionally trades efficiency for privacy**: recipients
  scan envelopes and attempt decryption without knowing which are theirs.
  Cheap checks (PoW pre-filter, signature verification) run before the
  expensive one (asymmetric decryption).
- **Content metadata stays sealed**: subjects, threading identifiers, reply
  addresses, and body text exist only inside ciphertext. Exposing them (e.g.
  a `thread_id` on an envelope tag) would let an observer with one envelope
  infer the existence of further messages and is therefore prohibited.

Spam economics: proof-of-work is the anti-spam lever, priced per recipient
category via the recipient policy. The burden is deliberately asymmetric —
senders mine; recipients compare and decrypt.

---

## 2. Event kinds and tags

| Kind | Meaning | Signed by |
|---|---|---|
| 8500 | Inner direct-message event | Sender's nsec |
| 8500 | Blinded envelope (direct) | Per-envelope throwaway key |
| 8500 | Broadcast envelope | Author's nsec (never blinded) |
| 30998 | Mail profile event (`d`-tagged, parameterized replaceable) | Owner's nsec |

### 2.1 Tag tables

**Blinded envelope (direct):**

| Tag | Value | Required |
|---|---|---|
| `l` | `direct_message` | MUST |
| `nonce` | decimal-string nonce from PoW mining | MUST |

**Broadcast envelope:**

| Tag | Value | Required |
|---|---|---|
| `l` | `broadcast_message` | MUST |
| `key_info` | JSON `{"salt": <64-hex>, "iv": <32-hex>}` | MUST |

Broadcast envelopes MUST NOT carry proof-of-work and MUST NOT have a `nonce`
tag: subscription via the naddr credential is the anti-spam mechanism (§9),
so there is nothing for PoW to price.

**Inner direct-message event:** no tags. (Replies and threading are carried
in the encrypted body, not in tags; see §3.1.)

**Profile events (kind 30998):**

| `d` tag | Content |
|---|---|
| `nv_recipient_profile` | JSON of the recipient policy (§3.3) |
| `nv_public_key` | The mail certificate public key (§4.1), DER base64 |

Profile updates MUST use strictly increasing `created_at`; consumers take the
newest event per `d` tag. Consumers MUST verify the event signature.

---

## 3. Wire formats

All wire objects are JSON. Field names in this section are protocol surface:
they MUST NOT be renamed or reformatted. Producers SHOULD emit fields in the
shapes locked by the reference implementation's tests; consumers MUST
tolerate omitted optional fields and unknown fields.

### 3.1 Direct-message body (encrypted inside the blinded envelope)

```json
{
  "mailToList":   ["<npub-hex>", ...],
  "mailFrom":     "<npub-hex>",
  "ccList":       ["<npub-hex>", ...],
  "replyTo":      "<npub-hex>",
  "subjectLine":  "string",
  "messageType":  { "plaintext": "<base64>", "md": "<base64>", "html": "<base64>" },
  "external_references": [["<type>", "<value>", ...], ...],
  "thread_id":    "string",
  "bccTo":        "<npub-hex>"
}
```

Field rules:

- `replyTo` is an **npub reply address** (the SMTP `Reply-To` analog): the
  npub clients direct replies to, which MAY differ from `mailFrom`. It is
  omitted when unset. It is NOT a message reference; threading uses
  `thread_id`.
- `thread_id` is an opaque conversation key chosen at random by the thread
  originator and propagated unchanged by replies. It MUST NOT be derived from
  message content, timestamps, or keys.
- `bccTo` appears ONLY on the private per-recipient copy generated for a BCC
  recipient. The shared body MUST NOT contain the BCC list.
- `external_references` is an array of arrays, each `[type, value, ...extra]`.
- `messageType` values are base64-encoded UTF-8 per format key. Empty strings
  are stored in memory but omitted from the wire. Producers MUST support
  `plaintext`, `md`, and `html`; consumers MUST preserve unknown format keys
  on import (forward compatibility).
- A body-level `bccList` field MUST NOT be produced; consumers MAY tolerate
  it on import (it is never serialized back).

BCC semantics: for each BCC recipient, the sender produces the shared body
plus `bccTo: <that recipient>`, and seals it only for them. On import, a
recipient's client maps a present `bccTo` into its recipient list AFTER the
visible `mailToList`/`ccList` — a BCC recipient sees the public recipients
and is appended as a recipient themselves (matching legacy email).

### 3.2 Broadcast-message body (encrypted; see §9)

```json
{
  "broadcastMessageType": 0,
  "replyTo": "",
  "subjectLine": "string",
  "author": "<npub-hex>",
  "topic": "string",
  "messageType": { "plaintext": "<base64>" },
  "external_references": []
}
```

Quirk (normative, for wire compatibility): `replyTo` is ALWAYS present,
serialized as `""` when unset — unlike direct messages, which omit it.
`broadcastMessageType` is `0` (open list) or `1` (list-serve).

### 3.3 Recipient policy (profile event content)

```json
{
  "allow": {
    "contacts":  { "leadingzeros": 8 },
    "list":      { "<npub-hex>": { "target": "<64-hex>" } },
    "untrusted": { "leadingzeros": 16 }
  },
  "deny": {
    "list": ["<npub-hex>", ...],
    "contacts": true,
    "untrusted": true
  },
  "global_minimum": { "leadingzeros": 4 }
}
```

A **requirement** object is exactly one of `{"target": "<64-hex>"}` or
`{"leadingzeros": <integer 0..255>}`. The same requirement type — and these
rules — apply uniformly to `allow.contacts`, `allow.list` entries,
`allow.untrusted`, and `global_minimum`.

- Producers MUST NOT emit both keys in one requirement.
- If a non-conforming event contains both, consumers MUST prefer `target`
  and ignore `leadingzeros`.
- Absent groups impose no requirement. Consumers MUST skip malformed entries
  on import rather than fail the policy.

---

## 4. Mail certificates and envelope encryption

### 4.1 Certificates

Each recipient generates an RSA keypair — their **mail certificate**:

- Public key: DER (spki), base64-encoded. Published as the content of the
  `nv_public_key` profile event. Default modulus 2048 bits; 1024–8192 are
  representable (chunk size scales; see §4.2).
- Private key: PKCS#8 PEM. Held solely by the recipient's client, however it
  stores secrets (encrypted keystore, OS store, …). The protocol never
  transmits it and the library never persists it.

### 4.2 Envelope content (direct)

A blinded envelope's content is `JSON.stringify(<chunks>)` where `chunks` is
an array of base64 strings, each an RSA-OAEP (SHA-1, library defaults)
ciphertext of one plaintext chunk of the **inner event JSON** (§7).

Chunking rules:

- Maximum plaintext per chunk: `floor(modulus_bytes) - 42` (42 = OAEP-SHA-1
  overhead) — 214 bytes for 2048-bit certificates.
- Chunks MUST split on UTF-8 character boundaries: never emit a chunk ending
  in the middle of a multi-byte sequence (decoders would produce U+FFFD).
  Implementations MAY chunk by byte length and walk back past continuation
  bytes (top bits `10xxxxxx`) to the character's leading byte.
- Empty plaintext produces a single encrypted empty chunk (the wire array is
  never empty).
- Decryption concatenates chunk plaintexts; therefore all chunkings of the
  same plaintext are mutually decryptable.

---

## 5. Proof of work

### 5.1 Definitions

- A **target** is a 256-bit integer serialized as 64 lowercase hex chars.
- `leadingzeros` counts leading zero **bits** (NIP-13 semantics). The target
  for `n` leading zero bits is `2^(256 - n)`. `n = 0` denotes "effectively no
  constraint" (the all-ones hash is the only non-satisfying id, probability
  2^-256).
- An event **meets** a target iff `event.id < target` (numerically; for
  zero-padded 64-char hex this equals lexicographic comparison). A hash equal
  to the target does NOT meet it.
- Difficulty (expected hashes) of a target is `floor(2^256 / target)`.

All arithmetic MUST be exact (big-integer); floating point MUST NOT be used.

### 5.2 Mining

The event id is `sha256` of the NIP-01 serialization
`[0, pubkey, created_at, kind, tags, content]`. Mining varies only the
`nonce` tag (`["nonce", <decimal string>]`) and therefore MUST run before
signing — the signature does not participate in the id, but the pubkey does,
so the template's pubkey MUST be the final one. Mining SHOULD yield to the
event loop periodically so interactive clients remain responsive, and SHOULD
support progress reporting and cancellation.

---

## 6. Recipient policy evaluation

Evaluation inputs: sender npub, and whether the sender is in the recipient's
contact list (see §11). Precedence:

1. `deny.list` — sender present → **deny** (`deny_list`).
2. `deny.contacts` — sender is a contact → **deny** (`deny_contacts`).
3. Explicit `allow.list` entry for the sender → requirement from that entry
   (an explicit allow overrides `deny.untrusted`; it is an invitation).
4. Sender is a contact → `allow.contacts` requirement.
5. Otherwise (`untrusted` category): `deny.untrusted` → **deny**
   (`deny_untrusted`); else `allow.untrusted` requirement.

`global_minimum` then applies as a floor to every allowed sender: the
effective requirement is the strictest (numerically smallest target) of the
category requirement and the global minimum. With no applicable requirement,
the decision is **allow with no constraint**.

The evaluation result carries the effective target and the producing group
(`contacts` | `list` | `untrusted` | `global_minimum` | `none`) so clients
can display it.

---

## 7. Sending direct mail

1. **Validate identity**: the message's `mailFrom`, when set, MUST equal the
   signer's npub; otherwise sending MUST fail. When unset, it is filled from
   the signer.
2. **Resolve recipients**: for each of To/CC/BCC, fetch the latest
   `nv_public_key` event. Absent certificate → sending fails (nothing to
   encrypt to). Present-but-invalid certificate → sending fails; the onus is
   on the recipient (§13).
3. **Resolve policy**: fetch the latest `nv_recipient_policy` event. Absent →
   open defaults. Present-but-invalid → sending fails (§13). Evaluate for the
   sender with `isContact = false` (conservative: a sender cannot know they
   are the recipient's contact; over-mining is always acceptable). Denied →
   sending fails with the reason.
4. **Build the inner event**: the message wire body (§3.1; one private body
   per BCC recipient, shared body otherwise), as content of a kind-8500 event
   with no tags, signed by the sender's key. Distinct identical bodies SHOULD
   reuse one inner event.
5. **Mine and seal per recipient**: encrypt the inner event JSON to the
   recipient's certificate (§4.2), build the envelope template with a fresh
   throwaway pubkey, mine to that recipient's required target, then sign with
   the throwaway key. Each envelope MUST use its own throwaway keypair.
6. **Publish** to the agreed relay set (§10).

---

## 8. Receiving direct mail

For each scanned envelope:

1. **Pre-filter**: if a scan target is configured (the recipient's policy
   `global_minimum`; §6), discard envelopes whose id fails it — with no
   further consideration.
2. **Verify** the envelope's Nostr signature, then attempt decryption with
   the recipient's certificate private key. Envelopes that do not open are
   discarded silently; relays learn nothing about which were ours.
3. **Post-decryption validation** — only now is the sender known:
   - the inner event MUST be kind 8500 with a valid sender signature;
     otherwise reject;
   - evaluate the recipient's policy for the sender. Denied → reject
     (`deny_list` / `deny_contacts` / `deny_untrusted`);
   - the envelope id MUST meet the effective requirement from that
     evaluation; otherwise reject (`insufficient_pow`).
4. Accepted messages are handed to the client. Messages rejected in step 3
   SHOULD be reported separately from silently-discarded envelopes so clients
   can surface "N envelopes blocked by your policy". Further handling
   (quarantine, spam scoring) is client scope, outside this protocol.

**Identity**: clients MUST key storage on the **inner event id** — the
canonical message identity, identical for all To/CC recipients of one
message. The outer envelope id is a disposable per-recipient artifact and
MUST NOT be used for identity or correlation.

---

## 9. Broadcast mail

### 9.1 Envelope

A broadcast envelope is a single kind-8500 event, signed by the **author's**
key — broadcast envelopes are never blinded, because subscribers find lists
by author. Content is base64 AES-256-CBC ciphertext of the broadcast wire
body. The `key_info` tag carries `{"salt", "iv"}` (§2.1).

- Key: `scrypt(password, salt, 32 bytes)` with implementation defaults
  (N=16384, r=8, p=1 — fixed for wire compatibility).
- A **fresh random IV MUST be generated per message** (16 bytes, serialized
  hex in `key_info`). Reusing an IV across messages under one key is a known
  CBC vulnerability and is prohibited.
- Neither the password nor the topic appears in any tag or plaintext-visible
  field. Discovery and interest filtering are client-side, after decryption.
- No proof-of-work is applied (§2.1); the event is signed and published
  directly.

### 9.2 Credentials (naddr)

A list's subscription credential is a bech32 **naddr**:

```
naddrEncode({ kind: 8500, pubkey: <author npub>, identifier: JSON.stringify([password, topic]) })
```

Decoders MUST reject: non-naddr inputs, naddrs of other kinds, and
identifiers that do not parse as a two-element JSON string array. The naddr
is the only place the password and topic exist outside ciphertext; clients
store it and treat it as the list's secret.

### 9.3 Subscription and receipt

- Subscription filter: `{ kinds: [8500], authors: [<author>], "#l": ["broadcast_message"] }`
  (plus `since` for incrementality). Relays learn only that a pubkey follows
  an author's broadcasts — never which lists.
- Receipt: for each event, derive the key from each held password and the
  event's `salt` (implementations SHOULD cache derived keys per
  `password+salt` so scrypt runs once per list, not per message), decrypt,
  and keep the message only if its decrypted `topic` matches a subscribed
  topic. Readable-but-unwanted messages are discarded. Envelope signatures
  MUST be verified before decryption is attempted.

---

## 10. Relay discovery and publish sets

The protocol does not require a specific relay-discovery mechanism; it
provides courtesy fetchers and a hard override seam, matching the contact-list
pattern (§11):

- **NIP-65** (kind 10002 `r` tags, `read`/`write` markers; unmarked = both) is
  the preferred source.
- **Legacy pre-NIP-65**: relay URLs from the kind-3 contact list's content
  object keys (both directions).
- Direction semantics: publish mail TO someone on their **read** relays;
  publish your profile on your **write** relays; scan your inbox on your
  **read** relays.
- Clients MAY build a **publish superset** — the union of their relays, the
  recipient's read relays, and extras — so an observer cannot tell which
  relays in the set actually matter to the recipient. (Privacy enhancement,
  not a requirement.)
- Sophisticated clients (e.g. cached-NIP-65 stores) override by supplying
  relay lists explicitly at every operation.

---

## 11. Contact lists

Policy evaluation's `isContact` input is deliberately a plain callback —
future contact-list standards integrate by implementing it. The protocol
defines a resolved **ContactList** view — *allowed* keys and *muted* keys —
with courtesy fetchers:

- **kind 3**: latest event; content JSON array plus `p` tags are allowed.
- **NIP-51**: kind 10000 Mute List `p` tags are muted; kind 30000 Categorized
  People Lists `p` tags are allowed (optionally filtered by `d` tag names).

Semantics: `isContact(k)` is true iff `k` is allowed AND not muted. Muting
strips contact privileges — the sender falls back to the untrusted category;
hard denial remains the deny lists' job. Fetching once and reusing the view
across a batch of messages is the intended usage; implementations SHOULD
provide the lookup whenever the policy uses contact-based rules (without it,
those rules cannot match).

---

## 12. Profile publication and health

Clients SHOULD publish both profile events on setup and whenever policy or
certificate changes, with strictly increasing `created_at`. Clients SHOULD
voluntarily self-check (`checkProfile`): certificate event present, valid,
and matching the local certificate (`mismatch` signals an unpushed rotation);
policy event present and valid. Anything not healthy SHOULD be repaired by
republishing (local certificate is ground truth; existing importable policy
is preserved).

---

## 13. Failure semantics

| Recipient published… | Sending behavior |
|---|---|
| Nothing (no profile events) | Allowed, no PoW required (open default) |
| Blank policy (`{}`) | Same: allowed, no PoW |
| A valid policy | Evaluated; denied senders refused with reason; otherwise mine to the required target |
| A corrupt policy event (unparseable, invalid signature) | **Refused** — treated as not sendable, like an invalid certificate. The onus is on the recipient to publish a correct profile; clients SHOULD self-check/repair (§12). |
| No certificate | Refused (nothing to encrypt to) |
| An invalid certificate | Refused |

Blank means open; present-but-broken means closed. There is no third state.

---

## 14. Versioning and forward compatibility

- Everything in §2–§3 (kinds, tag names and values, JSON field names and
  shapes) is **protocol surface**: renaming or reformatting it is a new
  protocol version, not an implementation change.
- Consumers MUST tolerate: omitted optional fields, unknown `messageType`
  format keys (preserved on import), unknown policy entries (skipped),
  unknown top-level fields (ignored).
- Producers MUST NOT emit fields reserved by future versions.
- v1 protocol version identifier: `1` (future use in credential/profile
  negotiation).

---

## Appendix A — v1 scope and v2 candidates

Deliberately omitted from v1 (recorded so they are not mistaken for
oversights):

- **Special Direct messages / paired trust** — an explicit shared secret
  overriding recipient policy. Aspirational; needs careful design. v2
  candidate.
- **`restricted` trust-layer state** — a third sender disposition between
  allow and deny. Same status: v2 candidate.

## Appendix B — Corrections relative to the pre-refactor implementation

The first implementation (same wire field names) was corrected as follows;
these corrections are normative for v1:

1. **PoW math**: `leadingzeros` is now precisely "leading zero bits"
   (`target = 2^(256-n)`), computed in exact integer arithmetic. The old code
   mixed bit/hex-digit math, produced wrong targets for multiples of 4 (which
   then passed everything), and used floating point.
2. **Broadcast IVs**: fresh per message; the old code reused one IV per key.
3. **Envelope chunking**: byte-based with UTF-8 character-boundary snapping;
   the old code split by UTF-16 units, crashing on non-ASCII-heavy messages.
4. **Broadcast credentials**: the old `neventEncode` call silently dropped
   password/topic, and the `#a` subscription filter matched no events. Both
   replaced by the mechanisms in §9.
5. **Signature-checked profile import**, absent-vs-corrupt semantics (§13),
   post-decryption policy validation (§8), and receipt-validation reporting
   are new in v1.
6. The rebuild initially ran broadcast envelopes through the same mining
   machinery as direct envelopes, emitting a trivially-mined `nonce` tag.
   Removed: the original wire shape had none, and opt-in subscription makes
   PoW meaningless for broadcast.

## Appendix C — Reference implementation map

| Spec section | Library module |
|---|---|
| §4 Certificates | `src/crypto/certificate.ts` |
| §4.2 Envelope chunks | `src/crypto/envelope.ts` |
| §5 PoW | `src/crypto/pow.ts` |
| §6 Policy | `src/profile/policy.ts` |
| §7–§8 Send/receive | `src/protocol/blinded.ts`, `src/relay/inbox.ts`, `src/client/nvelopeClient.ts` |
| §9 Broadcast | `src/crypto/symmetric.ts`, `src/protocol/broadcastNaddr.ts` |
| §10 Relays | `src/relay/relayDiscovery.ts` |
| §11 Contacts | `src/relay/contacts.ts` |
| §12 Profile health | `src/profile/mailProfile.ts`, `src/client/nvelopeClient.ts` |
