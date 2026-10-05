# nvelope-core

TypeScript implementation of the **Nostr-Mail** protocol, the messaging layer of the
**nVelope** project. It lets Nostr identities (`npub`s) exchange longer-form, retained
mail — distinct from chat DMs — using blinded, encrypted envelopes published as Nostr
events.

This library is transport- and secret-storage agnostic: it works in Electron renderers,
plain Node scripts, and (for the pure modules) browsers. Callers inject relay transport
and signing, and hold their own key material.

> **Wire-format stability.** Everything in `src/constants.ts` and `src/types.ts` is
> protocol surface: it appears verbatim in the JSON of events stored on public relays.
> These names and shapes must never be renamed or reformatted — a change there is a new
> protocol version, not a refactor.

The normative protocol definition — kinds, tags, wire JSON schemas, PoW
formulas, algorithms, and failure semantics — lives in **[SPEC.md](SPEC.md)**.
The original white paper remains the non-normative rationale ("why"); the
spec is the "what" that implementations are written against.

## Documentation

- **[TUTORIAL.md](TUTORIAL.md)** — hands-on recipes: identity, profiles,
  sending/receiving direct mail, broadcast lists, contacts, relays, offline
  testing.
- **API reference** — run `npm run docs` to generate browsable TypeDoc HTML
  from the TSDoc comments on every exported function (`docs/api/index.html`).

## Status

**Step 1 — foundation** is complete. See the roadmap below for what exists and what is
planned.

## Development

```bash
npm install
npm test        # run the test suite once
npm run check   # typecheck + lint + tests (run this before considering anything done)
```

## Protocol status and v2 candidates

Deliberate omissions from the v1 protocol (recorded so they are not mistaken
for oversights):

- **Special Direct messages / paired trust** — an explicit shared secret that
  would override recipient policy. Aspirational pre-code vision; not
  technically designed. Candidate for a carefully-specified v2.
- **`restricted` trust-layer state** — a third sender disposition between
  allow and deny. Same status: aspirational, never implemented, possible v2.

v1 is intentionally the simple model: allow/deny policy groups with PoW
requirements, blinded envelopes, and passphrase-keyed broadcast lists.

## Roadmap

- [x] **Step 1** — Scaffolding, protocol constants, wire types, exact BigInt PoW math,
      non-blocking miner
- [x] **Step 2** — Crypto: mail certificates (RSA), envelope chunk-encryption,
      symmetric (passphrase) encryption, known-answer wire-format fixtures
- [x] **Step 3** — Message models (direct, broadcast) with wire-format round-trip tests
- [x] **Step 4** — Blinded envelopes, kind-8500 events, broadcast naddr credentials
- [x] **Step 5** — Mail profile (kind 30998) and recipient-policy model + evaluation
- [x] **Step 6** — Transport/Signer interfaces + nostr-tools transport, profile resolution, inbox scanning
- [x] **Step 7** — High-level NvelopeClient API + runnable examples

## Layout

```
src/
  index.ts                 public exports — the only import surface consumers use
  constants.ts             kinds, tag names, wire field names (protocol surface)
  types.ts                 wire-format TypeScript interfaces (protocol surface)
  crypto/pow.ts            proof-of-work math (exact BigInt) + non-blocking miner
  crypto/certificate.ts    mail certificate (RSA) generation + format conversion
  crypto/envelope.ts       RSA-OAEP chunk-encryption to a recipient certificate
  crypto/symmetric.ts      AES-256-CBC + scrypt passphrase encryption (broadcast)
  messages/content.ts      shared multi-format body (the `messageType` object)
  messages/direct.ts       DirectMessage model (build/parse the wire format)
  messages/broadcast.ts    BroadcastMessage model + broadcast key material
  protocol/events.ts       kind-8500 event construction + verification
  protocol/blinded.ts      blinded envelope sealing/opening (direct + broadcast)
  protocol/broadcastNaddr.ts broadcast naddr credentials + subscription filters
  profile/policy.ts        recipient policy model (allow/deny/global_minimum) + evaluation
  profile/mailProfile.ts   kind-30998 profile events (policy + certificate)
  relay/transport.ts       Transport interface + SimplePool-backed default
  relay/memoryTransport.ts in-memory Transport (tests, demos, reference impl)
  relay/signer.ts          Signer interface + raw-nsec default
  relay/resolve.ts         fetching certificates and policies from relays
  relay/contacts.ts        ContactList + kind-3 / NIP-51 courtesy fetchers
  relay/relayDiscovery.ts  NIP-65 / legacy kind-3 relay hints + union helper
  relay/inbox.ts           direct + broadcast inbox scanning
  client/nvelopeClient.ts  the high-level facade (send/receive in one call)
tests/                     vitest suite mirroring src/
examples/
  demo-offline.ts          two users exchange mail with NO network (MemoryTransport)
  demo-setup.ts            create a demo identity + publish an open profile (npm run demo:setup)
  demo-relay.ts            send mail over live relays (npm run demo:relay -- <npub> "Subject" "Body")
  identity.ts              shared demo keystore (nvelope-identity.json — demo only, never commit)
```

## License

MIT
