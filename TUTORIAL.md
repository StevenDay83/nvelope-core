# nvelope-core Tutorial

Hands-on recipes for the most common things you'll do with nvelope-core.
Every snippet is runnable in spirit — see `examples/` for complete programs
(`demo-offline.ts` runs the whole tutorial with no network).

Prerequisites: `npm install nvelope-core` (or a local checkout), Node 20+.

```ts
import { ... } from 'nvelope-core'
```

---

## 1. The sixty-second model

- Your identity is a Nostr keypair, injected as a **Signer** (usually
  `NsecSigner`). The library never persists it.
- Your **mail certificate** is an RSA keypair. Recipients publish the public
  half; you keep the private half to open your mail.
- **Direct mail** = a signed *inner event* sealed inside a *blinded envelope*
  (throwaway key, per-recipient PoW, encrypted to the recipient's
  certificate).
- **Broadcast mail** = author-signed envelopes encrypted with a
  passphrase-derived key; subscribers hold an **naddr** credential
  `[password, topic]`.
- Relay access is injected as a **Transport** (`NostrToolsTransport` for live
  relays, `MemoryTransport` for tests).

---

## 2. Create an identity and a certificate

```ts
import { generateSecretKey } from 'nostr-tools/pure'
import { generateMailCertificate, NsecSigner } from 'nvelope-core'

const secretKey = generateSecretKey()            // or load from your keystore
const signer = new NsecSigner(secretKey)

const cert = generateMailCertificate()           // 2048-bit RSA by default
// cert.publicKeyDerBase64 → publish in your profile
// cert.privateKeyPem      → guard in your keystore
```

---

## 3. Create a client

```ts
import { NostrToolsTransport, NvelopeClient } from 'nvelope-core'

const relays = ['wss://relay.damus.io', 'wss://nos.lol']
const client = new NvelopeClient({
  transport: new NostrToolsTransport(),
  signer,
  relays,
  certificatePrivateKeyPem: cert.privateKeyPem,
  certificatePublicKeyDerBase64: cert.publicKeyDerBase64, // optional; derived if omitted
})
```

---

## 4. Publish (and maintain) your profile

```ts
import { RecipientPolicy } from 'nvelope-core'

// Open defaults: everyone may send, no PoW.
await client.publishProfile()

// Or with rules: contacts free, untrusted must mine 8 leading zero bits,
// and a floor of 4 bits for absolutely everyone.
await client.publishProfile(
  new RecipientPolicy()
    .setAllowContactsPolicy({ leadingZeros: 0 })
    .setAllowUntrustedPolicy({ leadingZeros: 8 })
    .setGlobalMinimum({ leadingZeros: 4 })
    .denyPubKey('e4d2…hex…'),                     // someone specific
    .setDenyUntrusted(false),
)

// Voluntary hygiene: verify what relays actually serve, repair if not.
const health = await client.checkProfile()
if (!health.healthy) await client.repairProfile()
```

Rules of thumb: **absent profile = open**, **corrupt profile = people can't
send to you**. If you publish anything, keep it valid (§13 of SPEC.md).

---

## 5. Send a direct message

```ts
import { DirectMessage } from 'nvelope-core'

const message = new DirectMessage()
  .addRecipientTo('b0b1…recipient npub hex…')
  .addCc('c0c1…cc npub hex…')
  .addBcc('d0d1…bcc npub hex…')              // never appears in the shared body
  .setSubject('Quarterly report')
  .setPlaintext('Hello — attached as md too.')
  .setMarkdown('# Quarterly report\nHello.')
  .setThreadId(crypto.randomUUID())          // start a thread (opaque!)
  .setReplyTo('e0e1…replies-go-here npub…')  // optional SMTP-style reply address

const sent = await client.sendDirectMail(message, {
  onProgress: (attempts) => console.log(`mining PoW… ${attempts}`),
})
for (const { recipient, published } of sent) {
  console.log(recipient, 'accepted by', published.accepted)
}
```

What `sendDirectMail` does for you: fills `from` from the signer (and refuses
spoofed `from`), resolves each recipient's certificate and policy from
relays, refuses denied recipients, mines each recipient's required PoW,
seals one blinded envelope per recipient, publishes.

Failures you'll meet (all thrown Errors): recipient has no certificate,
recipient published an invalid certificate/policy (`…published an invalid
recipient policy: …`), recipient denies you (`denies mail from you
(deny_list)`), no recipients, `from` mismatch.

---

## 6. Receive direct mail

```ts
const { inbox, rejected } = await client.checkDirectInbox()

for (const mail of inbox) {
  console.log(mail.message.getSubject(), 'from', mail.senderPubkey)
  console.log('thread:', mail.message.getThreadId())
  console.log('canonical id:', mail.innerEventId)   // key your store on THIS
}

for (const failure of rejected) {
  console.log('blocked:', failure.reason, failure.senderPubkey)
}
```

Notes:

- `checkDirectInbox` pre-filters by your policy's global minimum PoW,
  verifies and decrypts, then validates each sender against your policy.
  `rejected` contains envelopes that decrypted for you but failed policy
  (`deny_list`, `deny_contacts`, `deny_untrusted`, `insufficient_pow`).
- For incremental checks pass `{ since: lastScanTimestamp }`.
- **Contact rules need a contact source** — see §8.

### Replying

```ts
const reply = new DirectMessage()
  .addRecipientTo(original.senderPubkey)
  .setSubject(`Re: ${original.message.getSubject()}`)
  .setPlaintext('…')
  .setThreadId(original.message.getThreadId())   // same conversation
  .setReplyTo(original.message.getReplyTo() || original.senderPubkey)
```

---

## 7. Run and follow a broadcast list

```ts
import { BroadcastMessage, encodeBroadcastNaddr } from 'nvelope-core'

// Publisher side
await client.publishBroadcast(
  new BroadcastMessage()
    .setTopic('announcements')
    .setSubject('v3 is live')
    .setPlaintext('changelog inside'),
  'our-shared-list-password',
)

// Share this credential string with subscribers (it embeds password+topic):
const naddr = encodeBroadcastNaddr({
  author: await client.getPublicKey(),
  password: 'our-shared-list-password',
  topic: 'announcements',
})
```

```ts
// Subscriber side
client.addBroadcastCredential(naddr)             // validate + store
const { inbox } = await client.checkBroadcastInbox()
```

Topics and passwords never appear on relays; subscribers filter decrypted
messages by topic, so one password can serve several topics and readers see
only what they asked for.

---

## 8. Contact lists (for contact-based policies)

```ts
import { fetchKind3Contacts } from 'nvelope-core'

// Fetch ONCE, reuse across scans:
const contacts = await fetchKind3Contacts(transport, myPubkey, relays)

const { inbox } = await client.checkDirectInbox({ isContact: contacts })
// or with your own manager: { isContact: (pk) => myCache.isContact(pk) }
```

A `ContactList` is *allowed* keys minus *muted* keys (`fetchNip51Contacts`
adds kind-10000 mute lists and kind-30000 people lists). Without an
`isContact` source, `deny.contacts` and contact-tier PoW cannot match.

---

## 9. Relay discovery and the publish superset

```ts
import { fetchRelaysNip65, unionRelays } from 'nvelope-core'

const hints = await fetchRelaysNip65(transport, recipientPubkey, relays)

// Publish on your relays + theirs + decoys: observers can't tell which
// relays actually matter to the recipient.
await client.sendDirectMail(message, {
  relays: unionRelays(relays, hints.read, ['wss://decoy.example']),
})
```

Mail goes to the recipient's **read** relays; your profile to your **write**
relays; scanning happens on your **read** relays. Sophisticated clients pass
their own lists everywhere instead.

---

## 10. Test without a network

```ts
import { MemoryTransport } from 'nvelope-core'

const transport = new MemoryTransport()   // drop-in Transport; records queries
// …seed it, build clients with it, run entire flows offline.
// See examples/demo-offline.ts for a complete two-user flow.
```

---

## 11. Quick reference: common errors

| Error message contains | Meaning |
|---|---|
| `has not published a mail certificate` | Recipient can't receive yet |
| `published an invalid mail certificate` / `invalid recipient policy` | Recipient's profile is broken (onus on them; they should `checkProfile`/`repairProfile`) |
| `denies mail from you (…)` | Their policy rejects you |
| `message.from must match the client signer identity` | Spoofed `from` |
| `Envelope does not satisfy the PoW target` | A Signer mutated the mined event (remote-signer mismatch) |

See **SPEC.md** for the normative rules and **API docs** (`npm run docs`)
for every exported function.
