import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  BroadcastMessage,
  DirectMessage,
  RecipientPolicy,
  createBroadcastEnvelopeEvent,
  decodeBroadcastNaddr,
  encodeBroadcastNaddr,
  generateBroadcastKey,
  generateMailCertificate,
  publicKeyDerBase64ToPem,
  scanBroadcastInbox,
  scanDirectInbox,
  sealDirectMessage,
  targetFromLeadingZeros,
} from '../../src/index.js'
import { FakeTransport } from './fakeTransport.js'

const RELAYS = ['wss://relay.example']

async function makeCert() {
  const cert = generateMailCertificate()
  return { privateKeyPem: cert.privateKeyPem, certPem: publicKeyDerBase64ToPem(cert.publicKeyDerBase64) }
}

describe('scanDirectInbox', () => {
  it('finds only envelopes for our key and reports verified senders', async () => {
    const alice = await makeCert()
    const bob = await makeCert()
    const alicePub = 'a'.repeat(64)
    const bobPub = 'b'.repeat(64)

    const sender1 = generateSecretKey()
    const sender2 = generateSecretKey()
    const stranger = generateSecretKey()

    const transport = new FakeTransport()
    // Mail for Alice from two senders, plus mail for Bob (not ours).
    for (const [sender, subject] of [
      [sender1, 'from sender 1'],
      [sender2, 'from sender 2'],
    ] as const) {
      const msg = new DirectMessage()
        .setFrom(getPublicKey(sender))
        .addRecipientTo(alicePub)
        .setSubject(subject)
        .setPlaintext('hello alice')
      const [sealed] = await sealDirectMessage(msg, sender, { [alicePub]: alice.certPem })
      if (!sealed) throw new Error('unreachable')
      transport.seed(sealed.event)
    }
    const bobMsg = new DirectMessage()
      .setFrom(getPublicKey(stranger))
      .addRecipientTo(bobPub)
      .setSubject('for bob only')
      .setPlaintext('not yours')
    const [bobSealed] = await sealDirectMessage(bobMsg, stranger, { [bobPub]: bob.certPem })
    if (!bobSealed) throw new Error('unreachable')
    transport.seed(bobSealed.event)

    const { inbox, rejected } = await scanDirectInbox(transport, RELAYS, {
      privateKeyPem: alice.privateKeyPem,
    })
    expect(inbox).toHaveLength(2)
    expect(rejected).toHaveLength(0)
    for (const mail of inbox) {
      expect(mail.innerEventId).toHaveLength(64)
      expect(Number.isInteger(mail.innerCreatedAt)).toBe(true)
    }
    const subjects = inbox.map((m) => m.message.getSubject()).sort()
    expect(subjects).toEqual(['from sender 1', 'from sender 2'])
    const senders = inbox.map((m) => m.senderPubkey).sort()
    expect(senders).toEqual([getPublicKey(sender1), getPublicKey(sender2)].sort())
  })

  it('the PoW scan filter drops envelopes below the target', async () => {
    const alice = await makeCert()
    const alicePub = 'a'.repeat(64)
    const sender = generateSecretKey()
    const transport = new FakeTransport()

    for (const [subject, leadingZeros] of [
      ['heavy', 8],
      ['light', 0],
    ] as const) {
      const msg = new DirectMessage()
        .setFrom(getPublicKey(sender))
        .addRecipientTo(alicePub)
        .setSubject(subject)
        .setPlaintext('x')
      const [sealed] = await sealDirectMessage(msg, sender, { [alicePub]: alice.certPem }, { leadingZeros })
      if (!sealed) throw new Error('unreachable')
      transport.seed(sealed.event)
    }

    const { inbox } = await scanDirectInbox(transport, RELAYS, {
      privateKeyPem: alice.privateKeyPem,
      targetFilter: targetFromLeadingZeros(8),
    })
    expect(inbox).toHaveLength(1)
    const [only] = inbox
    if (!only) throw new Error('unreachable')
    expect(only.message.getSubject()).toBe('heavy')
  })
})

describe('scanDirectInbox post-decryption policy enforcement (Q2)', () => {
  it('rejects under-mined mail from a sender whose category demands more PoW', async () => {
    const alice = await makeCert()
    const alicePub = 'a'.repeat(64)
    const sender = generateSecretKey()
    const transport = new FakeTransport()

    // The sender under-mined: policy demands 8 zeros, envelope carries 0.
    const msg = new DirectMessage()
      .setFrom(getPublicKey(sender))
      .addRecipientTo(alicePub)
      .setSubject('under-mined')
      .setPlaintext('x')
    const [sealed] = await sealDirectMessage(msg, sender, { [alicePub]: alice.certPem }, { leadingZeros: 0 })
    if (!sealed) throw new Error('unreachable')
    transport.seed(sealed.event)

    const policy = new RecipientPolicy().setAllowUntrustedPolicy({ leadingZeros: 8 })
    const { inbox, rejected } = await scanDirectInbox(transport, RELAYS, {
      privateKeyPem: alice.privateKeyPem,
      policy,
    })
    expect(inbox).toHaveLength(0)
    expect(rejected).toHaveLength(1)
    const [failure] = rejected
    if (!failure) throw new Error('unreachable')
    expect(failure.reason).toBe('insufficient_pow')
    expect(failure.requiredTarget).toBe(targetFromLeadingZeros(8))
    expect(failure.senderPubkey).toBe(getPublicKey(sender))
  })

  it('rejects denied senders post-decryption', async () => {
    const alice = await makeCert()
    const alicePub = 'a'.repeat(64)
    const sender = generateSecretKey()
    const transport = new FakeTransport()

    const msg = new DirectMessage()
      .setFrom(getPublicKey(sender))
      .addRecipientTo(alicePub)
      .setSubject('spam')
      .setPlaintext('x')
    const [sealed] = await sealDirectMessage(msg, sender, { [alicePub]: alice.certPem })
    if (!sealed) throw new Error('unreachable')
    transport.seed(sealed.event)

    const policy = new RecipientPolicy().denyPubKey(getPublicKey(sender))
    const { inbox, rejected } = await scanDirectInbox(transport, RELAYS, {
      privateKeyPem: alice.privateKeyPem,
      policy,
    })
    expect(inbox).toHaveLength(0)
    expect(rejected).toHaveLength(1)
    expect(rejected[0]?.reason).toBe('deny_list')
  })

  it('contact rules only apply when an isContact lookup is provided', async () => {
    const alice = await makeCert()
    const alicePub = 'a'.repeat(64)
    const sender = generateSecretKey()
    const senderPub = getPublicKey(sender)
    const transport = new FakeTransport()

    const msg = new DirectMessage()
      .setFrom(senderPub)
      .addRecipientTo(alicePub)
      .setSubject('hi')
      .setPlaintext('x')
    const [sealed] = await sealDirectMessage(msg, sender, { [alicePub]: alice.certPem })
    if (!sealed) throw new Error('unreachable')
    transport.seed(sealed.event)

    const policy = new RecipientPolicy().setDenyContacts(true)

    // Without a contact lookup, contact rules cannot match: mail is accepted.
    const withoutLookup = await scanDirectInbox(transport, RELAYS, {
      privateKeyPem: alice.privateKeyPem,
      policy,
    })
    expect(withoutLookup.inbox).toHaveLength(1)

    // With the lookup identifying the sender as a contact: rejected.
    const withLookup = await scanDirectInbox(transport, RELAYS, {
      privateKeyPem: alice.privateKeyPem,
      policy,
      isContact: (pubkey) => pubkey === senderPub,
    })
    expect(withLookup.inbox).toHaveLength(0)
    expect(withLookup.rejected[0]?.reason).toBe('deny_contacts')
  })
})

describe('scanBroadcastInbox', () => {
  it('decrypts with the list password and keeps only subscribed topics', async () => {
    const authorKey = generateSecretKey()
    const author = getPublicKey(authorKey)
    const keyMaterial = generateBroadcastKey('list-password')
    const transport = new FakeTransport()

    for (const [topic, subject] of [
      ['announcements', 'v2 is live'],
      ['dev', 'nightly build ready'],
    ] as const) {
      const broadcast = new BroadcastMessage()
        .setAuthor(author)
        .setTopic(topic)
        .setSubject(subject)
        .setPlaintext('body')
      const { event } = await createBroadcastEnvelopeEvent(broadcast, authorKey, keyMaterial)
      transport.seed(event)
    }

    // Subscriber cares only about announcements.
    const credential = { author, password: 'list-password', topic: 'announcements' }
    const inbox = await scanBroadcastInbox(transport, RELAYS, [credential])
    expect(inbox).toHaveLength(1)
    const [only] = inbox
    if (!only) throw new Error('unreachable')
    expect(only.message.getSubject()).toBe('v2 is live')
    expect(only.message.getTopic()).toBe('announcements')
  })

  it('a wrong password opens nothing', async () => {
    const authorKey = generateSecretKey()
    const author = getPublicKey(authorKey)
    const transport = new FakeTransport()

    const broadcast = new BroadcastMessage().setAuthor(author).setTopic('t').setPlaintext('x')
    const { event } = await createBroadcastEnvelopeEvent(
      broadcast,
      authorKey,
      generateBroadcastKey('right-password'),
    )
    transport.seed(event)

    const inbox = await scanBroadcastInbox(transport, RELAYS, [
      { author, password: 'wrong-password', topic: 't' },
    ])
    expect(inbox).toHaveLength(0)
  })

  it('credentials decode from naddrs', () => {
    const author = 'c'.repeat(64)
    const naddr = encodeBroadcastNaddr({ author, password: 'pw', topic: 'announcements' })
    expect(decodeBroadcastNaddr(naddr)).toEqual({ author, password: 'pw', topic: 'announcements' })
  })
})
