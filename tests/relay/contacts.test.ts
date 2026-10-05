import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  ContactList,
  DirectMessage,
  NsecSigner,
  NvelopeClient,
  RecipientPolicy,
  buildUnsignedEvent,
  fetchKind3Contacts,
  fetchNip51Contacts,
  finalizeWithNsec,
  generateMailCertificate,
  publicKeyDerBase64ToPem,
  sealDirectMessage,
} from '../../src/index.js'
import { FakeTransport } from './fakeTransport.js'

const RELAYS = ['wss://relay.example']
const ALICE = 'a'.repeat(64)
const BOB = 'b'.repeat(64)
const CAROL = 'c'.repeat(64)

describe('ContactList', () => {
  it('isContact is true only for allowed-and-not-muted keys', () => {
    const list = new ContactList([ALICE, BOB], [BOB])
    expect(list.isContact(ALICE)).toBe(true)
    expect(list.isContact(BOB)).toBe(false) // muted overrides allowed
    expect(list.isContact(CAROL)).toBe(false)
    expect(list.isMuted(BOB)).toBe(true)
  })

  it('ignores non-hex keys and merges views', () => {
    const a = new ContactList([ALICE], [BOB])
    const b = new ContactList([BOB, CAROL], ['not-hex'])
    const merged = a.merge(b)
    expect(merged.isContact(ALICE)).toBe(true)
    expect(merged.isContact(BOB)).toBe(false) // still muted
    expect(merged.isContact(CAROL)).toBe(true)
  })
})

describe('fetchKind3Contacts', () => {
  it('reads the latest kind-3 content array and p tags', async () => {
    const ownerKey = generateSecretKey()
    const owner = getPublicKey(ownerKey)
    const transport = new FakeTransport()

    const older = finalizeWithNsec(
      buildUnsignedEvent({ kind: 3, content: JSON.stringify([ALICE]), createdAt: 1000 }),
      ownerKey,
    )
    const newer = finalizeWithNsec(
      buildUnsignedEvent({
        kind: 3,
        content: JSON.stringify([BOB]),
        tags: [['p', CAROL]],
        createdAt: 2000,
      }),
      ownerKey,
    )
    transport.seed(older, newer)

    const contacts = await fetchKind3Contacts(transport, owner, RELAYS)
    expect(contacts.isContact(BOB)).toBe(true)
    expect(contacts.isContact(CAROL)).toBe(true) // p tag
    expect(contacts.isContact(ALICE)).toBe(false) // superseded list
  })

  it('returns an empty view when nothing is published', async () => {
    const transport = new FakeTransport()
    const contacts = await fetchKind3Contacts(transport, ALICE, RELAYS)
    expect(contacts.allowedCount).toBe(0)
  })
})

describe('fetchNip51Contacts', () => {
  it('reads mute list (kind 10000) and people lists (kind 30000)', async () => {
    const ownerKey = generateSecretKey()
    const owner = getPublicKey(ownerKey)
    const transport = new FakeTransport()

    transport.seed(
      finalizeWithNsec(
        buildUnsignedEvent({ kind: 10000, content: '', tags: [['p', BOB]], createdAt: 1000 }),
        ownerKey,
      ),
      finalizeWithNsec(
        buildUnsignedEvent({
          kind: 30000,
          content: '',
          tags: [['d', 'friends'], ['p', ALICE], ['p', BOB]],
          createdAt: 1000,
        }),
        ownerKey,
      ),
    )

    const contacts = await fetchNip51Contacts(transport, owner, RELAYS)
    expect(contacts.isContact(ALICE)).toBe(true)
    expect(contacts.isContact(BOB)).toBe(false) // in friends list but muted
    expect(contacts.isMuted(BOB)).toBe(true)
  })

  it('honors a listNames filter on categorized people lists', async () => {
    const ownerKey = generateSecretKey()
    const owner = getPublicKey(ownerKey)
    const transport = new FakeTransport()

    transport.seed(
      finalizeWithNsec(
        buildUnsignedEvent({
          kind: 30000,
          content: '',
          tags: [['d', 'friends'], ['p', ALICE]],
          createdAt: 1000,
        }),
        ownerKey,
      ),
      finalizeWithNsec(
        buildUnsignedEvent({
          kind: 30000,
          content: '',
          tags: [['d', 'coworkers'], ['p', CAROL]],
          createdAt: 1000,
        }),
        ownerKey,
      ),
    )

    const onlyFriends = await fetchNip51Contacts(transport, owner, RELAYS, {
      listNames: ['friends'],
    })
    expect(onlyFriends.isContact(ALICE)).toBe(true)
    expect(onlyFriends.isContact(CAROL)).toBe(false)
  })
})

describe('batch evaluation: fetch once, validate many messages', () => {
  it('a single ContactList instance validates a whole inbox batch', async () => {
    const transport = new FakeTransport()
    const recipientKey = generateSecretKey()
    const recipientPub = getPublicKey(recipientKey)
    const cert = generateMailCertificate()
    const client = new NvelopeClient({
      transport,
      signer: new NsecSigner(recipientKey),
      relays: RELAYS,
      certificatePrivateKeyPem: cert.privateKeyPem,
    })

    // deny.contacts: only enforced when the contact lookup identifies senders.
    await client.publishProfile(new RecipientPolicy().setDenyContacts(true))

    const aliceKey = generateSecretKey()
    const alicePub = getPublicKey(aliceKey)
    const certPem = publicKeyDerBase64ToPem(cert.publicKeyDerBase64)
    for (const subject of ['one', 'two', 'three']) {
      const message = new DirectMessage()
        .setFrom(alicePub)
        .addRecipientTo(recipientPub)
        .setSubject(subject)
        .setPlaintext('x')
      const [sealed] = await sealDirectMessage(message, aliceKey, { [recipientPub]: certPem })
      if (!sealed) throw new Error('unreachable')
      transport.seed(sealed.event)
    }

    // One fetched ContactList, one scan: all three messages judged by it.
    const contacts = new ContactList([alicePub])
    const withLookup = await client.checkDirectInbox({ isContact: contacts })
    expect(withLookup.inbox).toHaveLength(0)
    expect(withLookup.rejected).toHaveLength(3)
    for (const failure of withLookup.rejected) {
      expect(failure.reason).toBe('deny_contacts')
    }

    // No lookup: contact rules cannot match, everything is accepted.
    const withoutLookup = await client.checkDirectInbox()
    expect(withoutLookup.inbox).toHaveLength(3)
    expect(withoutLookup.rejected).toHaveLength(0)
  })
})
