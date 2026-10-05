import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  BroadcastMessage,
  DirectMessage,
  NsecSigner,
  NvelopeClient,
  RecipientPolicy,
  encodeBroadcastNaddr,
  envelopeMeetsPow,
  generateMailCertificate,
  targetFromLeadingZeros,
} from '../../src/index.js'
import { FakeTransport } from '../relay/fakeTransport.js'

const RELAYS = ['wss://relay.example']

async function makeClient(transport: FakeTransport) {
  const secretKey = generateSecretKey()
  const cert = generateMailCertificate()
  const client = new NvelopeClient({
    transport,
    signer: new NsecSigner(secretKey),
    relays: RELAYS,
    certificatePrivateKeyPem: cert.privateKeyPem,
  })
  return { client, secretKey, pubkey: getPublicKey(secretKey), cert }
}

describe('NvelopeClient end-to-end (direct mail)', () => {
  it('send -> inbox round trip with policy-enforced PoW', async () => {
    const transport = new FakeTransport()
    const alice = await makeClient(transport)
    const bob = await makeClient(transport)

    // Bob publishes a profile requiring 8 leading zeros from untrusted senders.
    await bob.client.publishProfile(
      new RecipientPolicy().setAllowUntrustedPolicy({ leadingZeros: 8 }),
    )

    const message = new DirectMessage()
      .addRecipientTo(bob.pubkey)
      .setSubject('hello bob')
      .setPlaintext('the library works end to end')
    const sent = await alice.client.sendDirectMail(message)
    expect(sent).toHaveLength(1)
    if (!sent[0]) throw new Error('unreachable')
    expect(sent[0].recipient).toBe(bob.pubkey)
    // Alice mined to Bob's requirement.
    expect(envelopeMeetsPow(sent[0].event, targetFromLeadingZeros(8))).toBe(true)

    // Bob reads his inbox; the sender is verified as Alice.
    const { inbox } = await bob.client.checkDirectInbox()
    expect(inbox).toHaveLength(1)
    const [mail] = inbox
    if (!mail) throw new Error('unreachable')
    expect(mail.message.getSubject()).toBe('hello bob')
    expect(mail.senderPubkey).toBe(alice.pubkey)
    expect(message.getFrom()).toBe(alice.pubkey) // auto-filled
  })

  it('refuses to send when the recipient denies the sender', async () => {
    const transport = new FakeTransport()
    const alice = await makeClient(transport)
    const bob = await makeClient(transport)

    await bob.client.publishProfile(new RecipientPolicy().denyPubKey(alice.pubkey))

    const message = new DirectMessage().addRecipientTo(bob.pubkey).setPlaintext('x')
    await expect(alice.client.sendDirectMail(message)).rejects.toThrow(/denies mail/)
  })

  it('refuses when the recipient published no certificate', async () => {
    const transport = new FakeTransport()
    const alice = await makeClient(transport)
    const ghostPubkey = getPublicKey(generateSecretKey())

    const message = new DirectMessage().addRecipientTo(ghostPubkey).setPlaintext('x')
    await expect(alice.client.sendDirectMail(message)).rejects.toThrow(/certificate/)
  })

  it('rejects a message whose from does not match the signer', async () => {
    const transport = new FakeTransport()
    const alice = await makeClient(transport)
    const bob = await makeClient(transport)
    await bob.client.publishProfile(new RecipientPolicy())

    const message = new DirectMessage()
      .setFrom(bob.pubkey) // lies about the sender
      .addRecipientTo(bob.pubkey)
      .setPlaintext('x')
    await expect(alice.client.sendDirectMail(message)).rejects.toThrow(TypeError)
  })

  it('an inbox scan target from the recipient own policy drops under-mined mail', async () => {
    const transport = new FakeTransport()
    const alice = await makeClient(transport)
    const bob = await makeClient(transport)

    // Bob's first policy demands a trivial-but-real PoW: ids below
    // 0xfff…fe (top bytes 0xff — passes a no-constraint scan, fails 8 zeros).
    // A plain 0-target mine would pass BOTH scans by chance 1/256 of the time
    // (flaky test), so the requirement is pinned to this exact boundary.
    const boundary = 'f'.repeat(63) + 'e'
    await bob.client.publishProfile(new RecipientPolicy().setGlobalMinimum({ target: boundary }))

    const message = new DirectMessage().addRecipientTo(bob.pubkey).setSubject('old').setPlaintext('x')
    const [sent] = await alice.client.sendDirectMail(message)
    if (!sent) throw new Error('unreachable')
    expect(envelopeMeetsPow(sent.event, boundary)).toBe(true)
    expect(envelopeMeetsPow(sent.event, targetFromLeadingZeros(8))).toBe(false)

    // Bob tightens his policy; the auto scan target now drops the old mail.
    await bob.client.publishProfile(new RecipientPolicy().setGlobalMinimum({ leadingZeros: 8 }))

    // Overriding the scan filter lets the envelope reach decryption, but
    // post-decryption policy validation still rejects it (Q2 semantics).
    const loose = await bob.client.checkDirectInbox({ targetFilter: targetFromLeadingZeros(0) })
    expect(loose.inbox).toHaveLength(0)
    expect(loose.rejected).toHaveLength(1)
    expect(loose.rejected[0]?.reason).toBe('insufficient_pow')

    // With the default (policy-derived global-minimum) scan target, the
    // envelope is discarded pre-decryption: no inbox, no rejected entries.
    const strict = await bob.client.checkDirectInbox()
    expect(strict.inbox).toHaveLength(0)
    expect(strict.rejected).toHaveLength(0)
  })
})

describe('NvelopeClient broadcast', () => {
  it('publish -> subscribe via naddr -> inbox', async () => {
    const transport = new FakeTransport()
    const publisher = await makeClient(transport)
    const reader = await makeClient(transport)

    await publisher.client.publishBroadcast(
      new BroadcastMessage().setTopic('announcements').setSubject('v3 shipped').setPlaintext('go get it'),
      'list-password',
    )

    const naddr = encodeBroadcastNaddr({
      author: publisher.pubkey,
      password: 'list-password',
      topic: 'announcements',
    })
    reader.client.addBroadcastCredential(naddr)

    const inbox = await reader.client.checkBroadcastInbox()
    expect(inbox).toHaveLength(1)
    const [mail] = inbox
    if (!mail) throw new Error('unreachable')
    expect(mail.message.getSubject()).toBe('v3 shipped')
    expect(mail.message.getTopic()).toBe('announcements')
  })

  it('addBroadcastCredential rejects non-naddrs', () => {
    const transport = new FakeTransport()
    return makeClient(transport).then(({ client }) => {
      expect(() => client.addBroadcastCredential('npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l2y7f')).toThrow(TypeError)
    })
  })
})
