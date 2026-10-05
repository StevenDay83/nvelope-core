import { beforeAll, describe, expect, it } from 'vitest'
import { generateSecretKey } from 'nostr-tools/pure'
import {
  BroadcastMessage,
  DirectMessage,
  createBroadcastEnvelopeEvent,
  createDirectEnvelopeEvent,
  envelopeLabel,
  envelopeMeetsPow,
  generateBroadcastKey,
  generateMailCertificate,
  getTagValue,
  openBroadcastMessage,
  openBroadcastMessageWithKey,
  openDirectEnvelope,
  openDirectMessage,
  publicKeyDerBase64ToPem,
  publicKeyOf,
  readDirectEnvelopeJson,
  readKeyInfo,
  sealDirectMessage,
  targetFromLeadingZeros,
  verifyEnvelopeSignature,
} from '../../src/index.js'
import type { NostrEvent } from '../../src/index.js'

const ALICE = 'a'.repeat(64)
const BOB = 'b'.repeat(64)
const CAROL = 'c'.repeat(64)
const DAVE = 'd'.repeat(64)

let aliceCertPem: string
let aliceCertPrivate: string
let senderKey: Uint8Array

beforeAll(() => {
  const aliceCert = generateMailCertificate()
  aliceCertPem = publicKeyDerBase64ToPem(aliceCert.publicKeyDerBase64)
  aliceCertPrivate = aliceCert.privateKeyPem
  senderKey = generateSecretKey()
})

function tagValues(event: NostrEvent, name: string): string[] {
  return event.tags.filter((tag) => tag[0] === name).map((tag) => tag[1] ?? '')
}

describe('createDirectEnvelopeEvent', () => {
  it('seals the inner event so only the recipient certificate can open it', async () => {
    const inner = JSON.stringify({ id: 'fake', kind: 8500, content: 'x' })
    const { event } = await createDirectEnvelopeEvent(inner, aliceCertPem)

    expect(event.kind).toBe(8500)
    expect(getTagValue(event, 'l')).toBe('direct_message')
    expect(getTagValue(event, 'nonce')).toMatch(/^[0-9]+$/)
    expect(verifyEnvelopeSignature(event)).toBe(true)

    const opened = readDirectEnvelopeJson(event, aliceCertPrivate)
    expect(opened).toBe(inner)
  })

  it('rejects an envelope whose inner event is not a valid signed kind-8500 event', async () => {
    const { event } = await createDirectEnvelopeEvent('{"id":"forged","kind":4}', aliceCertPem)
    expect(openDirectMessage(event, aliceCertPrivate)).toBeUndefined()
  })

  it('returns undefined for any other private key (scanning)', async () => {
    const otherCert = generateMailCertificate()
    const { event } = await createDirectEnvelopeEvent('{"inner":true}', aliceCertPem)
    expect(readDirectEnvelopeJson(event, otherCert.privateKeyPem)).toBeUndefined()
  })

  it('meets an easy PoW target when requested', async () => {
    const { event } = await createDirectEnvelopeEvent('{"inner":true}', aliceCertPem, {
      leadingZeros: 8,
    })
    expect(envelopeMeetsPow(event, targetFromLeadingZeros(8))).toBe(true)
    expect(envelopeMeetsPow(event, targetFromLeadingZeros(16))).toBe(false)
  })
})

describe('sealDirectMessage (end-to-end per recipient)', () => {
  it('seals one blinded envelope per recipient; BCC gets a private copy', async () => {
    const message = new DirectMessage()
      .setFrom(publicKeyOf(senderKey))
      .addRecipientTo(ALICE)
      .addRecipientTo(BOB)
      .addCc(CAROL)
      .addBcc(DAVE)
      .setSubject('All hands')
      .setPlaintext('meeting moved to 3pm')

    const bobCert = generateMailCertificate()
    const carolCert = generateMailCertificate()
    const daveCert = generateMailCertificate()

    const sealed = await sealDirectMessage(message, senderKey, {
      [ALICE]: aliceCertPem,
      [BOB]: publicKeyDerBase64ToPem(bobCert.publicKeyDerBase64),
      [CAROL]: publicKeyDerBase64ToPem(carolCert.publicKeyDerBase64),
      [DAVE]: publicKeyDerBase64ToPem(daveCert.publicKeyDerBase64),
    })

    expect(sealed).toHaveLength(4)
    expect(sealed.map((s) => s.recipient)).toEqual([ALICE, BOB, CAROL, DAVE])

    // Each envelope opens only for its own recipient.
    const eventsByRecipient = new Map(sealed.map((s) => [s.recipient, s.event]))
    const aliceEvent = eventsByRecipient.get(ALICE)
    const bobEvent = eventsByRecipient.get(BOB)
    const daveEvent = eventsByRecipient.get(DAVE)
    if (!aliceEvent || !bobEvent || !daveEvent) throw new Error('missing sealed envelope')

    const openedForAlice = openDirectMessage(aliceEvent, aliceCertPrivate)
    expect(openedForAlice?.getSubject()).toBe('All hands')
    expect(openedForAlice?.getPlaintext()).toBe('meeting moved to 3pm')
    expect(openedForAlice?.getRecipientsTo()).toEqual([ALICE, BOB])
    expect(openedForAlice?.getCcList()).toEqual([CAROL])

    const openedForDave = openDirectMessage(daveEvent, daveCert.privateKeyPem)
    expect(openedForDave?.getRecipientsTo()).toEqual([ALICE, BOB, DAVE]) // bccTo appended
    expect(openedForDave?.getCcList()).toEqual([CAROL])

    // Cross-opening fails.
    expect(openDirectMessage(aliceEvent, bobCert.privateKeyPem)).toBeUndefined()
  })

  it('uses a distinct throwaway pubkey per envelope (unlinkability)', async () => {
    const message = new DirectMessage()
      .setFrom(publicKeyOf(senderKey))
      .addRecipientTo(ALICE)
      .addRecipientTo(BOB)
      .setPlaintext('x')

    const bobCert = generateMailCertificate()
    const sealed = await sealDirectMessage(message, senderKey, {
      [ALICE]: aliceCertPem,
      [BOB]: publicKeyDerBase64ToPem(bobCert.publicKeyDerBase64),
    })

    const pubkeys = new Set(sealed.map((s) => s.event.pubkey))
    expect(pubkeys.size).toBe(2)
    // Neither envelope reveals the sender.
    expect(pubkeys.has(publicKeyOf(senderKey))).toBe(false)
  })

  it('throws when a recipient has no certificate', async () => {
    const message = new DirectMessage()
      .setFrom(publicKeyOf(senderKey))
      .addRecipientTo(ALICE)
      .setPlaintext('x')
    await expect(sealDirectMessage(message, senderKey, {})).rejects.toThrow(RangeError)
  })
})

describe('createBroadcastEnvelopeEvent (author-signed, key_info, private topics)', () => {
  it('encrypts for password holders and carries only salt+iv in key_info', async () => {
    const authorKey = generateSecretKey()
    const keyMaterial = generateBroadcastKey('list-password')
    const broadcast = new BroadcastMessage()
      .setAuthor(publicKeyOf(authorKey))
      .setTopic('announcements')
      .setSubject('v2 is live')
      .setPlaintext('read the changelog')

    const { event, keyInfo } = await createBroadcastEnvelopeEvent(broadcast, authorKey, keyMaterial, {
      leadingZeros: 8,
    })

    // Signed by the author (not blinded): subscribers find lists by author.
    expect(event.pubkey).toBe(publicKeyOf(authorKey))
    expect(verifyEnvelopeSignature(event)).toBe(true)
    expect(envelopeMeetsPow(event, targetFromLeadingZeros(8))).toBe(true)

    // Privacy: no topic or password anywhere in the event.
    expect(getTagValue(event, 'l')).toBe('broadcast_message')
    expect(event.content).not.toContain('announcements')
    expect(event.content).not.toContain('v2 is live')
    expect(tagValues(event, 't')).toEqual([])

    // key_info carries exactly the salt and iv.
    expect(keyInfo).toEqual(readKeyInfo(event))
    expect(keyInfo.salt).toMatch(/^[0-9a-f]{64}$/)
    expect(keyInfo.iv).toMatch(/^[0-9a-f]{32}$/)

    // Password path and cached-key path both open it.
    const opened = openBroadcastMessage(event, 'list-password')
    expect(opened?.getSubject()).toBe('v2 is live')
    expect(opened?.getTopic()).toBe('announcements')
    expect(openBroadcastMessage(event, 'wrong-password')).toBeUndefined()
    expect(openBroadcastMessageWithKey(event, keyMaterial.key)?.getPlaintext()).toBe(
      'read the changelog',
    )
  })

  it('produces a fresh IV per event under the same key', async () => {
    const authorKey = generateSecretKey()
    const keyMaterial = generateBroadcastKey('pw')
    const broadcast = new BroadcastMessage().setAuthor(publicKeyOf(authorKey)).setPlaintext('same')

    const first = await createBroadcastEnvelopeEvent(broadcast, authorKey, keyMaterial)
    const second = await createBroadcastEnvelopeEvent(broadcast, authorKey, keyMaterial)
    expect(first.event.content).not.toBe(second.event.content)
    expect(first.keyInfo.iv).not.toBe(second.keyInfo.iv)
  })
})

describe('inner event identity (Q1 semantics)', () => {
  it('exposes a stable innerEventId shared by all recipients of one message', async () => {
    const bobCert = generateMailCertificate()
    const carolCert = generateMailCertificate()
    const message = new DirectMessage()
      .setFrom(publicKeyOf(senderKey))
      .addRecipientTo(BOB)
      .addRecipientTo(CAROL)
      .setSubject('shared identity')
      .setPlaintext('x')

    const sealed = await sealDirectMessage(message, senderKey, {
      [BOB]: publicKeyDerBase64ToPem(bobCert.publicKeyDerBase64),
      [CAROL]: publicKeyDerBase64ToPem(carolCert.publicKeyDerBase64),
    })
    expect(sealed).toHaveLength(2)

    const byRecipient = new Map(sealed.map((s) => [s.recipient, s.event]))
    const bobEvent = byRecipient.get(BOB)
    const carolEvent = byRecipient.get(CAROL)
    if (!bobEvent || !carolEvent) throw new Error('missing envelope')

    // Distinct outer envelopes (unlinkable)…
    expect(bobEvent.id).not.toBe(carolEvent.id)
    expect(bobEvent.pubkey).not.toBe(carolEvent.pubkey)

    // …but ONE inner event: same stable identity for both recipients.
    const openedForBob = openDirectEnvelope(bobEvent, bobCert.privateKeyPem)
    const openedForCarol = openDirectEnvelope(carolEvent, carolCert.privateKeyPem)
    if (!openedForBob || !openedForCarol) throw new Error('open failed')
    expect(openedForBob.innerEventId).toHaveLength(64)
    expect(openedForBob.innerEventId).toBe(openedForCarol.innerEventId)
    expect(openedForBob.senderPubkey).toBe(publicKeyOf(senderKey))
    expect(typeof openedForBob.innerCreatedAt).toBe('number')
  })
})

describe('envelope reading helpers', () => {
  it('envelopeLabel reads the l tag', async () => {
    const { event } = await createDirectEnvelopeEvent('{"x":1}', aliceCertPem)
    expect(envelopeLabel(event)).toBe('direct_message')

    const noLabel: NostrEvent = { ...event, tags: [] }
    expect(envelopeLabel(noLabel)).toBeUndefined()
  })

  it('readKeyInfo rejects malformed key_info tags', () => {
    const base: NostrEvent = {
      id: '0'.repeat(64),
      pubkey: '1'.repeat(64),
      created_at: 0,
      kind: 8500,
      tags: [],
      content: '',
      sig: '2'.repeat(128),
    }
    expect(readKeyInfo(base)).toBeUndefined()
    expect(readKeyInfo({ ...base, tags: [['key_info', 'not json']] })).toBeUndefined()
    expect(
      readKeyInfo({ ...base, tags: [['key_info', JSON.stringify({ salt: 'zz', iv: '01'.repeat(16) })]] }),
    ).toBeUndefined()
    expect(
      readKeyInfo({ ...base, tags: [['key_info', JSON.stringify({ salt: 'ab'.repeat(32), iv: 'short' })]] }),
    ).toBeUndefined()
  })
})
