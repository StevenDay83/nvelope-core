import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  buildUnsignedEvent,
  createDirectMessageEvent,
  finalizeWithNsec,
  nowSeconds,
  publicKeyOf,
  verifyNostrEvent,
  DirectMessage,
} from '../../src/index.js'

describe('buildUnsignedEvent', () => {
  it('defaults to kind 8500 with empty tags', () => {
    const unsigned = buildUnsignedEvent({ content: '{}' })
    expect(unsigned.kind).toBe(8500)
    expect(unsigned.tags).toEqual([])
    expect(unsigned.content).toBe('{}')
    expect(unsigned.created_at).toBeGreaterThan(0)
  })

  it('accepts overrides', () => {
    const unsigned = buildUnsignedEvent({
      content: 'x',
      tags: [['l', 'direct_message']],
      createdAt: 1234567890,
    })
    expect(unsigned.created_at).toBe(1234567890)
    expect(unsigned.tags).toEqual([['l', 'direct_message']])
  })
})

describe('finalizeWithNsec / verifyNostrEvent', () => {
  it('produces a verifiable event with the matching pubkey', () => {
    const secretKey = generateSecretKey()
    const event = finalizeWithNsec(buildUnsignedEvent({ content: 'hi' }), secretKey)

    expect(event.pubkey).toBe(getPublicKey(secretKey))
    expect(event.id).toHaveLength(64)
    expect(verifyNostrEvent(event)).toBe(true)
  })

  it('rejects a tampered event', () => {
    const event = finalizeWithNsec(buildUnsignedEvent({ content: 'hi' }), generateSecretKey())
    event.content = 'tampered'
    expect(verifyNostrEvent(event)).toBe(false)
  })

  it('publicKeyOf matches nostr-tools', () => {
    const secretKey = generateSecretKey()
    expect(publicKeyOf(secretKey)).toBe(getPublicKey(secretKey))
  })
})

describe('createDirectMessageEvent (inner event)', () => {
  it('creates a signed kind-8500 event whose content is the wire JSON', () => {
    const secretKey = generateSecretKey()
    const message = new DirectMessage()
      .setFrom(publicKeyOf(secretKey))
      .addRecipientTo('b'.repeat(64))
      .setSubject('Inner event test')
      .setPlaintext('body')

    const event = createDirectMessageEvent(message, secretKey)

    expect(event.kind).toBe(8500)
    expect(event.tags).toEqual([])
    expect(verifyNostrEvent(event)).toBe(true)

    const wire = JSON.parse(event.content)
    expect(wire.subjectLine).toBe('Inner event test')
    expect(DirectMessage.fromWire(wire).getPlaintext()).toBe('body')
  })

  it('accepts a pre-built wire object (per-BCC copies)', () => {
    const secretKey = generateSecretKey()
    const message = new DirectMessage().setFrom(publicKeyOf(secretKey)).addBcc('e'.repeat(64))
    const wire = message.toWireForBccRecipient('e'.repeat(64))

    const event = createDirectMessageEvent(wire, secretKey)
    expect(JSON.parse(event.content).bccTo).toBe('e'.repeat(64))
  })
})

describe('nowSeconds', () => {
  it('returns whole seconds', () => {
    expect(Number.isInteger(nowSeconds())).toBe(true)
  })
})
