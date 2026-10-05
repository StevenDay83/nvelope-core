import { describe, expect, it } from 'vitest'
import {
  BroadcastMessage,
  deriveKeyFromPassword,
  encodeBase64,
  generateBroadcastKey,
} from '../../src/index.js'

const AUTHOR = 'a'.repeat(64)
const REPLY = 'b'.repeat(64)

function buildFullMessage(): BroadcastMessage {
  return new BroadcastMessage()
    .setAuthor(AUTHOR)
    .setTopic('outages')
    .setSubject('Scheduled maintenance')
    .setReplyTo(REPLY)
    .setPlaintext('The system will be down.')
    .addExternalReference('runbook', 'RB-17')
}

describe('BroadcastMessage wire format', () => {
  it('locks the exact wire shape of an empty message (replyTo always present, as "")', () => {
    // toStrictEqual: the pre-refactor quirk is that replyTo is serialized even
    // when unset — unlike direct messages, which omit it.
    expect(new BroadcastMessage().toWire()).toStrictEqual({
      broadcastMessageType: 0,
      replyTo: '',
      subjectLine: '',
      author: '',
      topic: '',
      messageType: {},
      external_references: [],
    })
  })

  it('serializes a full message with base64 content on the wire', () => {
    const wire = buildFullMessage().toWire()
    expect(wire).toEqual({
      broadcastMessageType: 0,
      replyTo: REPLY,
      subjectLine: 'Scheduled maintenance',
      author: AUTHOR,
      topic: 'outages',
      messageType: { plaintext: encodeBase64('The system will be down.') },
      external_references: [['runbook', 'RB-17']],
    })
  })
})

describe('BroadcastMessage round-trips', () => {
  it('fromWire(toWire()) is stable and restores all fields', () => {
    const original = buildFullMessage()
    const imported = BroadcastMessage.fromWire(original.toWire())

    expect(imported.toWire()).toEqual(original.toWire())
    expect(imported.getAuthor()).toBe(AUTHOR)
    expect(imported.getTopic()).toBe('outages')
    expect(imported.getSubject()).toBe('Scheduled maintenance')
    expect(imported.getReplyTo()).toBe(REPLY)
    expect(imported.getPlaintext()).toBe('The system will be down.')
    expect(imported.getExternalReferences()).toEqual([['runbook', 'RB-17']])
  })

  it('imports from a JSON string', () => {
    const imported = BroadcastMessage.fromWire(buildFullMessage().toJson())
    expect(imported.getTopic()).toBe('outages')
  })

  it('rejects malformed imports', () => {
    expect(() => BroadcastMessage.fromWire('{nope')).toThrow(TypeError)
    expect(() => BroadcastMessage.fromWire({ broadcastMessageType: 2 })).toThrow(RangeError)
  })
})

describe('broadcast type and validation', () => {
  it('accepts only the defined broadcast types', () => {
    const message = new BroadcastMessage()
    message.setBroadcastMessageType(1)
    expect(message.getBroadcastMessageType()).toBe(1)
    expect(() => message.setBroadcastMessageType(2)).toThrow(RangeError)
  })

  it('rejects non-hex author and replyTo', () => {
    const message = new BroadcastMessage()
    expect(() => message.setAuthor('nope')).toThrow(TypeError)
    expect(() => message.setReplyTo('nope')).toThrow(TypeError)
  })
})

describe('generateBroadcastKey', () => {
  it('derives key material from a passphrase (salt published, key secret)', () => {
    const material = generateBroadcastKey('topic password')
    expect(material.salt).toMatch(/^[0-9a-f]{64}$/)
    expect(material.key).toBeInstanceOf(Uint8Array)
    expect(material.key.length).toBe(32)

    // Same passphrase + salt reproduces the key (how subscribers decrypt).
    const recomputed = deriveKeyFromPassword('topic password', material.salt)
    expect(Buffer.from(recomputed).equals(Buffer.from(material.key))).toBe(true)
  })
})
