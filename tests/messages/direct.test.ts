import { describe, expect, it } from 'vitest'
import { DirectMessage, encodeBase64 } from '../../src/index.js'

const FROM = 'a'.repeat(64)
const TO1 = 'b'.repeat(64)
const TO2 = 'c'.repeat(64)
const CC = 'd'.repeat(64)
const BCC = 'e'.repeat(64)
const REPLY = 'f'.repeat(64)

function buildFullMessage(): DirectMessage {
  return new DirectMessage()
    .setFrom(FROM)
    .addRecipientTo(TO1)
    .addRecipientTo(TO2)
    .addCc(CC)
    .addBcc(BCC)
    .setSubject('Quarterly report')
    .setReplyTo(REPLY)
    .setThreadId('thread-42')
    .addExternalReference('invoice', 'INV-2026-001')
    .setPlaintext('Hello there')
    .setMarkdown('# Hello there')
}

describe('DirectMessage wire format', () => {
  it('locks the exact wire shape of an empty message', () => {
    expect(new DirectMessage().toWire()).toEqual({
      mailToList: [],
      mailFrom: '',
      ccList: [],
      subjectLine: '',
      messageType: {},
      external_references: [],
      thread_id: '',
    })
  })

  it('serializes a full message with base64 content on the wire', () => {
    const wire = buildFullMessage().toWire()
    expect(wire).toEqual({
      mailToList: [TO1, TO2],
      mailFrom: FROM,
      ccList: [CC],
      replyTo: REPLY,
      subjectLine: 'Quarterly report',
      messageType: {
        plaintext: encodeBase64('Hello there'),
        md: encodeBase64('# Hello there'),
      },
      external_references: [['invoice', 'INV-2026-001']],
      thread_id: 'thread-42',
    })
  })

  it('omits replyTo from the wire when unset', () => {
    const wire = new DirectMessage().setFrom(FROM).toWire()
    expect(wire).not.toHaveProperty('replyTo')
  })
})

describe('DirectMessage round-trips', () => {
  it('fromWire(toWire()) is stable and restores all fields', () => {
    const original = buildFullMessage()
    const imported = DirectMessage.fromWire(original.toWire())

    expect(imported.toWire()).toEqual(original.toWire())
    expect(imported.getFrom()).toBe(FROM)
    expect(imported.getRecipientsTo()).toEqual([TO1, TO2])
    expect(imported.getCcList()).toEqual([CC])
    // The in-memory model retains the BCC list for the sender's own records…
    expect(original.getBccList()).toEqual([BCC])
    // …but the wire body never carries it (that secrecy IS BCC); a wire
    // round-trip therefore cannot restore it.
    expect(imported.getBccList()).toEqual([])
    expect(imported.getSubject()).toBe('Quarterly report')
    expect(imported.getReplyTo()).toBe(REPLY)
    expect(imported.getThreadId()).toBe('thread-42')
    expect(imported.getPlaintext()).toBe('Hello there')
    expect(imported.getMarkdown()).toBe('# Hello there')
    expect(imported.getExternalReferences()).toEqual([['invoice', 'INV-2026-001']])
  })

  it('imports from a JSON string (as stored inside an envelope)', () => {
    const json = buildFullMessage().toJson()
    const imported = DirectMessage.fromWire(json)
    expect(imported.getSubject()).toBe('Quarterly report')
    expect(imported.getPlaintext()).toBe('Hello there')
  })

  it('round-trips UTF-8 content', () => {
    const message = new DirectMessage().setFrom(FROM).addRecipientTo(TO1).setPlaintext('café ✓')
    const imported = DirectMessage.fromWire(message.toWire())
    expect(imported.getPlaintext()).toBe('café ✓')
  })

  it('rejects malformed imports early', () => {
    expect(() => DirectMessage.fromWire('{not json')).toThrow(TypeError)
    expect(() => DirectMessage.fromWire('[]')).toThrow(TypeError)
    expect(() => DirectMessage.fromWire('42')).toThrow(TypeError)
    expect(() =>
      DirectMessage.fromWire({ messageType: { plaintext: '!!!' } }),
    ).toThrow(TypeError)
  })
})

describe('BCC handling', () => {
  it('getWireMessages gives To/CC the shared body and BCC a private bccTo copy', () => {
    const message = buildFullMessage()
    const shared = message.toWire()
    expect(shared).not.toHaveProperty('bccTo')

    const messages = message.getWireMessages()
    expect(messages).toEqual([
      { recipient: TO1, message: shared },
      { recipient: TO2, message: shared },
      { recipient: CC, message: shared },
      { recipient: BCC, message: { ...shared, bccTo: BCC } },
    ])
  })

  it('returned wire objects are fresh copies (mutation does not corrupt the model)', () => {
    const message = buildFullMessage()
    const messages = message.getWireMessages()
    for (const entry of messages) {
      entry.message.mailToList?.push('x'.repeat(64))
      entry.message.ccList?.push('y'.repeat(64))
    }
    expect(message.getRecipientsTo()).toEqual([TO1, TO2])
    expect(message.getCcList()).toEqual([CC])
  })

  it('toWireForBccRecipient validates the recipient', () => {
    const message = buildFullMessage()
    expect(() => message.toWireForBccRecipient(TO1)).toThrow(RangeError) // not in BCC list
    expect(() => message.toWireForBccRecipient('not-hex')).toThrow(TypeError)
  })

  it('import maps bccTo into the recipient list after the visible recipients', () => {
    const imported = DirectMessage.fromWire(buildFullMessage().toWireForBccRecipient(BCC))
    // The BCC recipient sees the public To/CC recipients and is appended
    // themselves — exactly like reading a BCC'd email.
    expect(imported.getRecipientsTo()).toEqual([TO1, TO2, BCC])
    expect(imported.getCcList()).toEqual([CC])
  })
})

describe('regressions from the pre-refactor implementation', () => {
  it('setReplyTo sets replyTo, not mailFrom', () => {
    const message = new DirectMessage().setFrom(FROM).setReplyTo(REPLY)
    expect(message.getFrom()).toBe(FROM)
    expect(message.getReplyTo()).toBe(REPLY)
    const wire = message.toWire()
    expect(wire.mailFrom).toBe(FROM)
    expect(wire.replyTo).toBe(REPLY)
  })

  it('removeCc, removeBcc, and index-0 recipient removal all work', () => {
    const message = new DirectMessage()
      .addRecipientTo(TO1)
      .addRecipientTo(TO2)
      .addCc(CC)
      .addBcc(BCC)

    expect(message.removeCc(CC)).toBe(true)
    expect(message.getCcList()).toEqual([])
    expect(message.removeBcc(BCC)).toBe(true)
    expect(message.getBccList()).toEqual([])
    expect(message.removeRecipientTo(TO1)).toBe(true) // was at index 0
    expect(message.getRecipientsTo()).toEqual([TO2])
    expect(message.removeRecipientTo(TO1)).toBe(false) // already gone
  })

  it('getPlaintext returns the stored content', () => {
    const message = new DirectMessage().setPlaintext('hi')
    expect(message.getPlaintext()).toBe('hi')
  })

  it('duplicate recipients are ignored', () => {
    const message = new DirectMessage().addRecipientTo(TO1).addRecipientTo(TO1)
    expect(message.getRecipientsTo()).toEqual([TO1])
  })
})

describe('validation', () => {
  it('rejects non-hex npubs', () => {
    const message = new DirectMessage()
    expect(() => message.setFrom('not-hex')).toThrow(TypeError)
    expect(() => message.addRecipientTo('a'.repeat(63))).toThrow(TypeError)
    expect(() => message.setReplyTo('z'.repeat(64))).toThrow(TypeError)
  })

  it('removeExternalReference honors bounds', () => {
    const message = new DirectMessage().addExternalReference('a', '1').addExternalReference('b', '2')
    expect(message.removeExternalReference(5)).toBe(false)
    expect(message.removeExternalReference(-1)).toBe(false)
    expect(message.removeExternalReference(0)).toBe(true)
    expect(message.getExternalReferences()).toEqual([['b', '2']])
  })
})
