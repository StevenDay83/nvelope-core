/**
 * BroadcastMessage — the Nostr-Mail broadcast (topic-based, passphrase-keyed)
 * message model.
 *
 * Wire format (locked by tests): toWire() reproduces the JSON shape of the
 * pre-refactor `generateBroadcastMessageObject()`:
 *
 *   { broadcastMessageType, replyTo, subjectLine, author, topic,
 *     messageType, external_references }
 *
 * Note the pre-refactor quirk preserved here: `replyTo` is ALWAYS present —
 * as an empty string when unset (unlike direct messages, which omit it).
 *
 * Open design question (deferred from the pre-refactor code): the old
 * naddr/subscription helpers never actually worked — `neventEncode` was called
 * with fields it ignores (so the password/topic never made it on the wire) and
 * the subscription filter matched an '#a' tag that broadcast events never
 * carried. Broadcast discovery/addressing is revisited in the protocol layer
 * (Step 4); this module deliberately models the message body only.
 */
import {
  BROADCAST_MESSAGE_FIELDS as F,
  BROADCAST_TYPE_DEFAULT,
  BROADCAST_TYPE_LIST_SERVE,
  CONTENT_TYPE_HTML,
  CONTENT_TYPE_MARKDOWN,
  CONTENT_TYPE_PLAINTEXT,
} from '../constants.js'
import type { BroadcastMessageWire, ExternalReferenceWire, Hex256, MessageTypeWire } from '../types.js'
import { assertHex256 } from '../crypto/pow.js'
import { deriveKeyFromPassword, generateSalt } from '../crypto/symmetric.js'
import { MessageContent, parseWireJson } from './content.js'
import type { MessageContentFormat } from './content.js'

/** Passphrase-derived key material for publishing to a broadcast topic. */
export interface BroadcastKeyMaterial {
  /** 64-hex-char (32-byte) scrypt salt — published in the event's `key_info` tag. */
  salt: string
  /** 32-byte AES key derived from the passphrase and salt. Keep secret. */
  key: Uint8Array
}

/**
 * Derive broadcast key material from a passphrase. The same passphrase + salt
 * always reproduces the same key (scrypt), which is how subscribers decrypt.
 * A fresh IV per message is handled at encryption time (see symmetric.ts).
 */
export function generateBroadcastKey(password: string): BroadcastKeyMaterial {
  const salt = generateSalt()
  return { salt, key: deriveKeyFromPassword(password, salt) }
}

export class BroadcastMessage {
  private broadcastMessageType = BROADCAST_TYPE_DEFAULT
  private replyTo = ''
  private subjectLine = ''
  private author = ''
  private topic = ''
  private content: MessageContent = new MessageContent()
  private readonly externalReferences: ExternalReferenceWire[] = []

  /** 0 = allow all, 1 = list-serve (see BROADCAST_TYPE_* constants). */
  setBroadcastMessageType(type: number): this {
    if (type !== BROADCAST_TYPE_DEFAULT && type !== BROADCAST_TYPE_LIST_SERVE) {
      throw new RangeError(`broadcastMessageType must be ${BROADCAST_TYPE_DEFAULT} or ${BROADCAST_TYPE_LIST_SERVE}, got: ${type}`)
    }
    this.broadcastMessageType = type
    return this
  }

  getBroadcastMessageType(): number {
    return this.broadcastMessageType
  }

  /** Event-id reference (64-char hex) of the broadcast being replied to. */
  setReplyTo(eventId: Hex256): this {
    assertHex256(eventId, 'replyTo')
    this.replyTo = eventId
    return this
  }

  getReplyTo(): string {
    return this.replyTo
  }

  setSubject(subject: string): this {
    assertString(subject, 'subjectLine')
    this.subjectLine = subject
    return this
  }

  getSubject(): string {
    return this.subjectLine
  }

  /** Author npub (64-char hex). */
  setAuthor(npub: Hex256): this {
    assertHex256(npub, 'author')
    this.author = npub
    return this
  }

  getAuthor(): string {
    return this.author
  }

  setTopic(topic: string): this {
    assertString(topic, 'topic')
    this.topic = topic
    return this
  }

  getTopic(): string {
    return this.topic
  }

  addExternalReference(referenceType: string, value: string): this {
    assertString(referenceType, 'reference type')
    assertString(value, 'reference value')
    this.externalReferences.push([referenceType, value])
    return this
  }

  /** @returns true if a reference at that index existed and was removed. */
  removeExternalReference(index: number): boolean {
    if (!Number.isInteger(index) || index < 0 || index >= this.externalReferences.length) {
      return false
    }
    this.externalReferences.splice(index, 1)
    return true
  }

  getExternalReferences(): ExternalReferenceWire[] {
    return this.externalReferences.map((reference) => [...reference])
  }

  /** The underlying multi-format body (plaintext / md / html / future formats). */
  readonly contentModel: MessageContent = this.content

  setPlaintext(text: string): this {
    this.content.set(CONTENT_TYPE_PLAINTEXT, text)
    return this
  }

  getPlaintext(): string {
    return this.content.get(CONTENT_TYPE_PLAINTEXT) ?? ''
  }

  setMarkdown(text: string): this {
    this.content.set(CONTENT_TYPE_MARKDOWN, text)
    return this
  }

  getMarkdown(): string {
    return this.content.get(CONTENT_TYPE_MARKDOWN) ?? ''
  }

  setHtml(text: string): this {
    this.content.set(CONTENT_TYPE_HTML, text)
    return this
  }

  getHtml(): string {
    return this.content.get(CONTENT_TYPE_HTML) ?? ''
  }

  removeContent(format: MessageContentFormat): boolean {
    return this.content.remove(format)
  }

  getContentFormats(): string[] {
    return this.content.getFormats()
  }

  /** Serialize to the wire message. `replyTo` is always present ("" when unset). */
  toWire(): BroadcastMessageWire {
    return {
      [F.broadcastMessageType]: this.broadcastMessageType,
      [F.replyTo]: this.replyTo,
      [F.subjectLine]: this.subjectLine,
      [F.author]: this.author,
      [F.topic]: this.topic,
      [F.messageType]: this.content.toWire(),
      [F.externalReferences]: this.externalReferences.map((reference) => [...reference]),
    }
  }

  /** Import a wire message (object or JSON string). */
  static fromWire(wire: BroadcastMessageWire | string): BroadcastMessage {
    // The fields are validated individually below; the double cast is the
    // honest way to say "parsed JSON, checked by hand".
    const parsed: BroadcastMessageWire =
      typeof wire === 'string' ? (parseWireJson(wire) as unknown as BroadcastMessageWire) : wire
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new TypeError('Broadcast message wire content must be an object')
    }

    const message = new BroadcastMessage()
    if (typeof parsed.broadcastMessageType === 'number') {
      message.setBroadcastMessageType(parsed.broadcastMessageType)
    }
    if (typeof parsed.replyTo === 'string') message.replyTo = parsed.replyTo
    if (typeof parsed.subjectLine === 'string') message.subjectLine = parsed.subjectLine
    if (typeof parsed.author === 'string') message.author = parsed.author
    if (typeof parsed.topic === 'string') message.topic = parsed.topic

    if (Array.isArray(parsed.external_references)) {
      for (const reference of parsed.external_references) {
        if (Array.isArray(reference) && reference.every((part) => typeof part === 'string')) {
          message.externalReferences.push(reference as ExternalReferenceWire)
        }
      }
    }

    const wireContent: MessageTypeWire | undefined =
      parsed.messageType !== null && typeof parsed.messageType === 'object'
        ? (parsed.messageType as MessageTypeWire)
        : undefined
    if (wireContent !== undefined) {
      message.content = MessageContent.fromWire(wireContent)
    }

    return message
  }

  /** Convenience: the wire message as a JSON string. */
  toJson(): string {
    return JSON.stringify(this.toWire())
  }
}

function assertString(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string') {
    throw new TypeError(`${label} must be a string, got: ${typeof value}`)
  }
}
