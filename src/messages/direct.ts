/**
 * DirectMessage — the Nostr-Mail direct message model.
 *
 * Wire format (locked by tests): toWire() reproduces the JSON shape of the
 * pre-refactor `generateEmailMessage()`:
 *
 *   { mailToList, mailFrom, ccList, replyTo?, subjectLine, messageType,
 *     external_references, thread_id, bccTo? }
 *
 * `replyTo` is omitted when unset; `bccTo` appears only on the per-recipient
 * copy generated for a BCC recipient and never in the shared body. Import maps
 * a present `bccTo` into the recipient list (a BCC recipient sees the mail as
 * addressed to them), matching the old event import.
 *
 * Fixes versus the pre-refactor DirectMessage:
 * - setReplyTo() corrupted mailFrom (it assigned to the wrong field).
 * - removeRecipientTo()/removeCCTo()/removeBCCTo() all searched the To-list, so
 *   CC/BCC removal never worked and index-0 removals were silently skipped.
 * - getContentPlaintext() never returned its value.
 */
import {
  CONTENT_TYPE_HTML,
  CONTENT_TYPE_MARKDOWN,
  CONTENT_TYPE_PLAINTEXT,
  DIRECT_MESSAGE_FIELDS as F,
} from '../constants.js'
import type {
  DirectMessageWire,
  ExternalReferenceWire,
  Hex256,
  MessageTypeWire,
} from '../types.js'
import { assertHex256 } from '../crypto/pow.js'
import { MessageContent, parseWireJson } from './content.js'
import type { MessageContentFormat } from './content.js'

/** A wire message destined for one specific recipient. */
export interface DirectWireMessage {
  /** Recipient this copy will be encrypted for. */
  recipient: Hex256
  /**
   * The wire message. Identical to the shared body for To/CC recipients;
   * carries `bccTo` only for BCC recipients. Treat as immutable.
   */
  message: DirectMessageWire
}

export class DirectMessage {
  private content: MessageContent = new MessageContent()
  private replyTo = ''
  private subjectLine = ''
  private mailFrom = ''
  private readonly mailToList: string[] = []
  private readonly ccList: string[] = []
  private readonly bccList: string[] = []
  private readonly externalReferences: ExternalReferenceWire[] = []
  private threadId = ''

  /* ------------------------------------------------------------------ */
  /* Sender and recipients (64-char hex npubs)                           */
  /* ------------------------------------------------------------------ */

  setFrom(npub: Hex256): this {
    assertHex256(npub, 'mailFrom')
    this.mailFrom = npub
    return this
  }

  getFrom(): string {
    return this.mailFrom
  }

  /** Add a primary recipient. Duplicates are ignored. */
  addRecipientTo(npub: Hex256): this {
    assertHex256(npub, 'recipient')
    if (!this.mailToList.includes(npub)) {
      this.mailToList.push(npub)
    }
    return this
  }

  /** @returns true if the recipient was present and removed. */
  removeRecipientTo(npub: Hex256): boolean {
    return removeFrom(this.mailToList, npub)
  }

  getRecipientsTo(): string[] {
    return [...this.mailToList]
  }

  /** Add a CC recipient. Duplicates are ignored. */
  addCc(npub: Hex256): this {
    assertHex256(npub, 'cc recipient')
    if (!this.ccList.includes(npub)) {
      this.ccList.push(npub)
    }
    return this
  }

  /** @returns true if the recipient was present and removed. */
  removeCc(npub: Hex256): boolean {
    return removeFrom(this.ccList, npub)
  }

  getCcList(): string[] {
    return [...this.ccList]
  }

  /**
   * Add a BCC recipient. The BCC list is never serialized into the shared
   * body; each BCC recipient gets a private copy carrying `bccTo`.
   */
  addBcc(npub: Hex256): this {
    assertHex256(npub, 'bcc recipient')
    if (!this.bccList.includes(npub)) {
      this.bccList.push(npub)
    }
    return this
  }

  /** @returns true if the recipient was present and removed. */
  removeBcc(npub: Hex256): boolean {
    return removeFrom(this.bccList, npub)
  }

  getBccList(): string[] {
    return [...this.bccList]
  }

  /* ------------------------------------------------------------------ */
  /* Headers                                                             */
  /* ------------------------------------------------------------------ */

  setSubject(subject: string): this {
    assertString(subject, 'subjectLine')
    this.subjectLine = subject
    return this
  }

  getSubject(): string {
    return this.subjectLine
  }

  /**
   * Reply address (npub), the SMTP Reply-To analog: the npub clients should
   * address replies to, which may differ from mailFrom (e.g. mail sent from
   * one key with replies directed elsewhere). Threading uses thread_id.
   */
  setReplyTo(replyAddress: Hex256): this {
    assertHex256(replyAddress, 'replyTo')
    this.replyTo = replyAddress
    return this
  }

  getReplyTo(): string {
    return this.replyTo
  }

  setThreadId(threadId: string): this {
    assertString(threadId, 'thread_id')
    this.threadId = threadId
    return this
  }

  getThreadId(): string {
    return this.threadId
  }

  /* ------------------------------------------------------------------ */
  /* External references                                                 */
  /* ------------------------------------------------------------------ */

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

  /* ------------------------------------------------------------------ */
  /* Content                                                             */
  /* ------------------------------------------------------------------ */

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

  /** Remove one format from the body. @returns true if it was present. */
  removeContent(format: MessageContentFormat): boolean {
    return this.content.remove(format)
  }

  /** Formats with content, in insertion order. */
  getContentFormats(): string[] {
    return this.content.getFormats()
  }

  /* ------------------------------------------------------------------ */
  /* Wire format                                                         */
  /* ------------------------------------------------------------------ */

  /** Serialize to the shared wire message (no bccTo — safe for To/CC copies). */
  toWire(): DirectMessageWire {
    const wire: DirectMessageWire = {
      [F.mailToList]: [...this.mailToList],
      [F.mailFrom]: this.mailFrom,
      [F.ccList]: [...this.ccList],
      [F.subjectLine]: this.subjectLine,
      [F.messageType]: this.content.toWire(),
      [F.externalReferences]: this.externalReferences.map((reference) => [...reference]),
      [F.threadId]: this.threadId,
    }
    if (this.replyTo.length > 0) {
      wire[F.replyTo] = this.replyTo
    }
    return wire
  }

  /** Serialize to the private wire copy for one BCC recipient (adds bccTo). */
  toWireForBccRecipient(bccRecipient: Hex256): DirectMessageWire {
    assertHex256(bccRecipient, 'bccRecipient')
    if (!this.bccList.includes(bccRecipient)) {
      throw new RangeError('npub is not in the BCC list of this message')
    }
    return { ...this.toWire(), [F.bccTo]: bccRecipient }
  }

  /**
   * Build the per-recipient wire messages ready for envelope encryption:
   * one copy each for every To/CC recipient (identical shared body) and one
   * private copy per BCC recipient (body + bccTo).
   */
  getWireMessages(): DirectWireMessage[] {
    const messages: DirectWireMessage[] = []
    for (const recipient of [...this.mailToList, ...this.ccList]) {
      messages.push({ recipient, message: this.toWire() })
    }
    for (const recipient of this.bccList) {
      messages.push({ recipient, message: this.toWireForBccRecipient(recipient) })
    }
    return messages
  }

  /**
   * Import a wire message (object or JSON string). A present `bccTo` is mapped
   * into the recipient list, matching the pre-refactor event import.
   *
   * @throws {TypeError} on malformed JSON, non-object input, or undecodable
   *   base64 content.
   */
  static fromWire(wire: DirectMessageWire | string): DirectMessage {
    const parsed: DirectMessageWire =
      typeof wire === 'string' ? (parseWireJson(wire) as DirectMessageWire) : wire
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new TypeError('Direct message wire content must be an object')
    }

    const message = new DirectMessage()
    if (typeof parsed.mailFrom === 'string') message.mailFrom = parsed.mailFrom
    if (typeof parsed.subjectLine === 'string') message.subjectLine = parsed.subjectLine
    if (typeof parsed.replyTo === 'string') message.replyTo = parsed.replyTo
    if (typeof parsed.thread_id === 'string') message.threadId = parsed.thread_id

    for (const npub of asStringArray(parsed.mailToList)) message.addRecipientTo(npub)
    for (const npub of asStringArray(parsed.ccList)) message.addCc(npub)
    for (const npub of asStringArray(parsed.bccList)) message.addBcc(npub)
    // A BCC recipient sees the public recipients and is appended themselves
    // (matches the pre-refactor import order).
    if (typeof parsed.bccTo === 'string') message.addRecipientTo(parsed.bccTo)

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

  /** Convenience: the shared wire message as a JSON string. */
  toJson(): string {
    return JSON.stringify(this.toWire())
  }
}

function removeFrom(list: string[], npub: string): boolean {
  const index = list.indexOf(npub)
  if (index < 0) return false
  list.splice(index, 1)
  return true
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((item): item is string => typeof item === 'string')
}

function assertString(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string') {
    throw new TypeError(`${label} must be a string, got: ${typeof value}`)
  }
}
