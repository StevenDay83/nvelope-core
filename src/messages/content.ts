/**
 * Shared multi-format message body handling — the `messageType` object on the
 * wire: { plaintext?: base64, md?: base64, html?: base64, ...future formats }.
 *
 * Values are base64-encoded UTF-8 on the wire (matching the pre-refactor
 * implementation). Empty-string content is stored but omitted from the wire,
 * exactly like the old code. Unknown formats are preserved on import for
 * forward compatibility with future protocol versions.
 */

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

/** Canonical formats plus any future format string (e.g. "latex"). */
export type MessageContentFormat = 'plaintext' | 'md' | 'html' | (string & {})

/** Base64-encode UTF-8 text (wire encoding for message bodies). */
export function encodeBase64(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64')
}

/** Decode and validate wire base64. @throws {TypeError} on malformed input. */
export function decodeBase64(base64: string): string {
  if (typeof base64 !== 'string' || !BASE64_PATTERN.test(base64)) {
    throw new TypeError('Invalid base64 message content')
  }
  return Buffer.from(base64, 'base64').toString('utf8')
}

/** Parse a JSON string into an object. @throws {TypeError} on malformed input. */
export function parseWireJson(text: string): Record<string, unknown> {
  if (typeof text !== 'string') throw new TypeError('Expected a JSON string')
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new TypeError('Invalid JSON wire content')
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new TypeError('Wire content must be a JSON object')
  }
  return parsed as Record<string, unknown>
}

/** A message body holding one text per format (plaintext/markdown/html/…). */
export class MessageContent {
  private readonly entries = new Map<string, string>()

  /** Set (or overwrite) the text for a format. Empty strings are stored but omitted from the wire. */
  set(format: MessageContentFormat, text: string): this {
    assertFormat(format)
    if (typeof text !== 'string') {
      throw new TypeError(`text must be a string, got: ${typeof text}`)
    }
    this.entries.set(format, text)
    return this
  }

  /** The text for a format, or undefined if not set. */
  get(format: MessageContentFormat): string | undefined {
    return this.entries.get(format)
  }

  has(format: MessageContentFormat): boolean {
    return this.entries.has(format)
  }

  remove(format: MessageContentFormat): boolean {
    return this.entries.delete(format)
  }

  /** All formats with content, in insertion order. */
  getFormats(): string[] {
    return [...this.entries.keys()]
  }

  get size(): number {
    return this.entries.size
  }

  isEmpty(): boolean {
    return this.entries.size === 0
  }

  /** Wire form: base64-encoded values (non-empty only). */
  toWire(): Record<string, string> {
    const wire: Record<string, string> = {}
    for (const [format, text] of this.entries) {
      if (text.length > 0) {
        wire[format] = encodeBase64(text)
      }
    }
    return wire
  }

  /**
   * Import from wire form, decoding base64. Unknown formats are preserved.
   *
   * @throws {TypeError} if the wire value is not an object or contains
   *   malformed base64 (early corruption detection for bad envelopes).
   */
  static fromWire(wire: unknown): MessageContent {
    if (wire === null || typeof wire !== 'object' || Array.isArray(wire)) {
      throw new TypeError('messageType must be an object')
    }
    const content = new MessageContent()
    for (const [format, base64] of Object.entries(wire)) {
      if (base64 === undefined) continue
      if (typeof base64 !== 'string') {
        throw new TypeError(`messageType.${format} must be a base64 string`)
      }
      assertFormat(format)
      content.entries.set(format, decodeBase64(base64))
    }
    return content
  }
}

function assertFormat(format: unknown): asserts format is string {
  if (typeof format !== 'string' || format.length === 0) {
    throw new TypeError('content format must be a non-empty string')
  }
}
