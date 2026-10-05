/**
 * Wire-format TypeScript types for Nostr-Mail.
 *
 * "Wire" means the exact JSON shapes stored on Nostr relays. These interfaces
 * must remain stable; the field-name constants live in constants.ts.
 */

/** A 64-character hex string: a Nostr public key or an event id. */
export type Hex256 = string

/** A single external reference on a message: `[referenceType, value, ...extra]`. */
export type ExternalReferenceWire = string[]

/** Map of body formats to base64-encoded content, as it appears on the wire. */
export interface MessageTypeWire {
  plaintext?: string
  md?: string
  html?: string
  /** Forward compatibility: formats added by future protocol versions. */
  [format: string]: string | undefined
}

/** Shape of the direct-message JSON object (encrypted inside a blinded envelope). */
export interface DirectMessageWire {
  mailFrom?: string
  mailToList?: string[]
  ccList?: string[]
  /** Reply address npub (SMTP Reply-To analog); may differ from mailFrom. */
  replyTo?: string
  subjectLine?: string
  messageType?: MessageTypeWire
  external_references?: ExternalReferenceWire[]
  /** Opaque conversation key (client-side threading; encrypted at rest). */
  thread_id?: string
  /**
   * Present only on the per-recipient copy generated for a BCC recipient.
   * The shared body never contains the bcc list.
   */
  bccTo?: string
  /** Never serialized by this library; tolerated on import for robustness. */
  bccList?: string[]
}

/** Shape of the broadcast-message JSON object. */
export interface BroadcastMessageWire {
  broadcastMessageType: number
  replyTo?: string
  subjectLine?: string
  author?: Hex256
  topic?: string
  messageType?: MessageTypeWire
  external_references?: ExternalReferenceWire[]
}

/** Key material metadata attached to broadcast events (value of the `key_info` tag). */
export interface KeyInfoWire {
  salt: string
  iv: string
}

/**
 * Proof-of-work requirement for a policy group. `target` (64-char hex) and
 * `leadingzeros` are mutually exclusive; `leadingzeros` counts leading zero
 * HEX DIGITS (4 bits each) in the event id.
 */
export interface PowPolicyWire {
  target?: string
  leadingzeros?: number
}

export interface AllowPolicyWire {
  contacts?: PowPolicyWire
  list?: Record<Hex256, PowPolicyWire>
  untrusted?: PowPolicyWire
}

export interface DenyPolicyWire {
  list?: Hex256[]
  contacts?: boolean
  untrusted?: boolean
}

/** Shape of the recipient-policy JSON object published in the mail profile. */
export interface RecipientPolicyWire {
  allow?: AllowPolicyWire
  deny?: DenyPolicyWire
  global_minimum?: PowPolicyWire
}
