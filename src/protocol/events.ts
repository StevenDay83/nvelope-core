/**
 * Kind-8500 event construction and verification helpers.
 *
 * A Nostr-Mail message exists on relays as a kind-8500 Nostr event. For direct
 * mail there are two: the INNER event (the actual message, signed by the
 * sender's nsec — never published directly) and the OUTER blinded envelope
 * (see blinded.ts). For broadcast mail there is one event, signed by the
 * author (never blinded: subscribers find lists by author).
 *
 * Signing here takes a raw nsec (Uint8Array), matching the pre-refactor code.
 * The Signer abstraction (Step 6) generalizes this for NIP-07/NIP-46.
 */
import { finalizeEvent, getEventHash, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { NVELOPE_EVENT_KIND } from '../constants.js'
import type { DirectMessageWire, Hex256 } from '../types.js'
import { DirectMessage } from '../messages/direct.js'

/** A finalized Nostr event (NIP-01). */
export interface NostrEvent {
  id: string
  pubkey: string
  created_at: number
  kind: number
  tags: string[][]
  content: string
  sig: string
}

/** The fields that go into an event id / signature (NIP-01 serialization). */
export interface UnsignedEvent {
  kind: number
  created_at: number
  tags: string[][]
  content: string
  pubkey?: string
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

/** Build an unsigned kind-8500 event skeleton (content defaults to ''). */
export function buildUnsignedEvent(input: {
  content?: string
  tags?: string[][]
  createdAt?: number
  kind?: number
}): UnsignedEvent {
  return {
    kind: input.kind ?? NVELOPE_EVENT_KIND,
    created_at: input.createdAt ?? nowSeconds(),
    tags: input.tags ?? [],
    content: input.content ?? '',
  }
}

/** Sign an unsigned event with a raw nsec. */
export function finalizeWithNsec(unsigned: UnsignedEvent, secretKey: Uint8Array): NostrEvent {
  return finalizeEvent(
    {
      kind: unsigned.kind,
      created_at: unsigned.created_at,
      tags: unsigned.tags,
      content: unsigned.content,
    },
    secretKey,
  ) as NostrEvent
}

/**
 * Verify a Nostr event: the id must match the content hash AND the signature
 * must be valid for that id. The id check is done explicitly because some
 * nostr-tools versions verify the signature only against the embedded id
 * without re-deriving it — which would accept content tampered after signing.
 */
export function verifyNostrEvent(event: NostrEvent): boolean {
  try {
    if (getEventHash(event) !== event.id) return false
    return verifyEvent(event)
  } catch {
    return false
  }
}

/** The pubkey (hex) corresponding to a raw nsec. */
export function publicKeyOf(secretKey: Uint8Array): Hex256 {
  return getPublicKey(secretKey)
}

/**
 * Create the INNER direct-message event: the signed kind-8500 event whose
 * content is the message wire JSON. Pass a DirectMessage, or a pre-built wire
 * object (e.g. a per-BCC-recipient copy from getWireMessages()).
 *
 * The inner event is never published directly — it is sealed inside a blinded
 * envelope (see blinded.ts).
 */
export function createDirectMessageEvent(
  message: DirectMessage | DirectMessageWire,
  secretKey: Uint8Array,
): NostrEvent {
  const wire = message instanceof DirectMessage ? message.toWire() : message
  return finalizeWithNsec(buildUnsignedEvent({ content: JSON.stringify(wire) }), secretKey)
}
