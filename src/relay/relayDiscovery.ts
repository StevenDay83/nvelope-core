/**
 * Relay discovery — resolving WHICH relays to use for an npub.
 *
 * Same courtesy pattern as contacts.ts: the library core never resolves
 * relays itself; every send/scan/publish call takes an explicit relay list.
 * These fetchers provide baseline discovery for scripts and small clients;
 * sophisticated clients (e.g. nVelope-Client with cached NIP-65 data) pass
 * their own lists instead.
 *
 * USAGE:
 * - Publishing MAIL to someone: their READ relays (add your own + extras as
 *   a superset to obfuscate which relays are theirs — see unionRelays).
 * - Publishing your PROFILE: your WRITE relays.
 * - Scanning your inbox: your READ relays.
 *
 * HISTORY: pre-NIP-65, relay discovery read relay URLs from the kind-3
 * contact list's content (JSON object keys). NIP-65 superseded this with
 * kind 10002 relay list metadata (r tags, optional read/write marker).
 */
import { CONTACT_LIST_KIND } from './contacts.js'
import type { Hex256 } from '../types.js'
import type { NostrEvent } from '../protocol/events.js'
import type { Transport } from './transport.js'

export const RELAY_LIST_KIND_NIP65 = 10002

/** An npub's relay hints, split by direction. */
export interface RelayHints {
  /** Relays this npub reads from (where THEIR mail should be published). */
  read: string[]
  /** Relays this npub writes to (where THEIR profile/events appear first). */
  write: string[]
}

const RELAY_URL_PATTERN = /^wss?:\/\//

function isRelayUrl(value: unknown): value is string {
  return typeof value === 'string' && RELAY_URL_PATTERN.test(value)
}

function latestOfKind(events: NostrEvent[], kind: number): NostrEvent | undefined {
  let latest: NostrEvent | undefined
  for (const event of events) {
    if (event.kind !== kind) continue
    if (latest === undefined || event.created_at > latest.created_at) {
      latest = event
    }
  }
  return latest
}

/**
 * NIP-65 relay list metadata (kind 10002): r tags, optionally marked
 * "read" / "write"; unmarked relays count for both directions.
 */
export async function fetchRelaysNip65(
  transport: Transport,
  owner: Hex256,
  relays: string[],
): Promise<RelayHints> {
  const events = await transport.query({ kinds: [RELAY_LIST_KIND_NIP65], authors: [owner] }, relays)
  const event = latestOfKind(events, RELAY_LIST_KIND_NIP65)
  if (event === undefined) return { read: [], write: [] }

  const read: string[] = []
  const write: string[] = []
  for (const tag of event.tags) {
    if (tag[0] !== 'r' || !isRelayUrl(tag[1])) continue
    const url = tag[1]
    const marker = tag[2]
    if (marker === 'read') {
      read.push(url)
    } else if (marker === 'write') {
      write.push(url)
    } else {
      read.push(url)
      write.push(url)
    }
  }
  return { read, write }
}

/**
 * Legacy pre-NIP-65 discovery: relay URLs from the kind-3 contact list's
 * content — the JSON object's keys are relay URLs. Counts for both
 * directions (the old format had no read/write distinction).
 */
export async function fetchRelaysKind3Legacy(
  transport: Transport,
  owner: Hex256,
  relays: string[],
): Promise<RelayHints> {
  const events = await transport.query({ kinds: [CONTACT_LIST_KIND], authors: [owner] }, relays)
  const event = latestOfKind(events, CONTACT_LIST_KIND)
  if (event === undefined) return { read: [], write: [] }

  const found: string[] = []
  try {
    const content: unknown = JSON.parse(event.content)
    if (content !== null && typeof content === 'object' && !Array.isArray(content)) {
      for (const key of Object.keys(content)) {
        if (isRelayUrl(key)) {
          found.push(key)
        }
      }
    }
  } catch {
    // Unparseable content: no hints.
  }
  return { read: found, write: [...found] }
}

/**
 * Union of relay lists, deduplicated, order-preserving (first appearance
 * wins). Use it to build a publish superset — e.g. unionRelays(yourRelays,
 * recipientHints.read, extraObfuscationRelays) — so an observer cannot tell
 * which relays in the set actually matter to the recipient.
 */
export function unionRelays(...sets: Array<Iterable<string>>): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const set of sets) {
    for (const relay of set) {
      if (typeof relay !== 'string' || !RELAY_URL_PATTERN.test(relay)) continue
      if (seen.has(relay)) continue
      seen.add(relay)
      result.push(relay)
    }
  }
  return result
}
