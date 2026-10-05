/**
 * Contact lists — resolved "allowed and muted keys" for policy evaluation.
 *
 * DESIGN: the library core (scanDirectInbox, RecipientPolicy.evaluate) only
 * ever sees `isContact(sender) => boolean`. Where that answer comes from is
 * the client's choice: nVelope-Client will manage its own cached contact
 * lists; the courtesy fetchers below cover kind 3 and NIP-51 for scripts and
 * smaller clients. Future contact-list NIPs only require a new fetcher
 * returning ContactList — the core does not change.
 *
 * SEMANTICS: isContact() is true only for keys that are allowed AND not
 * muted. A muted key loses contact privileges and falls back to the
 * untrusted policy category; hard denial remains the job of deny lists.
 *
 * EFFICIENCY: fetch once per batch/session and reuse the same instance —
 * evaluation against a payload of downloaded messages costs one Set lookup
 * each, with no further relay traffic.
 */
import { IDENTIFIER_TAG } from '../constants.js'
import type { Hex256 } from '../types.js'
import { isHex256 } from '../crypto/pow.js'
import type { NostrEvent } from '../protocol/events.js'
import type { Transport } from './transport.js'

export const CONTACT_LIST_KIND = 3
export const MUTE_LIST_KIND = 10000
export const CATEGORIZED_PEOPLE_LIST_KIND = 30000

/** A resolved contact view: allowed keys and muted keys. */
export class ContactList {
  private readonly allowed: Set<Hex256>
  private readonly muted: Set<Hex256>

  constructor(allowed: Iterable<Hex256> = [], muted: Iterable<Hex256> = []) {
    this.allowed = new Set([...allowed].filter((key) => isHex256(key)))
    this.muted = new Set([...muted].filter((key) => isHex256(key)))
  }

  /** True when the key is allowed and not muted. */
  isContact(pubkey: Hex256): boolean {
    return this.allowed.has(pubkey) && !this.muted.has(pubkey)
  }

  isMuted(pubkey: Hex256): boolean {
    return this.muted.has(pubkey)
  }

  get allowedCount(): number {
    return this.allowed.size
  }

  get mutedCount(): number {
    return this.muted.size
  }

  /** Union of two contact views (e.g. kind 3 + NIP-51 mute list). */
  merge(other: ContactList): ContactList {
    return new ContactList(
      [...this.allowed, ...other.allowed],
      [...this.muted, ...other.muted],
    )
  }

  /** An empty view: nobody is a contact. */
  static empty(): ContactList {
    return new ContactList()
  }
}

function latestByKind(events: NostrEvent[], kind: number): NostrEvent | undefined {
  let latest: NostrEvent | undefined
  for (const event of events) {
    if (event.kind !== kind) continue
    if (latest === undefined || event.created_at > latest.created_at) {
      latest = event
    }
  }
  return latest
}

function pubkeysFromPTags(event: NostrEvent): Hex256[] {
  const keys: Hex256[] = []
  for (const tag of event.tags) {
    if (tag[0] === 'p' && tag[1] !== undefined && isHex256(tag[1])) {
      keys.push(tag[1])
    }
  }
  return keys
}

/**
 * Courtesy fetcher: kind 3 contact lists (deprecated by newer NIPs but still
 * the most widely maintained). Reads the owner's latest kind-3 event: the
 * JSON content array plus p tags are treated as allowed keys. No mute
 * semantics exist in kind 3 — muted stays empty.
 */
export async function fetchKind3Contacts(
  transport: Transport,
  owner: Hex256,
  relays: string[],
): Promise<ContactList> {
  const events = await transport.query({ kinds: [CONTACT_LIST_KIND], authors: [owner] }, relays)
  const event = latestByKind(events, CONTACT_LIST_KIND)
  if (event === undefined) return ContactList.empty()

  const allowed: Hex256[] = pubkeysFromPTags(event)
  try {
    const content: unknown = JSON.parse(event.content)
    if (Array.isArray(content)) {
      for (const key of content) {
        if (typeof key === 'string' && isHex256(key)) {
          allowed.push(key)
        }
      }
    }
  } catch {
    // Unparseable content: fall back to p tags only.
  }
  return new ContactList(allowed)
}

/**
 * Courtesy fetcher: NIP-51 lists. The kind-10000 Mute List's p tags become
 * muted keys; kind-30000 Categorized People Lists' p tags become allowed
 * keys — restricted to `options.listNames` d tags when given (e.g.
 * ["friends"]), otherwise all people lists count.
 */
export async function fetchNip51Contacts(
  transport: Transport,
  owner: Hex256,
  relays: string[],
  options: { listNames?: string[] } = {},
): Promise<ContactList> {
  const wanted = options.listNames !== undefined ? new Set(options.listNames) : undefined

  const muteEvents = await transport.query({ kinds: [MUTE_LIST_KIND], authors: [owner] }, relays)
  const muteEvent = latestByKind(muteEvents, MUTE_LIST_KIND)
  const muted = muteEvent === undefined ? [] : pubkeysFromPTags(muteEvent)

  const peopleEvents = await transport.query(
    { kinds: [CATEGORIZED_PEOPLE_LIST_KIND], authors: [owner] },
    relays,
  )
  // Latest event per d tag.
  const byDTag = new Map<string, NostrEvent>()
  for (const event of peopleEvents) {
    if (event.kind !== CATEGORIZED_PEOPLE_LIST_KIND) continue
    let dTag: string | undefined
    for (const tag of event.tags) {
      if (tag[0] === IDENTIFIER_TAG) {
        dTag = tag[1]
        break
      }
    }
    if (dTag === undefined) continue
    if (wanted !== undefined && !wanted.has(dTag)) continue
    const existing = byDTag.get(dTag)
    if (existing === undefined || event.created_at > existing.created_at) {
      byDTag.set(dTag, event)
    }
  }
  const allowed: Hex256[] = []
  for (const event of byDTag.values()) {
    allowed.push(...pubkeysFromPTags(event))
  }

  return new ContactList(allowed, muted)
}

/** Either a lookup callback or a resolved ContactList (see CheckDirectInboxOptions). */
export type ContactSource = ((senderPubkey: Hex256) => boolean) | ContactList

/** Normalize a ContactSource into the plain callback the core expects. */
export function contactSourceToCallback(source: ContactSource | undefined): ((pk: Hex256) => boolean) | undefined {
  if (source === undefined) return undefined
  if (typeof source === 'function') return source
  return (pubkey: Hex256) => source.isContact(pubkey)
}
