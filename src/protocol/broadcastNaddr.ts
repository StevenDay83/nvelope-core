/**
 * Broadcast subscription credentials (naddrs) and subscription filters.
 *
 * An naddr bundles everything a subscriber needs: the author's pubkey, the
 * list password (for deriving the decryption key), and the topic (for
 * client-side interest filtering). The identifier is JSON [password, topic].
 *
 * Privacy model (decided for the protocol): neither the password nor the
 * topic appears in any event tag. A relay sees only that a pubkey subscribes
 * to a given author's broadcasts.
 */
import { decode, naddrEncode } from 'nostr-tools/nip19'
import { LABEL_BROADCAST_MESSAGE, NVELOPE_EVENT_KIND } from '../constants.js'
import type { Hex256 } from '../types.js'
import { assertHex256 } from '../crypto/pow.js'

/** Everything encoded in a broadcast subscription naddr. */
export interface BroadcastCredential {
  /** The list author's npub (hex). */
  author: Hex256
  /** List password; derives the AES key together with each event's salt. */
  password: string
  /** Client-side interest filter; matched against the decrypted body. */
  topic: string
}

/**
 * Encode a broadcast credential as an naddr (bech32). Hand this string to
 * subscribers; they store it and use it to find, decrypt, and filter the list.
 */
export function encodeBroadcastNaddr(credential: BroadcastCredential): string {
  assertHex256(credential.author, 'author')
  assertNonEmptyString(credential.password, 'password')
  assertNonEmptyString(credential.topic, 'topic')
  return naddrEncode({
    kind: NVELOPE_EVENT_KIND,
    pubkey: credential.author,
    identifier: JSON.stringify([credential.password, credential.topic]),
  })
}

/**
 * Decode and validate a broadcast naddr.
 *
 * @throws {TypeError} if the input is not a kind-8500 naddr with a
 *   well-formed [password, topic] identifier.
 */
export function decodeBroadcastNaddr(naddr: string): BroadcastCredential {
  let decoded: { type: string; data: unknown }
  try {
    decoded = decode(naddr) as { type: string; data: unknown }
  } catch {
    throw new TypeError('Invalid bech32: expected an naddr')
  }
  if (decoded.type !== 'naddr') {
    throw new TypeError(`Expected an naddr, got: ${decoded.type}`)
  }
  const data = decoded.data as { kind?: unknown; pubkey?: unknown; identifier?: unknown }
  if (data.kind !== NVELOPE_EVENT_KIND) {
    throw new TypeError(`Expected naddr kind ${NVELOPE_EVENT_KIND}, got: ${JSON.stringify(data.kind)}`)
  }
  assertHex256(data.pubkey, 'naddr pubkey')

  if (typeof data.identifier !== 'string') {
    throw new TypeError('naddr identifier must be a string')
  }
  let parts: unknown
  try {
    parts = JSON.parse(data.identifier)
  } catch {
    throw new TypeError('naddr identifier is not valid JSON')
  }
  if (
    !Array.isArray(parts) ||
    parts.length !== 2 ||
    !parts.every((part) => typeof part === 'string')
  ) {
    throw new TypeError('naddr identifier must be JSON [password, topic]')
  }
  const [password, topic] = parts as [string, string]
  return { author: data.pubkey, password, topic }
}

/** A relay filter matching all broadcast envelopes from the given author(s). */
export interface BroadcastFilter {
  kinds: number[]
  authors: string[]
  '#l': string[]
  since?: number
}

/**
 * Build the subscription filter for an author's broadcast lists. Topic and
 * password filtering happen client-side after decryption — the relay learns
 * nothing about which lists a subscriber reads.
 */
export function createBroadcastFilter(
  author: Hex256 | Hex256[],
  options: { since?: number } = {},
): BroadcastFilter {
  const authors = Array.isArray(author) ? author : [author]
  for (const a of authors) {
    assertHex256(a, 'author')
  }
  const filter: BroadcastFilter = {
    kinds: [NVELOPE_EVENT_KIND],
    authors,
    '#l': [LABEL_BROADCAST_MESSAGE],
  }
  if (options.since !== undefined) {
    filter.since = options.since
  }
  return filter
}

function assertNonEmptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`)
  }
}
