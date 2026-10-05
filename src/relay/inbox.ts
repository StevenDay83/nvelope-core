/**
 * Inbox scanning: finding YOUR mail on relays.
 *
 * DIRECT: fetch all direct_message envelopes, drop those below your scan
 * target (your policy's GLOBAL MINIMUM — see RecipientPolicy.scanTarget),
 * verify, and try to decrypt each. Ones encrypted for your certificate open;
 * the rest are discarded silently — relays learn nothing about which
 * envelopes were yours. With the sender revealed, your policy is enforced
 * per sender (deny lists, category PoW vs the outer envelope id); failures
 * go to `rejected`, not `inbox`.
 *
 * BROADCAST: fetch broadcast envelopes from the authors you follow, try each
 * of your list passwords (keys cached per password+salt so scrypt runs once
 * per list, not per message), then keep only messages whose decrypted topic
 * matches a topic you subscribed to — "can read but doesn't care" is dropped
 * here, per the privacy-first design.
 */
import type { Filter } from 'nostr-tools'
import {
  LABEL_BROADCAST_MESSAGE,
  LABEL_DIRECT_MESSAGE,
  LABEL_TAG,
  NVELOPE_EVENT_KIND,
} from '../constants.js'
import type { Hex256 } from '../types.js'
import { deriveKeyFromPassword } from '../crypto/symmetric.js'
import {
  envelopeMeetsPow,
  openBroadcastMessageWithKey,
  openDirectEnvelope,
  readKeyInfo,
  verifyEnvelopeSignature,
} from '../protocol/blinded.js'
import type { NostrEvent } from '../protocol/events.js'
import type { DirectMessage } from '../messages/direct.js'
import type { BroadcastMessage } from '../messages/broadcast.js'
import type { RecipientPolicy } from '../profile/policy.js'
import type { BroadcastCredential } from '../protocol/broadcastNaddr.js'
import type { Transport } from './transport.js'

export interface ScannedDirectMail {
  /** The outer (blinded) envelope — a disposable, per-recipient artifact. */
  event: NostrEvent
  message: DirectMessage
  /** Verified sender of the inner event. */
  senderPubkey: Hex256
  /** Stable message identity for client storage (see OpenedDirectEnvelope). */
  innerEventId: Hex256
  /** Sender's authoritative timestamp. */
  innerCreatedAt: number
}

/** A decrypted envelope that failed post-decryption policy validation. */
export interface RejectedDirectMail {
  event: NostrEvent
  senderPubkey: Hex256
  reason: 'deny_list' | 'deny_contacts' | 'deny_untrusted' | 'insufficient_pow'
  /** For insufficient_pow: the target the envelope should have met. */
  requiredTarget?: string
}

export interface ScanDirectResult {
  /** Envelopes that passed every check (pre-filter, decrypt, validation). */
  inbox: ScannedDirectMail[]
  /** Envelopes decrypted for us but rejected by policy (see checkProfile). */
  rejected: RejectedDirectMail[]
}

export interface ScanDirectOptions {
  /** Your mail certificate private key (PEM). */
  privateKeyPem: string
  /**
   * Pre-decryption PoW filter: envelopes whose id fails this target are
   * discarded without decryption. Default: your policy's global minimum
   * (pass options explicitly to override).
   */
  targetFilter?: string
  /**
   * Your recipient policy, enforced POST-decryption: deny lists reject the
   * sender outright; the sender's category PoW requirement is weighed
   * against the OUTER envelope id (where the PoW was applied).
   */
  policy?: RecipientPolicy
  /**
   * Contact-list lookup for policy evaluation (the recipient knows their own
   * contacts). Without it, contact-based rules cannot match — provide it for
   * deny.contacts and contact-category policies to be enforced.
   */
  isContact?: (senderPubkey: Hex256) => boolean
  since?: number
  limit?: number
  signal?: AbortSignal
}

export async function scanDirectInbox(
  transport: Transport,
  relays: string[],
  options: ScanDirectOptions,
): Promise<ScanDirectResult> {
  const filter: Filter = {
    kinds: [NVELOPE_EVENT_KIND],
    [`#${LABEL_TAG}`]: [LABEL_DIRECT_MESSAGE],
  }
  if (options.since !== undefined) filter.since = options.since
  if (options.limit !== undefined) filter.limit = options.limit

  const events = await transport.query(filter, relays)
  const inbox: ScannedDirectMail[] = []
  const rejected: RejectedDirectMail[] = []

  for (const event of events) {
    if (options.signal?.aborted) break

    // 1. Pre-decryption: outer envelope id vs the global-minimum filter.
    if (options.targetFilter !== undefined && !envelopeMeetsPow(event, options.targetFilter)) {
      continue
    }

    // 2. Verify and attempt decryption — unknowable if it is for us until now.
    if (!verifyEnvelopeSignature(event)) continue
    const opened = openDirectEnvelope(event, options.privateKeyPem)
    if (opened === undefined) continue

    // 3. Post-decryption: the sender is known — enforce the specific policy
    //    against the OUTER envelope id where the PoW was applied.
    if (options.policy !== undefined) {
      const contact = options.isContact?.(opened.senderPubkey) ?? false
      const decision = options.policy.evaluate(opened.senderPubkey, contact)
      if (!decision.allowed) {
        rejected.push({ event, senderPubkey: opened.senderPubkey, reason: decision.reason })
        continue
      }
      if (!envelopeMeetsPow(event, decision.target)) {
        rejected.push({
          event,
          senderPubkey: opened.senderPubkey,
          reason: 'insufficient_pow',
          requiredTarget: decision.target,
        })
        continue
      }
    }

    inbox.push({
      event,
      message: opened.message,
      senderPubkey: opened.senderPubkey,
      innerEventId: opened.innerEventId,
      innerCreatedAt: opened.innerCreatedAt,
    })
  }
  return { inbox, rejected }
}

export interface ScannedBroadcast {
  event: NostrEvent
  message: BroadcastMessage
}

export interface ScanBroadcastOptions {
  since?: number
  limit?: number
  signal?: AbortSignal
}

export async function scanBroadcastInbox(
  transport: Transport,
  relays: string[],
  credentials: BroadcastCredential[],
  options: ScanBroadcastOptions = {},
): Promise<ScannedBroadcast[]> {
  if (credentials.length === 0) return []
  const authors = [...new Set(credentials.map((credential) => credential.author))]

  const filter: Filter = {
    kinds: [NVELOPE_EVENT_KIND],
    authors,
    [`#${LABEL_TAG}`]: [LABEL_BROADCAST_MESSAGE],
  }
  if (options.since !== undefined) filter.since = options.since
  if (options.limit !== undefined) filter.limit = options.limit

  const events = await transport.query(filter, relays)
  const keyCache = new Map<string, Uint8Array>()
  const inbox: ScannedBroadcast[] = []

  for (const event of events) {
    if (options.signal?.aborted) break
    if (!verifyEnvelopeSignature(event)) continue
    for (const credential of credentials) {
      if (credential.author !== event.pubkey) continue
      const keyInfo = readKeyInfo(event)
      if (keyInfo === undefined) continue

      // Cache derived keys per (password, salt): scrypt runs once per list.
      const cacheKey = `${credential.password}:${keyInfo.salt}`
      let key = keyCache.get(cacheKey)
      if (key === undefined) {
        key = deriveKeyFromPassword(credential.password, keyInfo.salt)
        keyCache.set(cacheKey, key)
      }

      const message = openBroadcastMessageWithKey(event, key)
      if (message === undefined) continue
      if (message.getTopic() !== credential.topic) continue // readable but not wanted
      inbox.push({ event, message })
      break // one credential opens each event
    }
  }
  return inbox
}
