/**
 * Blinded envelopes — the encrypted kind-8500 events that actually touch relays.
 *
 * DIRECT mail: the inner signed message event is JSON-serialized, RSA-chunk-
 * encrypted to the recipient's certificate, and the base64 chunk array becomes
 * the content of an OUTER event signed by a THROWAWAY key (fresh per envelope).
 * The throwaway key is what makes the envelope "blinded": nothing on the
 * envelope links it to the sender, and envelopes to different recipients are
 * unlinkable to each other. A `nonce` tag carries the proof-of-work.
 *
 * BROADCAST mail: one event, content = AES-256-CBC(base64) of the wire JSON,
 * signed by the AUTHOR's key (subscribers find lists by author, so broadcast
 * envelopes are never blinded). The `key_info` tag carries { salt, iv } so
 * holders of the list password can derive the key. The topic and password
 * appear NOWHERE on the event — discovery and filtering are client-side.
 *
 * PoW: mined via crypto/pow.ts's non-blocking miner BEFORE signing (the event
 * id covers the nonce tag; the signature does not affect the id).
 */
import { randomBytes } from 'node:crypto'
import { generateSecretKey, getEventHash, getPublicKey } from 'nostr-tools/pure'
import {
  KEY_INFO_TAG,
  LABEL_BROADCAST_MESSAGE,
  LABEL_DIRECT_MESSAGE,
  LABEL_TAG,
  NONCE_TAG,
  NVELOPE_EVENT_KIND,
} from '../constants.js'
import type { Hex256, KeyInfoWire } from '../types.js'
import { decryptEnvelope, encryptEnvelope } from '../crypto/envelope.js'
import {
  SYMMETRIC_IV_BYTES,
  decryptWithKey,
  deriveKeyFromPassword,
  encryptSymmetric,
} from '../crypto/symmetric.js'
import { assertHex256, meetsPowTarget, minePow, targetFromLeadingZeros } from '../crypto/pow.js'
import type { MinePowResult } from '../crypto/pow.js'
import { DirectMessage } from '../messages/direct.js'
import { BroadcastMessage } from '../messages/broadcast.js'
import type { BroadcastKeyMaterial } from '../messages/broadcast.js'
import {
  createDirectMessageEvent,
  finalizeWithNsec,
  nowSeconds,
  verifyNostrEvent,
} from './events.js'
import type { NostrEvent, UnsignedEvent } from './events.js'

/** PoW requirement and mining controls for envelope creation. */
export interface EnvelopePowOptions {
  /** Leading zero bits required in the event id. 0 = effectively none (default). */
  leadingZeros?: number
  /** Explicit 256-bit target (id must be numerically < target). Overrides leadingZeros. */
  target?: string
  /** Hash attempts per event-loop yield (see minePow). */
  batchSize?: number
  /** Progress callback for GUI progress bars. */
  onProgress?: (attempts: number) => void
  /** Cancellation. */
  signal?: AbortSignal
}

/** A sealed envelope ready for transport.publish(). */
export interface SealedEnvelope {
  event: NostrEvent
}

function resolveTarget(options: EnvelopePowOptions): string {
  return options.target ?? targetFromLeadingZeros(options.leadingZeros ?? 0)
}

interface MinedTemplate {
  kind: number
  created_at: number
  tags: string[][]
  content: string
  pubkey: string
}

/** A mining candidate: an unsigned event whose pubkey is always set. */
interface MinedCandidate {
  kind: number
  created_at: number
  tags: string[][]
  content: string
  pubkey: string
}

/**
 * Mine an envelope template to a target WITHOUT signing. The returned unsigned
 * event carries the final pubkey and nonce; its id is determined, so a signer
 * that preserves kind/created_at/tags/content produces an envelope that still
 * meets the target. Callers sign via their Signer and SHOULD verify with
 * envelopeMeetsPow afterwards.
 */
async function mineEnvelopeTemplate(
  template: MinedTemplate,
  options: EnvelopePowOptions,
): Promise<UnsignedEvent> {
  const target = resolveTarget(options)
  const mined: MinePowResult<MinedCandidate> = await minePow(
    (nonce): MinedCandidate => ({
      kind: template.kind,
      created_at: template.created_at,
      content: template.content,
      pubkey: template.pubkey,
      tags: [...template.tags, [NONCE_TAG, nonce]],
    }),
    (candidate) => getEventHash(candidate),
    target,
    {
      batchSize: options.batchSize,
      onProgress: options.onProgress,
      signal: options.signal,
    },
  )
  return mined.candidate
}

/**
 * Seal an inner direct-message event JSON into a blinded envelope for one
 * recipient, mining PoW and signing with a fresh throwaway key.
 */
export async function createDirectEnvelopeEvent(
  innerEventJson: string,
  recipientCertPem: string,
  options: EnvelopePowOptions = {},
): Promise<SealedEnvelope> {
  if (typeof innerEventJson !== 'string' || innerEventJson.length === 0) {
    throw new TypeError('innerEventJson must be the JSON of a signed inner event')
  }
  const throwaway = generateSecretKey()
  const { unsigned } = await mineDirectEnvelopeEvent(
    innerEventJson,
    recipientCertPem,
    getPublicKey(throwaway),
    options,
  )
  return { event: finalizeWithNsec(unsigned, throwaway) }
}

/**
 * Mine (without signing) a blinded direct envelope for one recipient.
 * `throwawayPubkey` is the pubkey the final envelope will carry — generate a
 * fresh throwaway keypair per envelope for unlinkability, then sign the
 * returned unsigned event with its secret key.
 */
export async function mineDirectEnvelopeEvent(
  innerEventJson: string,
  recipientCertPem: string,
  throwawayPubkey: Hex256,
  options: EnvelopePowOptions = {},
): Promise<{ unsigned: UnsignedEvent }> {
  if (typeof innerEventJson !== 'string' || innerEventJson.length === 0) {
    throw new TypeError('innerEventJson must be the JSON of a signed inner event')
  }
  assertHex256(throwawayPubkey, 'throwawayPubkey')
  const chunks = encryptEnvelope(innerEventJson, recipientCertPem)
  const unsigned = await mineEnvelopeTemplate(
    {
      kind: NVELOPE_EVENT_KIND,
      created_at: nowSeconds(),
      pubkey: throwawayPubkey,
      tags: [[LABEL_TAG, LABEL_DIRECT_MESSAGE]],
      content: JSON.stringify(chunks),
    },
    options,
  )
  return { unsigned }
}

export interface SealedDirectMail {
  recipient: Hex256
  event: NostrEvent
}

/**
 * High-level helper: seal a DirectMessage for all its recipients.
 *
 * Builds the per-recipient wire messages (shared body for To/CC, private
 * bccTo copy per BCC recipient), signs ONE inner event per distinct body, and
 * seals one blinded envelope per recipient with that recipient's certificate.
 *
 * @param recipientCertificates map of recipient npub -> certificate PEM (as
 *   published in their nv_public_key profile event).
 * @throws {RangeError} if a recipient has no certificate provided.
 */
export async function sealDirectMessage(
  message: DirectMessage,
  secretKey: Uint8Array,
  recipientCertificates: Record<Hex256, string>,
  options: EnvelopePowOptions = {},
): Promise<SealedDirectMail[]> {
  const innerCache = new Map<string, NostrEvent>()
  const results: SealedDirectMail[] = []

  for (const { recipient, message: wire } of message.getWireMessages()) {
    const cert = recipientCertificates[recipient]
    if (cert === undefined) {
      throw new RangeError(`No certificate provided for recipient ${recipient}`)
    }
    const wireJson = JSON.stringify(wire)
    let inner = innerCache.get(wireJson)
    if (inner === undefined) {
      inner = createDirectMessageEvent(wire, secretKey)
      innerCache.set(wireJson, inner)
    }
    const { event } = await createDirectEnvelopeEvent(JSON.stringify(inner), cert, options)
    results.push({ recipient, event })
  }
  return results
}

/**
 * Create a broadcast envelope event: AES-256-CBC encrypted wire content,
 * signed by the AUTHOR's key (never blinded), with `key_info` and a mined
 * `nonce`. A fresh IV is used per call.
 *
 * @returns the sealed event plus the key_info that was embedded (salt + iv).
 */
export async function createBroadcastEnvelopeEvent(
  message: BroadcastMessage,
  secretKey: Uint8Array,
  keyMaterial: BroadcastKeyMaterial,
  options: EnvelopePowOptions = {},
): Promise<{ event: NostrEvent; keyInfo: KeyInfoWire }> {
  const { unsigned, keyInfo } = await mineBroadcastEnvelopeEvent(
    message,
    getPublicKey(secretKey),
    keyMaterial,
    options,
  )
  return { event: finalizeWithNsec(unsigned, secretKey), keyInfo }
}

/**
 * Mine (without signing) a broadcast envelope for a message. `authorPubkey`
 * is baked into the template (subscribers find lists by author); sign the
 * returned unsigned event with the author's key and verify the result still
 * meets the PoW target.
 */
export async function mineBroadcastEnvelopeEvent(
  message: BroadcastMessage,
  authorPubkey: Hex256,
  keyMaterial: BroadcastKeyMaterial,
  options: EnvelopePowOptions = {},
): Promise<{ unsigned: UnsignedEvent; keyInfo: KeyInfoWire }> {
  assertHex256(authorPubkey, 'authorPubkey')
  const iv = randomBytes(SYMMETRIC_IV_BYTES)
  const ciphertext = encryptSymmetric(message.toJson(), keyMaterial.key, iv)
  const keyInfo: KeyInfoWire = { salt: keyMaterial.salt, iv: iv.toString('hex') }
  const unsigned = await mineEnvelopeTemplate(
    {
      kind: NVELOPE_EVENT_KIND,
      created_at: nowSeconds(),
      pubkey: authorPubkey,
      tags: [
        [LABEL_TAG, LABEL_BROADCAST_MESSAGE],
        [KEY_INFO_TAG, JSON.stringify(keyInfo)],
      ],
      content: ciphertext,
    },
    options,
  )
  return { unsigned, keyInfo }
}

/* ------------------------------------------------------------------------ */
/* Reading envelopes (recipient / subscriber side)                          */
/* ------------------------------------------------------------------------ */

/** Find a tag's first value. @returns undefined if the tag is absent. */
export function getTagValue(event: NostrEvent, name: string): string | undefined {
  for (const tag of event.tags) {
    const [tagName, value] = tag
    if (tagName === name) return value
  }
  return undefined
}

/** The envelope's label tag value ('direct_message' | 'broadcast_message'). */
export function envelopeLabel(event: NostrEvent): string | undefined {
  return getTagValue(event, LABEL_TAG)
}

/** Parse and validate the `key_info` tag of a broadcast envelope. */
export function readKeyInfo(event: NostrEvent): KeyInfoWire | undefined {
  const raw = getTagValue(event, KEY_INFO_TAG)
  if (raw === undefined) return undefined
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return undefined
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined
  const { salt, iv } = parsed as Record<string, unknown>
  if (typeof salt !== 'string' || !/^[0-9a-fA-F]{64}$/.test(salt)) return undefined
  if (typeof iv !== 'string' || !/^[0-9a-fA-F]{32}$/.test(iv)) return undefined
  return { salt: salt.toLowerCase(), iv: iv.toLowerCase() }
}

/**
 * Decrypt a direct blinded envelope with the recipient's certificate private
 * key. @returns the inner event JSON, or undefined if not encrypted for this
 * key (expected while scanning envelopes).
 */
export function readDirectEnvelopeJson(
  event: NostrEvent,
  privateKeyPem: string,
): string | undefined {
  let chunks: unknown
  try {
    chunks = JSON.parse(event.content)
  } catch {
    return undefined
  }
  if (!Array.isArray(chunks) || chunks.some((chunk) => typeof chunk !== 'string')) {
    return undefined
  }
  return decryptEnvelope(chunks as string[], privateKeyPem)
}

/** A successfully opened direct envelope. */
export interface OpenedDirectEnvelope {
  message: DirectMessage
  /** The verified sender (inner event pubkey). */
  senderPubkey: Hex256
  /**
   * The stable message identity: the INNER event id. Identical for all
   * To/CC recipients of one message (distinct per BCC copy); clients should
   * key their mail store on this, never on the disposable outer envelope id.
   */
  innerEventId: Hex256
  /** The sender's authoritative timestamp (inner event created_at). */
  innerCreatedAt: number
}

/**
 * Open a direct envelope, returning the message AND the verified sender.
 *
 * Unwraps the three JSON layers (envelope ciphertext -> inner signed event ->
 * wire message) and validates the inner event: kind 8500, well-formed, and a
 * valid sender signature (per the white paper, a direct message IS a properly
 * signed Nostr event — a forged or tampered inner event is rejected).
 *
 * @returns undefined if the envelope was not encrypted for this key, or the
 *   inner event failed validation.
 */
export function openDirectEnvelope(
  event: NostrEvent,
  privateKeyPem: string,
): OpenedDirectEnvelope | undefined {
  const json = readDirectEnvelopeJson(event, privateKeyPem)
  if (json === undefined) return undefined

  let inner: NostrEvent
  try {
    inner = JSON.parse(json) as NostrEvent
  } catch {
    return undefined
  }
  if (inner.kind !== NVELOPE_EVENT_KIND) return undefined
  if (typeof inner.content !== 'string') return undefined
  if (!verifyNostrEvent(inner)) return undefined

  try {
    return {
      message: DirectMessage.fromWire(inner.content),
      senderPubkey: inner.pubkey,
      innerEventId: inner.id,
      innerCreatedAt: inner.created_at,
    }
  } catch {
    return undefined
  }
}

/** Open a direct envelope into just the message (see openDirectEnvelope). */
export function openDirectMessage(
  event: NostrEvent,
  privateKeyPem: string,
): DirectMessage | undefined {
  return openDirectEnvelope(event, privateKeyPem)?.message
}

/**
 * Open a broadcast envelope with the list password (derives the key via
 * scrypt — prefer openBroadcastMessageWithKey when the key is cached).
 */
export function openBroadcastMessage(
  event: NostrEvent,
  password: string,
): BroadcastMessage | undefined {
  const keyInfo = readKeyInfo(event)
  if (keyInfo === undefined) return undefined
  const key = deriveKeyFromPassword(password, keyInfo.salt)
  return openBroadcastMessageWithKey(event, key)
}

/** Open a broadcast envelope with a pre-derived key (see generateBroadcastKey). */
export function openBroadcastMessageWithKey(
  event: NostrEvent,
  key: Uint8Array,
): BroadcastMessage | undefined {
  const keyInfo = readKeyInfo(event)
  if (keyInfo === undefined) return undefined
  const json = decryptWithKey(event.content, key, keyInfo.iv)
  if (json === undefined) return undefined
  try {
    return BroadcastMessage.fromWire(json)
  } catch {
    return undefined
  }
}

/** Check a blinded envelope's PoW: its event id must satisfy the target. */
export function envelopeMeetsPow(event: NostrEvent, targetHex: string): boolean {
  return meetsPowTarget(event.id, targetHex)
}

/** Verify the envelope's Nostr signature (throwaway key for direct mail). */
export function verifyEnvelopeSignature(event: NostrEvent): boolean {
  return verifyNostrEvent(event)
}
