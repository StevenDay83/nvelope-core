/**
 * MailProfile — a recipient's published presence: the recipient policy (who
 * may send, with what PoW) and the mail certificate public key subscribers
 * need to encrypt mail to them.
 *
 * Both pieces are addressable Nostr events of kind 30998:
 * - d tag "nv_recipient_profile": content = JSON of RecipientPolicyWire
 * - d tag "nv_public_key":        content = the certificate public key (DER base64)
 *
 * Fixes versus the pre-refactor mailprofile.js:
 * - importRecipientProfile only processed `deny` when `allow` was present
 *   (nesting bug); here deny is imported independently (regression-tested).
 * - addDenyListPubKey used an undeclared variable (implicit global); the
 *   equivalent here validates inputs.
 */
import {
  IDENTIFIER_TAG,
  MAIL_PROFILE_KIND,
  PROFILE_IDENTIFIER_PUBLIC_KEY,
  PROFILE_IDENTIFIER_RECIPIENT_POLICY,
} from '../constants.js'
import { publicKeyDerBase64ToPem } from '../crypto/certificate.js'
import { buildUnsignedEvent, finalizeWithNsec, verifyNostrEvent } from '../protocol/events.js'
import type { NostrEvent } from '../protocol/events.js'
import { RecipientPolicy } from './policy.js'

export class MailProfile {
  private policyModel = new RecipientPolicy()
  private certificateDerBase64 = ''

  /** The recipient policy model (mutate it, then publish via toPolicyJson()). */
  get policy(): RecipientPolicy {
    return this.policyModel
  }

  /**
   * Set the mail certificate public key (DER base64, as produced by
   * generateMailCertificate). Validated by parsing it.
   */
  setCertificate(publicKeyDerBase64: string): this {
    publicKeyDerBase64ToPem(publicKeyDerBase64) // throws TypeError on malformed input
    this.certificateDerBase64 = publicKeyDerBase64
    return this
  }

  getCertificate(): string {
    return this.certificateDerBase64
  }

  /** Build a profile from a policy wire object or JSON string. */
  static fromPolicyWire(wire: Parameters<typeof RecipientPolicy.fromWire>[0]): MailProfile {
    const profile = new MailProfile()
    profile.policyModel = RecipientPolicy.fromWire(wire)
    return profile
  }

  /** Event content for the nv_recipient_profile event. */
  toPolicyJson(): string {
    return this.policyModel.toJson()
  }

  /** Event content for the nv_public_key event. */
  toCertificateContent(): string {
    return this.certificateDerBase64
  }

  /**
   * Import a recipient policy from a published profile event (or its content
   * string). When an event object is given, its `d` tag must be
   * "nv_recipient_profile".
   */
  static importPolicyEvent(event: NostrEvent | string): RecipientPolicy {
    if (typeof event === 'string') {
      return RecipientPolicy.fromWire(event)
    }
    if (event.kind !== MAIL_PROFILE_KIND) {
      throw new TypeError(`Expected a kind ${MAIL_PROFILE_KIND} profile event`)
    }
    let dTag: string | undefined
    for (const tag of event.tags) {
      if (tag[0] === IDENTIFIER_TAG) {
        dTag = tag[1]
        break
      }
    }
    if (dTag !== PROFILE_IDENTIFIER_RECIPIENT_POLICY) {
      throw new TypeError(
        `Expected d tag "${PROFILE_IDENTIFIER_RECIPIENT_POLICY}", got: ${JSON.stringify(dTag)}`,
      )
    }
    if (!verifyNostrEvent(event)) {
      throw new TypeError('Recipient policy event has an invalid signature')
    }
    return RecipientPolicy.fromWire(event.content)
  }

  /** Import a certificate public key from its nv_public_key event. */
  static importCertificateEvent(event: NostrEvent | string): string {
    const content = typeof event === 'string' ? event : event.content
    if (typeof event !== 'string') {
      if (event.kind !== MAIL_PROFILE_KIND) {
        throw new TypeError(`Expected a kind ${MAIL_PROFILE_KIND} profile event`)
      }
      let dTag: string | undefined
      for (const tag of event.tags) {
        if (tag[0] === IDENTIFIER_TAG) {
          dTag = tag[1]
          break
        }
      }
      if (dTag !== PROFILE_IDENTIFIER_PUBLIC_KEY) {
        throw new TypeError(
          `Expected d tag "${PROFILE_IDENTIFIER_PUBLIC_KEY}", got: ${JSON.stringify(dTag)}`,
        )
      }
      if (!verifyNostrEvent(event)) {
        throw new TypeError('Certificate event has an invalid signature')
      }
    }
    publicKeyDerBase64ToPem(content) // validate
    return content
  }
}

/**
 * Create an addressable profile event (kind 30998) with the given d tag and
 * content, signed by the owner's nsec.
 */
export function createProfileEvent(dTag: string, content: string, secretKey: Uint8Array): NostrEvent {
  if (dTag !== PROFILE_IDENTIFIER_RECIPIENT_POLICY && dTag !== PROFILE_IDENTIFIER_PUBLIC_KEY) {
    throw new TypeError(`Unknown profile d tag: ${JSON.stringify(dTag)}`)
  }
  if (typeof content !== 'string' || content.length === 0) {
    throw new TypeError('Profile event content must be a non-empty string')
  }
  return finalizeWithNsec(
    buildUnsignedEvent({ kind: MAIL_PROFILE_KIND, tags: [[IDENTIFIER_TAG, dTag]], content }),
    secretKey,
  )
}
