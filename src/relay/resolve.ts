/**
 * Resolving other users' mail profiles from relays.
 *
 * A sender needs two things before sealing mail to someone: the recipient's
 * mail certificate (to encrypt) and their recipient policy (to know how much
 * PoW to attach). Both are kind-30998 events; these helpers fetch the latest.
 */
import type { Filter } from 'nostr-tools'
import {
  IDENTIFIER_TAG,
  MAIL_PROFILE_KIND,
  PROFILE_IDENTIFIER_PUBLIC_KEY,
  PROFILE_IDENTIFIER_RECIPIENT_POLICY,
} from '../constants.js'
import type { Hex256 } from '../types.js'
import { assertHex256 } from '../crypto/pow.js'
import { publicKeyDerBase64ToPem } from '../crypto/certificate.js'
import { MailProfile } from '../profile/mailProfile.js'
import { RecipientPolicy } from '../profile/policy.js'
import type { NostrEvent } from '../protocol/events.js'
import type { Transport } from './transport.js'

/** A recipient's published certificate, in both wire and usable PEM form. */
export interface ResolvedCertificate {
  derBase64: string
  pem: string
}

function latest(events: NostrEvent[]): NostrEvent | undefined {
  let newest: NostrEvent | undefined
  for (const event of events) {
    if (newest === undefined || event.created_at > newest.created_at) {
      newest = event
    }
  }
  return newest
}

/**
 * Fetch a recipient's mail certificate. @returns undefined if none published
 * (caller should then refuse to send — no way to encrypt for them).
 */
export async function fetchCertificate(
  transport: Transport,
  owner: Hex256,
  relays: string[],
): Promise<ResolvedCertificate | undefined> {
  assertHex256(owner, 'owner')
  const filter: Filter = {
    kinds: [MAIL_PROFILE_KIND],
    authors: [owner],
    [`#${IDENTIFIER_TAG}`]: [PROFILE_IDENTIFIER_PUBLIC_KEY],
  }
  const event = latest(await transport.query(filter, relays))
  if (event === undefined) return undefined
  const derBase64 = MailProfile.importCertificateEvent(event)
  return { derBase64, pem: publicKeyDerBase64ToPem(derBase64) }
}

/**
 * Fetch a recipient's published policy. @returns undefined if none published
 * (treat as "no constraints" — see RecipientPolicy.evaluate).
 */
export async function fetchRecipientPolicy(
  transport: Transport,
  owner: Hex256,
  relays: string[],
): Promise<RecipientPolicy | undefined> {
  assertHex256(owner, 'owner')
  const filter: Filter = {
    kinds: [MAIL_PROFILE_KIND],
    authors: [owner],
    [`#${IDENTIFIER_TAG}`]: [PROFILE_IDENTIFIER_RECIPIENT_POLICY],
  }
  const event = latest(await transport.query(filter, relays))
  if (event === undefined) return undefined
  return MailProfile.importPolicyEvent(event)
}
