/**
 * NvelopeClient — the high-level facade composing the whole protocol into
 * intent-named calls: publish your profile, send direct mail (resolving the
 * recipient's certificate and policy, mining the required PoW per recipient),
 * and check your direct/broadcast inboxes.
 *
 * Identity is injected as a Signer; relay access as a Transport. Your mail
 * certificate private key is provided only for DECRYPTION and never leaves
 * the client. Direct envelopes are signed with internally generated throwaway
 * keys — your nsec is used only for inner events, broadcast envelopes, and
 * profile events, always through the Signer.
 */
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  IDENTIFIER_TAG,
  MAIL_PROFILE_KIND,
  PROFILE_IDENTIFIER_PUBLIC_KEY,
  PROFILE_IDENTIFIER_RECIPIENT_POLICY,
} from '../constants.js'
import type { Hex256 } from '../types.js'
import { publicKeyDerBase64FromPrivateKeyPem } from '../crypto/certificate.js'
import { TARGET_NO_CONSTRAINT } from '../crypto/pow.js'
import { BroadcastMessage, generateBroadcastKey } from '../messages/broadcast.js'
import { DirectMessage } from '../messages/direct.js'
import { buildUnsignedEvent } from '../protocol/events.js'
import type { NostrEvent } from '../protocol/events.js'
import { decodeBroadcastNaddr } from '../protocol/broadcastNaddr.js'
import {
  envelopeMeetsPow,
  mineBroadcastEnvelopeEvent,
  mineDirectEnvelopeEvent,
} from '../protocol/blinded.js'
import type { BroadcastCredential } from '../protocol/broadcastNaddr.js'
import type { KeyInfoWire } from '../types.js'
import type { PublishResult, Transport } from '../relay/transport.js'
import type { Signer } from '../relay/signer.js'
import { NsecSigner } from '../relay/signer.js'
import { fetchCertificate, fetchRecipientPolicy } from '../relay/resolve.js'
import { contactSourceToCallback } from '../relay/contacts.js'
import type { ContactSource } from '../relay/contacts.js'
import { MailProfile } from '../profile/mailProfile.js'
import { scanBroadcastInbox, scanDirectInbox } from '../relay/inbox.js'
import type { ScanDirectResult, ScannedBroadcast } from '../relay/inbox.js'
import { RecipientPolicy } from '../profile/policy.js'

export interface NvelopeClientOptions {
  transport: Transport
  signer: Signer
  /** Relays used by default; per-call override available on most methods. */
  relays: string[]
  /** Your mail certificate private key (PEM) — used to open your direct mail. */
  certificatePrivateKeyPem: string
  /** Optional override; derived from the private key when omitted. */
  certificatePublicKeyDerBase64?: string
  /** Broadcast list credentials (from naddrs) you subscribe to. */
  broadcastCredentials?: BroadcastCredential[]
}

export interface SendDirectOptions {
  relays?: string[]
  onProgress?: (attempts: number) => void
  signal?: AbortSignal
}

export interface SentDirectMail {
  recipient: Hex256
  event: NostrEvent
  published: PublishResult
}

export interface CheckInboxOptions {
  relays?: string[]
  since?: number
  limit?: number
  signal?: AbortSignal
}

export interface CheckDirectInboxOptions extends CheckInboxOptions {
  /** Override the PoW scan filter (default: your own published policy's). */
  targetFilter?: string
  /**
   * Contact lookup for post-decryption policy validation: a callback, or a
   * resolved ContactList from the courtesy fetchers (fetchKind3Contacts /
   * fetchNip51Contacts). Fetch ONCE per batch and reuse the instance — the
   * lookup then costs a Set hit per message. Without it, contact-based rules
   * (deny.contacts, contact-category PoW) cannot match.
   */
  isContact?: ContactSource
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Health of one published profile component. */
export type ProfileComponentStatus = 'ok' | 'missing' | 'corrupt' | 'mismatch'

/** Result of the voluntary checkProfile() self-check. */
export interface ProfileHealth {
  /** nv_public_key event: present, valid, and matching the local certificate. */
  certificate: ProfileComponentStatus
  /** nv_recipient_profile event: present and valid. */
  policy: ProfileComponentStatus
  /** True when both components are 'ok'. */
  healthy: boolean
}

export interface PublishBroadcastOptions {
  relays?: string[]
  onProgress?: (attempts: number) => void
  signal?: AbortSignal
  /** Explicit PoW target; default: no additional PoW beyond protocol needs. */
  leadingZeros?: number
}

export class NvelopeClient {
  private readonly transport: Transport
  private readonly signer: Signer
  private readonly relays: string[]
  private readonly certificatePrivateKeyPem: string
  /** Monotonic clock for published events (reliable replaceable-event ordering). */
  private lastEventTime = 0
  readonly certificatePublicKeyDerBase64: string
  private readonly broadcastCredentials: BroadcastCredential[]

  constructor(options: NvelopeClientOptions) {
    if (options.relays.length === 0) {
      throw new RangeError('At least one relay is required')
    }
    this.transport = options.transport
    this.signer = options.signer
    this.relays = options.relays
    this.certificatePrivateKeyPem = options.certificatePrivateKeyPem
    this.certificatePublicKeyDerBase64 =
      options.certificatePublicKeyDerBase64 ??
      publicKeyDerBase64FromPrivateKeyPem(options.certificatePrivateKeyPem)
    this.broadcastCredentials = [...(options.broadcastCredentials ?? [])]
  }

  /** Your npub (from the signer). */
  async getPublicKey(): Promise<Hex256> {
    return this.signer.getPublicKey()
  }

  /**
   * Whole seconds, strictly increasing: two profile updates in the same
   * second must still order so relays replace the old event reliably.
   */
  private nextEventTime(): number {
    const now = Math.floor(Date.now() / 1000)
    this.lastEventTime = Math.max(now, this.lastEventTime + 1)
    return this.lastEventTime
  }

  /* ------------------------------------------------------------------ */
  /* Profile                                                             */
  /* ------------------------------------------------------------------ */

  /**
   * Publish (or update) your mail profile: the recipient policy event and the
   * certificate public key event (both kind 30998, addressable).
   */
  async publishProfile(policy: RecipientPolicy = new RecipientPolicy()): Promise<PublishResult[]> {
    const policyEvent = await this.signer.signEvent(
      buildUnsignedEvent({
        kind: MAIL_PROFILE_KIND,
        tags: [[IDENTIFIER_TAG, PROFILE_IDENTIFIER_RECIPIENT_POLICY]],
        content: policy.toJson(),
        createdAt: this.nextEventTime(),
      }),
    )
    const certificateEvent = await this.signer.signEvent(
      buildUnsignedEvent({
        kind: MAIL_PROFILE_KIND,
        tags: [[IDENTIFIER_TAG, PROFILE_IDENTIFIER_PUBLIC_KEY]],
        content: this.certificatePublicKeyDerBase64,
        createdAt: this.nextEventTime(),
      }),
    )
    return [
      await this.transport.publish(policyEvent, this.relays),
      await this.transport.publish(certificateEvent, this.relays),
    ]
  }

  /* ------------------------------------------------------------------ */
  /* Voluntary profile self-check and repair                             */
  /* ------------------------------------------------------------------ */

  /**
   * Fetch the latest profile event of one d-tag kind for an author.
   * Query failures (transport) surface as undefined for the health check.
   */
  private async fetchLatestProfileEvent(
    owner: Hex256,
    dTag: string,
    relays: string[],
  ): Promise<NostrEvent | undefined> {
    const events = await this.transport.query(
      {
        kinds: [MAIL_PROFILE_KIND],
        authors: [owner],
        [`#${IDENTIFIER_TAG}`]: [dTag],
      },
      relays,
    )
    let latest: NostrEvent | undefined
    for (const event of events) {
      if (latest === undefined || event.created_at > latest.created_at) {
        latest = event
      }
    }
    return latest
  }

  /**
   * Voluntarily verify this identity's PUBLISHED profile: is the certificate
   * event present, valid, and matching the local certificate? Is the policy
   * event present and valid? A client (e.g. nVelope-Client on startup) can
   * run this and then call repairProfile() for anything not 'ok'.
   */
  async checkProfile(options: { relays?: string[] } = {}): Promise<ProfileHealth> {
    const relays = options.relays ?? this.relays
    const owner = await this.signer.getPublicKey()

    let certificate: ProfileComponentStatus = 'ok'
    const certEvent = await this.fetchLatestProfileEvent(
      owner,
      PROFILE_IDENTIFIER_PUBLIC_KEY,
      relays,
    ).catch(() => undefined)
    if (certEvent === undefined) {
      certificate = 'missing'
    } else {
      try {
        const published = MailProfile.importCertificateEvent(certEvent)
        if (published !== this.certificatePublicKeyDerBase64) {
          certificate = 'mismatch'
        }
      } catch {
        certificate = 'corrupt'
      }
    }

    let policy: ProfileComponentStatus = 'ok'
    const policyEvent = await this.fetchLatestProfileEvent(
      owner,
      PROFILE_IDENTIFIER_RECIPIENT_POLICY,
      relays,
    ).catch(() => undefined)
    if (policyEvent === undefined) {
      policy = 'missing'
    } else {
      try {
        MailProfile.importPolicyEvent(policyEvent)
      } catch {
        policy = 'corrupt'
      }
    }

    return { certificate, policy, healthy: certificate === 'ok' && policy === 'ok' }
  }

  /**
   * Republish whichever profile components are not 'ok'. The LOCAL
   * certificate is the ground truth for repair; the policy defaults to the
   * provided one, else the existing published policy (if importable), else a
   * fresh open policy.
   */
  async repairProfile(
    policy?: RecipientPolicy,
    options: { relays?: string[] } = {},
  ): Promise<PublishResult[]> {
    const relays = options.relays ?? this.relays
    const health = await this.checkProfile({ relays })
    const results: PublishResult[] = []

    if (health.certificate !== 'ok') {
      const event = await this.signer.signEvent(
        buildUnsignedEvent({
          kind: MAIL_PROFILE_KIND,
          tags: [[IDENTIFIER_TAG, PROFILE_IDENTIFIER_PUBLIC_KEY]],
          content: this.certificatePublicKeyDerBase64,
          createdAt: this.nextEventTime(),
        }),
      )
      results.push(await this.transport.publish(event, relays))
    }

    if (health.policy !== 'ok') {
      let content: string
      if (policy !== undefined) {
        content = policy.toJson()
      } else {
        const owner = await this.signer.getPublicKey()
        const existing = await this.fetchLatestProfileEvent(
          owner,
          PROFILE_IDENTIFIER_RECIPIENT_POLICY,
          relays,
        ).catch(() => undefined)
        let imported: RecipientPolicy | undefined
        if (existing !== undefined) {
          try {
            imported = MailProfile.importPolicyEvent(existing)
          } catch {
            imported = undefined
          }
        }
        content = (imported ?? new RecipientPolicy()).toJson()
      }
      const event = await this.signer.signEvent(
        buildUnsignedEvent({
          kind: MAIL_PROFILE_KIND,
          tags: [[IDENTIFIER_TAG, PROFILE_IDENTIFIER_RECIPIENT_POLICY]],
          content,
          createdAt: this.nextEventTime(),
        }),
      )
      results.push(await this.transport.publish(event, relays))
    }

    return results
  }

  /* ------------------------------------------------------------------ */
  /* Sending direct mail                                                 */
  /* ------------------------------------------------------------------ */

  /**
   * Send a DirectMessage: resolve each recipient's certificate and policy,
   * enforce it (refusing denied recipients), mine the required PoW per
   * recipient, seal one blinded envelope each, and publish.
   *
   * If message.from is unset it defaults to your npub; a mismatch with the
   * signer throws.
   *
   * Note on contact policies: the sender cannot know whether the recipient
   * counts them as a contact, so evaluation uses the conservative
   * (non-contact) categories; explicit allow-list entries still override.
   * Over-mining is always accepted by recipients.
   */
  async sendDirectMail(
    message: DirectMessage,
    options: SendDirectOptions = {},
  ): Promise<SentDirectMail[]> {
    const relays = options.relays ?? this.relays
    const myPubkey = await this.signer.getPublicKey()

    if (message.getFrom().length === 0) {
      message.setFrom(myPubkey)
    } else if (message.getFrom() !== myPubkey) {
      throw new TypeError('message.from must match the client signer identity')
    }

    const recipients = [
      ...new Set([
        ...message.getRecipientsTo(),
        ...message.getCcList(),
        ...message.getBccList(),
      ]),
    ]
    if (recipients.length === 0) {
      throw new RangeError('Message has no recipients')
    }

    // Resolve certificates and per-recipient PoW targets.
    //
    // Failure semantics: a recipient who publishes NOTHING gets the open
    // default (no PoW, anyone may send). A recipient who publishes something
    // INVALID is not sendable — the onus is on the recipient to keep their
    // profile correct (clients can self-check with checkProfile()).
    const certificates: Record<Hex256, string> = {}
    const targets: Record<Hex256, string> = {}
    for (const recipient of recipients) {
      let certificate: Awaited<ReturnType<typeof fetchCertificate>>
      try {
        certificate = await fetchCertificate(this.transport, recipient, relays)
      } catch (error) {
        throw new Error(
          `Recipient ${recipient} published an invalid mail certificate: ${messageOf(error)}`,
        )
      }
      if (certificate === undefined) {
        throw new Error(`Recipient ${recipient} has not published a mail certificate`)
      }
      certificates[recipient] = certificate.pem

      let policy: Awaited<ReturnType<typeof fetchRecipientPolicy>>
      try {
        policy = await fetchRecipientPolicy(this.transport, recipient, relays)
      } catch (error) {
        throw new Error(
          `Recipient ${recipient} published an invalid recipient policy: ${messageOf(error)}`,
        )
      }
      const decision = policy
        ? policy.evaluate(myPubkey, false)
        : { allowed: true as const, target: TARGET_NO_CONSTRAINT, source: 'none' as const }
      if (!decision.allowed) {
        throw new Error(`Recipient ${recipient} denies mail from you (${decision.reason})`)
      }
      targets[recipient] = decision.target
    }

    // Seal one envelope per recipient; reuse one inner event per distinct body.
    const innerCache = new Map<string, NostrEvent>()
    const results: SentDirectMail[] = []
    for (const { recipient, message: wire } of message.getWireMessages()) {
      const certificate = certificates[recipient]
      const target = targets[recipient]
      if (certificate === undefined || target === undefined) {
        throw new Error(`Missing resolution for recipient ${recipient}`)
      }

      const wireJson = JSON.stringify(wire)
      let inner = innerCache.get(wireJson)
      if (inner === undefined) {
        inner = await this.signer.signEvent(buildUnsignedEvent({ content: wireJson }))
        innerCache.set(wireJson, inner)
      }

      const throwaway = generateSecretKey()
      const { unsigned } = await mineDirectEnvelopeEvent(
        JSON.stringify(inner),
        certificate,
        getPublicKey(throwaway),
        { target, onProgress: options.onProgress, signal: options.signal },
      )
      const envelope = await new NsecSigner(throwaway).signEvent(unsigned)
      if (!envelopeMeetsPow(envelope, target)) {
        throw new Error('Signed envelope does not satisfy the PoW target (signer modified it?)')
      }
      const published = await this.transport.publish(envelope, relays)
      results.push({ recipient, event: envelope, published })
    }
    return results
  }

  /* ------------------------------------------------------------------ */
  /* Reading                                                             */
  /* ------------------------------------------------------------------ */

  /**
   * Check your direct mail inbox: pre-filter by your policy's global minimum
   * PoW, decrypt survivors, then enforce your policy per sender (deny lists
   * and category PoW weighed against the outer envelope id). Returns accepted
   * mail and policy-rejected envelopes separately; client-side spam filtering
   * beyond this is the application's business.
   */
  async checkDirectInbox(options: CheckDirectInboxOptions = {}): Promise<ScanDirectResult> {
    const relays = options.relays ?? this.relays
    const myPubkey = await this.signer.getPublicKey()
    const policy = await fetchRecipientPolicy(this.transport, myPubkey, relays).catch(
      () => undefined,
    )
    return scanDirectInbox(this.transport, relays, {
      privateKeyPem: this.certificatePrivateKeyPem,
      targetFilter: options.targetFilter ?? policy?.scanTarget(),
      policy,
      isContact: contactSourceToCallback(options.isContact),
      since: options.since,
      limit: options.limit,
      signal: options.signal,
    })
  }

  /** Subscribe to a broadcast list from its naddr credential. */
  addBroadcastCredential(naddr: string): BroadcastCredential {
    const credential = decodeBroadcastNaddr(naddr)
    this.broadcastCredentials.push(credential)
    return credential
  }

  getBroadcastCredentials(): BroadcastCredential[] {
    return [...this.broadcastCredentials]
  }

  /**
   * Publish a broadcast message to a list. Fresh key material is derived from
   * the password on every call (subscribers read the salt from key_info).
   */
  async publishBroadcast(
    message: BroadcastMessage,
    password: string,
    options: PublishBroadcastOptions = {},
  ): Promise<{ event: NostrEvent; keyInfo: KeyInfoWire; published: PublishResult }> {
    const relays = options.relays ?? this.relays
    const authorPubkey = await this.signer.getPublicKey()
    if (message.getAuthor().length === 0) {
      message.setAuthor(authorPubkey)
    } else if (message.getAuthor() !== authorPubkey) {
      throw new TypeError('message.author must match the client signer identity')
    }

    const keyMaterial = generateBroadcastKey(password)
    const { unsigned, keyInfo } = await mineBroadcastEnvelopeEvent(
      message,
      authorPubkey,
      keyMaterial,
      {
        leadingZeros: options.leadingZeros ?? 0,
        onProgress: options.onProgress,
        signal: options.signal,
      },
    )
    const event = await this.signer.signEvent(unsigned)
    if (event.pubkey !== authorPubkey) {
      throw new Error('Signed event pubkey does not match the signer identity')
    }
    const published = await this.transport.publish(event, relays)
    return { event, keyInfo, published }
  }

  /** Check your broadcast inbox across all subscribed list credentials. */
  async checkBroadcastInbox(options: CheckInboxOptions = {}): Promise<ScannedBroadcast[]> {
    const relays = options.relays ?? this.relays
    return scanBroadcastInbox(this.transport, relays, this.broadcastCredentials, {
      since: options.since,
      limit: options.limit,
      signal: options.signal,
    })
  }
}
