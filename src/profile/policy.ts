/**
 * Recipient policy — the rules a Nostr-Mail recipient publishes in their
 * nv_recipient_profile event (kind 30998): who may send, and how much
 * proof-of-work their blinded envelope must carry.
 *
 * Wire format (locked by tests): RecipientPolicyWire (see types.ts):
 *   { allow?: { contacts?, list?: {pubkey: req}, untrusted? },
 *     deny?: { list?: pubkeys[], contacts?, untrusted? },
 *     global_minimum? }
 * where a requirement req is { target: <64-hex> } or { leadingzeros: n }.
 *
 * Semantics (the pre-refactor code never implemented evaluation; these are
 * the protocol rules this library enforces):
 * - deny.list beats everything.
 * - deny.contacts denies Nostr-contacts; deny.untrusted denies everyone not
 *   explicitly allowed and not a contact.
 * - An explicit allow.list entry for a sender overrides deny.untrusted
 *   (an explicit allow is an invitation).
 * - Otherwise: contacts -> contacts policy, allow.list -> per-key policy,
 *   everyone else -> untrusted policy.
 * - global_minimum always applies as a floor: the effective requirement is
 *   the STRICTEST (numerically smallest target) of the applicable requirement
 *   and global_minimum.
 */
import { PROFILE_POLICY_FIELDS as F } from '../constants.js'
import type {
  AllowPolicyWire,
  DenyPolicyWire,
  Hex256,
  PowPolicyWire,
  RecipientPolicyWire,
} from '../types.js'
import {
  TARGET_NO_CONSTRAINT,
  assertHex256,
  isHex256,
  normalizeHex256,
  targetFromLeadingZeros,
} from '../crypto/pow.js'

/** A proof-of-work requirement: an explicit target OR a leading-zero count. */
export interface PowRequirement {
  /** 256-bit PoW target (event id must be < target). */
  target?: string
  /** Leading zero bits (NIP-13 style). */
  leadingZeros?: number
}

/** The outcome of evaluating a policy for one sender. */
export type PolicyDecision = PolicyAllowance | PolicyDenial

export interface PolicyAllowance {
  allowed: true
  /** Effective PoW target the sender's envelope must satisfy. */
  target: string
  /** Which group produced the requirement (for UI display). */
  source: 'contacts' | 'list' | 'untrusted' | 'global_minimum' | 'none'
}

export interface PolicyDenial {
  allowed: false
  reason: 'deny_list' | 'deny_contacts' | 'deny_untrusted'
}

/** Validate a requirement. @throws on malformed input or both fields set. */
export function validateRequirement(requirement: PowRequirement): PowRequirement {
  if (requirement.target !== undefined && requirement.leadingZeros !== undefined) {
    throw new TypeError('requirement: target and leadingZeros are mutually exclusive')
  }
  if (requirement.target !== undefined) {
    normalizeHex256(requirement.target)
    return { target: requirement.target }
  }
  if (requirement.leadingZeros !== undefined) {
    targetFromLeadingZeros(requirement.leadingZeros)
    return { leadingZeros: requirement.leadingZeros }
  }
  throw new TypeError('requirement needs a target or leadingZeros')
}

/** Normalize a requirement to its effective target hex (undefined if absent). */
export function requirementTarget(requirement: PowRequirement | undefined): string | undefined {
  if (requirement === undefined) return undefined
  if (requirement.target !== undefined) return normalizeHex256(requirement.target)
  return targetFromLeadingZeros(requirement.leadingZeros ?? 0)
}

/** The numerically smallest target (hardest PoW); undefined if both absent. */
export function strictestTarget(a: string | undefined, b: string | undefined): string | undefined {
  if (a === undefined) return b
  if (b === undefined) return a
  return BigInt(`0x${a}`) <= BigInt(`0x${b}`) ? a : b
}

export class RecipientPolicy {
  private allowContacts: PowRequirement | undefined
  private readonly allowList = new Map<Hex256, PowRequirement>()
  private allowUntrusted: PowRequirement | undefined
  private readonly denyList = new Set<Hex256>()
  private denyContacts = false
  private denyUntrusted = false
  private globalMinimum: PowRequirement | undefined

  /* -- setters -- */

  setAllowContactsPolicy(requirement: PowRequirement): this {
    this.allowContacts = validateRequirement(requirement)
    return this
  }

  setAllowUntrustedPolicy(requirement: PowRequirement): this {
    this.allowUntrusted = validateRequirement(requirement)
    return this
  }

  /** Explicitly allow one sender (overrides deny.untrusted). */
  allowPubKey(pubkey: Hex256, requirement: PowRequirement): this {
    assertHex256(pubkey, 'allowList pubkey')
    this.allowList.set(pubkey, validateRequirement(requirement))
    return this
  }

  removeAllowPubKey(pubkey: Hex256): boolean {
    return this.allowList.delete(pubkey)
  }

  denyPubKey(pubkey: Hex256): this {
    assertHex256(pubkey, 'denyList pubkey')
    this.denyList.add(pubkey)
    return this
  }

  undenyPubKey(pubkey: Hex256): boolean {
    return this.denyList.delete(pubkey)
  }

  setDenyContacts(deny: boolean): this {
    this.denyContacts = deny
    return this
  }

  setDenyUntrusted(deny: boolean): this {
    this.denyUntrusted = deny
    return this
  }

  /** Floor requirement applied to every sender, regardless of group. */
  setGlobalMinimum(requirement: PowRequirement): this {
    this.globalMinimum = validateRequirement(requirement)
    return this
  }

  /* -- evaluation -- */

  /**
   * Evaluate the policy for one sender.
   *
   * @param senderPubkey the sender's npub (hex)
   * @param isContact whether the sender is in the recipient's Nostr contacts
   *   (determined by the caller from their contact list)
   */
  evaluate(senderPubkey: Hex256, isContact: boolean): PolicyDecision {
    assertHex256(senderPubkey, 'senderPubkey')

    if (this.denyList.has(senderPubkey)) {
      return { allowed: false, reason: 'deny_list' }
    }
    if (isContact && this.denyContacts) {
      return { allowed: false, reason: 'deny_contacts' }
    }

    let target: string | undefined = undefined
    let source: PolicyAllowance['source'] = 'none'

    const listed = this.allowList.get(senderPubkey)
    if (listed !== undefined) {
      target = requirementTarget(listed)
      source = 'list'
    } else if (isContact) {
      target = requirementTarget(this.allowContacts)
      source = 'contacts'
    } else {
      if (this.denyUntrusted) {
        return { allowed: false, reason: 'deny_untrusted' }
      }
      target = requirementTarget(this.allowUntrusted)
      source = 'untrusted'
    }

    // global_minimum is a floor: the strictest of the two wins.
    const globalTarget = requirementTarget(this.globalMinimum)
    const globalIsStricter =
      globalTarget !== undefined &&
      (target === undefined || BigInt(`0x${globalTarget}`) < BigInt(`0x${target}`))
    const finalTarget = globalIsStricter ? globalTarget : (target ?? TARGET_NO_CONSTRAINT)
    const finalSource: PolicyAllowance['source'] = globalIsStricter
      ? 'global_minimum'
      : target === undefined
        ? 'none'
        : source
    return { allowed: true, target: finalTarget, source: finalSource }
  }

  /**
   * PoW pre-filter target for envelope scanning: the GLOBAL MINIMUM
   * requirement. Envelopes whose id fails this target are discarded BEFORE
   * any decryption attempt ("no further consideration").
   *
   * Category requirements (contacts/list/untrusted) cannot be pre-filtered —
   * the sender is unknowable until decryption — so they are enforced
   * POST-decryption against the outer envelope id (see scanDirectInbox).
   *
   * Returns TARGET_NO_CONSTRAINT when no global minimum is set: every
   * envelope is attempted, and all enforcement happens post-decryption.
   */
  scanTarget(): string {
    return requirementTarget(this.globalMinimum) ?? TARGET_NO_CONSTRAINT
  }

  /* -- wire format -- */

  toWire(): RecipientPolicyWire {
    const allow: AllowPolicyWire = {}
    if (this.allowContacts !== undefined) {
      allow[F.contacts] = requirementToWire(this.allowContacts)
    }
    if (this.allowList.size > 0) {
      const list: Record<Hex256, PowPolicyWire> = {}
      for (const [pubkey, requirement] of this.allowList) {
        list[pubkey] = requirementToWire(requirement)
      }
      allow[F.list] = list
    }
    if (this.allowUntrusted !== undefined) {
      allow[F.untrusted] = requirementToWire(this.allowUntrusted)
    }

    const deny: DenyPolicyWire = {}
    if (this.denyList.size > 0) {
      deny[F.list] = [...this.denyList]
    }
    if (this.denyContacts) {
      deny[F.contacts] = true
    }
    if (this.denyUntrusted) {
      deny[F.untrusted] = true
    }

    const wire: RecipientPolicyWire = {}
    if (Object.keys(allow).length > 0) wire[F.allow] = allow
    if (Object.keys(deny).length > 0) wire[F.deny] = deny
    if (this.globalMinimum !== undefined) {
      wire[F.globalMinimum] = requirementToWire(this.globalMinimum)
    }
    return wire
  }

  /** Convenience: the wire object as a JSON string (profile event content). */
  toJson(): string {
    return JSON.stringify(this.toWire())
  }

  /** Import from wire form; malformed entries are skipped (robust reading). */
  static fromWire(wire: RecipientPolicyWire | string): RecipientPolicy {
    const parsed: RecipientPolicyWire =
      typeof wire === 'string'
        ? (JSON.parse(wire) as RecipientPolicyWire) // throws SyntaxError on bad JSON
        : wire
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new TypeError('Recipient policy must be an object')
    }

    const policy = new RecipientPolicy()

    const allow = parsed[F.allow]
    if (allow !== null && typeof allow === 'object' && !Array.isArray(allow)) {
      const contacts = requirementFromWire(allow[F.contacts])
      if (contacts !== undefined) policy.allowContacts = contacts
      const untrusted = requirementFromWire(allow[F.untrusted])
      if (untrusted !== undefined) policy.allowUntrusted = untrusted
      const list = allow[F.list]
      if (list !== null && typeof list === 'object' && !Array.isArray(list)) {
        for (const [pubkey, requirement] of Object.entries(list)) {
          if (!isHex256(pubkey)) continue
          const req = requirementFromWire(requirement)
          if (req !== undefined) policy.allowList.set(pubkey, req)
        }
      }
    }

    // NOTE: deny is imported independently of allow — the pre-refactor code
    // only processed deny when allow was present (a nesting bug).
    const deny = parsed[F.deny]
    if (deny !== null && typeof deny === 'object' && !Array.isArray(deny)) {
      const denyEntries = deny[F.list]
      if (Array.isArray(denyEntries)) {
        for (const pubkey of denyEntries) {
          if (isHex256(pubkey)) policy.denyList.add(pubkey)
        }
      }
      if (deny[F.contacts] === true) policy.denyContacts = true
      if (deny[F.untrusted] === true) policy.denyUntrusted = true
    }

    const globalMinimum = requirementFromWire(parsed[F.globalMinimum])
    if (globalMinimum !== undefined) policy.globalMinimum = globalMinimum

    return policy
  }
}

function requirementToWire(requirement: PowRequirement): PowPolicyWire {
  if (requirement.target !== undefined) {
    return { target: normalizeHex256(requirement.target) }
  }
  return { leadingzeros: requirement.leadingZeros ?? 0 }
}

function requirementFromWire(value: unknown): PowRequirement | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const { target, leadingzeros } = value as Record<string, unknown>
  if (typeof target === 'string') {
    try {
      return { target: normalizeHex256(target) }
    } catch {
      return undefined
    }
  }
  if (typeof leadingzeros === 'number' && Number.isInteger(leadingzeros) && leadingzeros >= 0 && leadingzeros <= 255) {
    return { leadingZeros: leadingzeros }
  }
  return undefined
}
