import { describe, expect, it } from 'vitest'
import {
  RecipientPolicy,
  TARGET_NO_CONSTRAINT,
  requirementTarget,
  strictestTarget,
  targetFromLeadingZeros,
  validateRequirement,
} from '../../src/index.js'

const CONTACT = 'b'.repeat(64)
const LISTED = 'c'.repeat(64)
const STRANGER = 'd'.repeat(64)
const DENIED = 'e'.repeat(64)

describe('requirement helpers', () => {
  it('validateRequirement rejects both-fields and neither-field input', () => {
    expect(() => validateRequirement({ target: 'ab'.repeat(32), leadingZeros: 8 })).toThrow(TypeError)
    expect(() => validateRequirement({})).toThrow(TypeError)
  })

  it('validateRequirement rejects malformed values', () => {
    expect(() => validateRequirement({ target: 'not-hex' })).toThrow(TypeError)
    expect(() => validateRequirement({ leadingZeros: 300 })).toThrow(RangeError)
    expect(() => validateRequirement({ leadingZeros: 2.5 })).toThrow(RangeError)
  })

  it('requirementTarget normalizes both forms', () => {
    expect(requirementTarget({ leadingZeros: 8 })).toBe(targetFromLeadingZeros(8))
    expect(requirementTarget({ target: 'abc' })).toBe('0'.repeat(61) + 'abc')
    expect(requirementTarget(undefined)).toBeUndefined()
  })

  it('strictestTarget picks the numerically smallest (hardest) target', () => {
    const easy = targetFromLeadingZeros(0)
    const hard = targetFromLeadingZeros(16)
    expect(strictestTarget(easy, hard)).toBe(hard)
    expect(strictestTarget(hard, easy)).toBe(hard)
    expect(strictestTarget(undefined, hard)).toBe(hard)
    expect(strictestTarget(easy, undefined)).toBe(easy)
    expect(strictestTarget(undefined, undefined)).toBeUndefined()
  })
})

describe('RecipientPolicy.evaluate', () => {
  it('allows everyone with no constraint on an empty policy', () => {
    const decision = new RecipientPolicy().evaluate(STRANGER, false)
    expect(decision).toEqual({ allowed: true, target: TARGET_NO_CONSTRAINT, source: 'none' })
  })

  it('deny.list beats everything', () => {
    const policy = new RecipientPolicy()
      .denyPubKey(DENIED)
      .setAllowUntrustedPolicy({ leadingZeros: 0 })
    const decision = policy.evaluate(DENIED, false)
    expect(decision.allowed).toBe(false)
    if (decision.allowed) throw new Error('unreachable')
    expect(decision.reason).toBe('deny_list')
  })

  it('deny.contacts denies contacts only', () => {
    const policy = new RecipientPolicy().setDenyContacts(true).setAllowUntrustedPolicy({ leadingZeros: 4 })
    expect(policy.evaluate(CONTACT, true)).toMatchObject({ allowed: false, reason: 'deny_contacts' })
    expect(policy.evaluate(STRANGER, false)).toMatchObject({ allowed: true })
  })

  it('deny.untrusted denies strangers, but explicit allow.list overrides it', () => {
    const policy = new RecipientPolicy()
      .setDenyUntrusted(true)
      .setAllowContactsPolicy({ leadingZeros: 2 })
      .allowPubKey(LISTED, { leadingZeros: 6 })

    const stranger = policy.evaluate(STRANGER, false)
    expect(stranger.allowed).toBe(false)
    if (stranger.allowed) throw new Error('unreachable')
    expect(stranger.reason).toBe('deny_untrusted')

    expect(policy.evaluate(LISTED, false)).toMatchObject({ allowed: true, source: 'list' })
    expect(policy.evaluate(CONTACT, true)).toMatchObject({ allowed: true, source: 'contacts' })
  })

  it('resolves the right group policy per sender', () => {
    const policy = new RecipientPolicy()
      .setAllowContactsPolicy({ leadingZeros: 8 })
      .allowPubKey(LISTED, { leadingZeros: 12 })
      .setAllowUntrustedPolicy({ leadingZeros: 16 })

    expect(policy.evaluate(CONTACT, true)).toEqual({
      allowed: true,
      target: targetFromLeadingZeros(8),
      source: 'contacts',
    })
    expect(policy.evaluate(LISTED, false)).toEqual({
      allowed: true,
      target: targetFromLeadingZeros(12),
      source: 'list',
    })
    expect(policy.evaluate(STRANGER, false)).toEqual({
      allowed: true,
      target: targetFromLeadingZeros(16),
      source: 'untrusted',
    })
  })

  it('global_minimum applies as a floor and reports when it wins', () => {
    const policy = new RecipientPolicy()
      .setAllowContactsPolicy({ leadingZeros: 8 })
      .setGlobalMinimum({ leadingZeros: 10 })

    // Stricter than the contacts policy -> global_minimum wins.
    expect(policy.evaluate(CONTACT, true)).toEqual({
      allowed: true,
      target: targetFromLeadingZeros(10),
      source: 'global_minimum',
    })
    // The untrusted policy (16) is stricter than the floor -> it wins.
    policy.setAllowUntrustedPolicy({ leadingZeros: 16 })
    expect(policy.evaluate(STRANGER, false)).toEqual({
      allowed: true,
      target: targetFromLeadingZeros(16),
      source: 'untrusted',
    })
  })

  it('global_minimum alone applies to everyone', () => {
    const policy = new RecipientPolicy().setGlobalMinimum({ leadingZeros: 6 })
    expect(policy.evaluate(STRANGER, false)).toEqual({
      allowed: true,
      target: targetFromLeadingZeros(6),
      source: 'global_minimum',
    })
  })
})

describe('RecipientPolicy.scanTarget (pre-decryption filter)', () => {
  it('is the GLOBAL MINIMUM only — category requirements are post-decryption', () => {
    const policy = new RecipientPolicy()
      .setAllowContactsPolicy({ leadingZeros: 0 })
      .allowPubKey(LISTED, { leadingZeros: 12 })
      .setAllowUntrustedPolicy({ leadingZeros: 16 })
      .setGlobalMinimum({ leadingZeros: 8 })
    // The pre-filter is the floor everyone must clear; the lenient contacts
    // category is enforced AFTER decryption, once the sender is known.
    expect(policy.scanTarget()).toBe(targetFromLeadingZeros(8))
  })

  it('returns no-constraint when no global minimum is set (attempt everything)', () => {
    expect(
      new RecipientPolicy().setAllowUntrustedPolicy({ leadingZeros: 16 }).scanTarget(),
    ).toBe(TARGET_NO_CONSTRAINT)
  })
})

describe('RecipientPolicy wire format', () => {
  it('locks the exact wire shape of a full policy', () => {
    const policy = new RecipientPolicy()
      .setAllowContactsPolicy({ leadingZeros: 8 })
      .allowPubKey(LISTED, { target: 'ab'.repeat(32) })
      .setAllowUntrustedPolicy({ leadingZeros: 16 })
      .denyPubKey(DENIED)
      .setDenyUntrusted(true)
      .setGlobalMinimum({ leadingZeros: 4 })

    expect(policy.toWire()).toEqual({
      allow: {
        contacts: { leadingzeros: 8 },
        list: { [LISTED]: { target: 'ab'.repeat(32) } },
        untrusted: { leadingzeros: 16 },
      },
      deny: {
        list: [DENIED],
        untrusted: true,
      },
      global_minimum: { leadingzeros: 4 },
    })
  })

  it('round-trips through the wire form (both requirement forms preserved)', () => {
    const policy = new RecipientPolicy()
      .setAllowContactsPolicy({ leadingZeros: 8 })
      .allowPubKey(LISTED, { target: 'ab'.repeat(32) })
      .setAllowUntrustedPolicy({ leadingZeros: 16 })
      .denyPubKey(DENIED)
      .setDenyContacts(true)
      .setGlobalMinimum({ leadingZeros: 4 })

    const restored = RecipientPolicy.fromWire(policy.toWire())
    expect(restored.toWire()).toEqual(policy.toWire())
  })

  it('imports from a JSON string', () => {
    const policy = new RecipientPolicy().setAllowUntrustedPolicy({ leadingZeros: 8 })
    const restored = RecipientPolicy.fromWire(policy.toJson())
    expect(restored.toWire()).toEqual(policy.toWire())
  })

  it('skips malformed entries on import (robust reading)', () => {
    const wire = {
      allow: {
        contacts: { leadingzeros: 8 },
        list: {
          ['not-hex']: { leadingzeros: 4 },
          [LISTED]: { leadingzeros: 'many' },
          [STRANGER]: { leadingzeros: 12 },
        },
      },
      deny: { list: ['also-not-hex', DENIED] },
      global_minimum: { target: 'zz' },
    }
    const restored = RecipientPolicy.fromWire(wire as never)
    expect(restored.evaluate(STRANGER, false)).toMatchObject({ allowed: true, source: 'list' })
    const denied = restored.evaluate(DENIED, false)
    expect(denied.allowed).toBe(false)
    if (denied.allowed) throw new Error('unreachable')
    expect(denied.reason).toBe('deny_list')
    // global_minimum was malformed -> contacts policy applies to contacts
    expect(restored.evaluate(CONTACT, true)).toMatchObject({ allowed: true, source: 'contacts' })
  })

  it('prefers target when a non-conforming requirement has both keys', () => {
    const both = targetFromLeadingZeros(4)
    const policy = RecipientPolicy.fromWire({
      global_minimum: { target: both, leadingzeros: 24 },
    })
    // target wins; leadingzeros is ignored.
    expect(policy.evaluate(STRANGER, false)).toEqual({
      allowed: true,
      target: both,
      source: 'global_minimum',
    })
  })

  it('rejects non-object wire content', () => {
    expect(() => RecipientPolicy.fromWire('[1,2]' as never)).toThrow()
    expect(() => RecipientPolicy.fromWire(42 as never)).toThrow(TypeError)
  })
})
