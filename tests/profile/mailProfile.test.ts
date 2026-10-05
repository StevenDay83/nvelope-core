import { describe, expect, it } from 'vitest'
import { generateSecretKey } from 'nostr-tools/pure'
import {
  MailProfile,
  RecipientPolicy,
  createProfileEvent,
  generateMailCertificate,
  verifyNostrEvent,
} from '../../src/index.js'

const LISTED = 'c'.repeat(64)

describe('MailProfile certificate', () => {
  it('sets and returns the certificate public key', () => {
    const cert = generateMailCertificate()
    const profile = new MailProfile().setCertificate(cert.publicKeyDerBase64)
    expect(profile.getCertificate()).toBe(cert.publicKeyDerBase64)
  })

  it('rejects malformed certificates', () => {
    expect(() => new MailProfile().setCertificate('not a der key')).toThrow(TypeError)
  })
})

describe('createProfileEvent', () => {
  it('creates a signed kind-30998 event with the given d tag', () => {
    const secretKey = generateSecretKey()
    const event = createProfileEvent('nv_recipient_profile', '{"allow":{}}', secretKey)

    expect(event.kind).toBe(30998)
    expect(event.tags).toEqual([['d', 'nv_recipient_profile']])
    expect(verifyNostrEvent(event)).toBe(true)
  })

  it('rejects unknown d tags and empty content', () => {
    const secretKey = generateSecretKey()
    expect(() => createProfileEvent('nv_bogus', '{}', secretKey)).toThrow(TypeError)
    expect(() => createProfileEvent('nv_public_key', '', secretKey)).toThrow(TypeError)
  })
})

describe('profile event round-trips', () => {
  it('policy event content imports back to an equivalent policy', () => {
    const profile = new MailProfile()
    profile.policy.setAllowContactsPolicy({ leadingZeros: 8 }).setGlobalMinimum({ leadingZeros: 4 })

    const secretKey = generateSecretKey()
    const event = createProfileEvent('nv_recipient_profile', profile.toPolicyJson(), secretKey)

    const imported = MailProfile.importPolicyEvent(event)
    expect(imported.toWire()).toEqual(profile.policy.toWire())
  })

  it('certificate event content imports back to the same key', () => {
    const cert = generateMailCertificate()
    const secretKey = generateSecretKey()
    const event = createProfileEvent('nv_public_key', cert.publicKeyDerBase64, secretKey)

    expect(MailProfile.importCertificateEvent(event)).toBe(cert.publicKeyDerBase64)
  })

  it('importCertificateEvent validates the key material', () => {
    const secretKey = generateSecretKey()
    const bad = createProfileEvent('nv_public_key', 'aGVsbG8=', secretKey) // base64 of "hello"
    expect(() => MailProfile.importCertificateEvent(bad)).toThrow(TypeError)
  })

  it('rejects events with the wrong kind or d tag', () => {
    const secretKey = generateSecretKey()
    const cert = generateMailCertificate()
    const certEvent = createProfileEvent('nv_public_key', cert.publicKeyDerBase64, secretKey)
    expect(() => MailProfile.importPolicyEvent(certEvent)).toThrow(TypeError)

    const tampered = { ...certEvent, kind: 30000 }
    expect(() => MailProfile.importCertificateEvent(tampered)).toThrow(TypeError)
  })
})

describe('regression: deny imports independently of allow (pre-refactor nesting bug)', () => {
  it('imports a deny-only policy', () => {
    const denyOnly = JSON.stringify({ deny: { list: [LISTED] } })
    const imported = MailProfile.importPolicyEvent(denyOnly)

    const decision = imported.evaluate(LISTED, false)
    expect(decision.allowed).toBe(false)
    if (decision.allowed) throw new Error('unreachable')
    expect(decision.reason).toBe('deny_list')
  })
})

describe('fromPolicyWire', () => {
  it('builds a profile from wire content', () => {
    const policy = new RecipientPolicy().setAllowUntrustedPolicy({ leadingZeros: 8 })
    const profile = MailProfile.fromPolicyWire(policy.toWire())
    expect(profile.policy.toWire()).toEqual(policy.toWire())
    expect(profile.getCertificate()).toBe('')
  })
})
