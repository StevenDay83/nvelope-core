import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  MailProfile,
  buildUnsignedEvent,
  createProfileEvent,
  fetchCertificate,
  fetchRecipientPolicy,
  finalizeWithNsec,
  generateMailCertificate,
  publicKeyDerBase64ToPem,
} from '../../src/index.js'
import { FakeTransport } from './fakeTransport.js'

const RELAYS = ['wss://relay.example']
const ownerKey = generateSecretKey()
const OWNER = getPublicKey(ownerKey)

describe('fetchCertificate', () => {
  it('returns the published certificate in PEM form', async () => {
    const transport = new FakeTransport()
    const cert = generateMailCertificate()

    transport.seed(createProfileEvent('nv_public_key', cert.publicKeyDerBase64, ownerKey))

    const resolved = await fetchCertificate(transport, OWNER, RELAYS)
    expect(resolved?.derBase64).toBe(cert.publicKeyDerBase64)
    expect(resolved?.pem).toBe(publicKeyDerBase64ToPem(cert.publicKeyDerBase64))
  })

  it('returns undefined when the owner published nothing', async () => {
    const transport = new FakeTransport()
    expect(await fetchCertificate(transport, OWNER, RELAYS)).toBeUndefined()
  })

  it('returns the NEWEST certificate when several are published', async () => {
    const transport = new FakeTransport()

    // Timestamps are baked in BEFORE signing — profile import now verifies
    // signatures, so mutating created_at after signing would (correctly) fail.
    const older = finalizeWithNsec(
      buildUnsignedEvent({
        kind: 30998,
        tags: [['d', 'nv_public_key']],
        content: generateMailCertificate().publicKeyDerBase64,
        createdAt: 1000,
      }),
      ownerKey,
    )
    const newerCert = generateMailCertificate()
    const newer = finalizeWithNsec(
      buildUnsignedEvent({
        kind: 30998,
        tags: [['d', 'nv_public_key']],
        content: newerCert.publicKeyDerBase64,
        createdAt: 2000,
      }),
      ownerKey,
    )
    transport.seed(older, newer)

    const resolved = await fetchCertificate(transport, OWNER, RELAYS)
    expect(resolved?.derBase64).toBe(newerCert.publicKeyDerBase64)
  })

  it('rejects a non-hex owner', async () => {
    const transport = new FakeTransport()
    await expect(fetchCertificate(transport, 'nope', RELAYS)).rejects.toThrow(TypeError)
  })
})

describe('fetchRecipientPolicy', () => {
  it('returns the published policy', async () => {
    const transport = new FakeTransport()

    const profile = new MailProfile()
    profile.policy.setAllowUntrustedPolicy({ leadingZeros: 12 }).setGlobalMinimum({ leadingZeros: 4 })
    transport.seed(createProfileEvent('nv_recipient_profile', profile.toPolicyJson(), ownerKey))

    const policy = await fetchRecipientPolicy(transport, OWNER, RELAYS)
    expect(policy?.toWire()).toEqual(profile.policy.toWire())
  })

  it('returns undefined when no policy is published', async () => {
    const transport = new FakeTransport()
    expect(await fetchRecipientPolicy(transport, OWNER, RELAYS)).toBeUndefined()
  })
})
