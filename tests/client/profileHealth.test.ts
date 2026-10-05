import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  DirectMessage,
  NsecSigner,
  NvelopeClient,
  RecipientPolicy,
  buildUnsignedEvent,
  createProfileEvent,
  fetchRecipientPolicy,
  finalizeWithNsec,
  generateMailCertificate,
} from '../../src/index.js'
import { FakeTransport } from '../relay/fakeTransport.js'

const RELAYS = ['wss://relay.example']

async function makeClient(transport: FakeTransport) {
  const secretKey = generateSecretKey()
  const cert = generateMailCertificate()
  const client = new NvelopeClient({
    transport,
    signer: new NsecSigner(secretKey),
    relays: RELAYS,
    certificatePrivateKeyPem: cert.privateKeyPem,
  })
  return { client, secretKey, pubkey: getPublicKey(secretKey), cert }
}

/** A properly SIGNED profile event whose content is garbage. */
function signedGarbageEvent(dTag: string, content: string, secretKey: Uint8Array) {
  return finalizeWithNsec(
    buildUnsignedEvent({ kind: 30998, tags: [['d', dTag]], content, createdAt: 1000 }),
    secretKey,
  )
}

describe('sendDirectMail rejects invalid published profiles (onus on recipient)', () => {
  it('rejects a corrupt recipient policy with a clear error', async () => {
    const transport = new FakeTransport()
    const alice = await makeClient(transport)
    const bob = await makeClient(transport)

    transport.seed(
      createProfileEvent('nv_public_key', bob.cert.publicKeyDerBase64, bob.secretKey),
      signedGarbageEvent('nv_recipient_profile', '{broken json', bob.secretKey),
    )

    const message = new DirectMessage().addRecipientTo(bob.pubkey).setPlaintext('x')
    await expect(alice.client.sendDirectMail(message)).rejects.toThrow(/invalid recipient policy/)
  })

  it('rejects a corrupt certificate with a clear error', async () => {
    const transport = new FakeTransport()
    const alice = await makeClient(transport)
    const bob = await makeClient(transport)

    transport.seed(signedGarbageEvent('nv_public_key', 'not-a-der-key', bob.secretKey))

    const message = new DirectMessage().addRecipientTo(bob.pubkey).setPlaintext('x')
    await expect(alice.client.sendDirectMail(message)).rejects.toThrow(/invalid mail certificate/)
  })

  it('still treats a blank (empty-object) policy as open', async () => {
    const transport = new FakeTransport()
    const alice = await makeClient(transport)
    const bob = await makeClient(transport)

    transport.seed(
      createProfileEvent('nv_public_key', bob.cert.publicKeyDerBase64, bob.secretKey),
      createProfileEvent('nv_recipient_profile', '{}', bob.secretKey),
    )

    const message = new DirectMessage().addRecipientTo(bob.pubkey).setSubject('open').setPlaintext('x')
    const sent = await alice.client.sendDirectMail(message)
    expect(sent).toHaveLength(1)

    const { inbox } = await bob.client.checkDirectInbox()
    expect(inbox).toHaveLength(1)
  })
})

describe('checkProfile (voluntary self-check)', () => {
  it('reports healthy after publishProfile', async () => {
    const transport = new FakeTransport()
    const { client } = await makeClient(transport)
    await client.publishProfile(new RecipientPolicy().setGlobalMinimum({ leadingZeros: 4 }))

    const health = await client.checkProfile()
    expect(health).toEqual({ certificate: 'ok', policy: 'ok', healthy: true })
  })

  it('reports missing components for a fresh identity', async () => {
    const transport = new FakeTransport()
    const { client } = await makeClient(transport)
    expect(await client.checkProfile()).toEqual({
      certificate: 'missing',
      policy: 'missing',
      healthy: false,
    })
  })

  it('reports corrupt when a published event fails validation', async () => {
    const transport = new FakeTransport()
    const { client, secretKey } = await makeClient(transport)
    transport.seed(signedGarbageEvent('nv_recipient_profile', 'not json at all', secretKey))

    const health = await client.checkProfile()
    expect(health.policy).toBe('corrupt')
    expect(health.healthy).toBe(false)
  })

  it('reports mismatch when relays hold a different certificate than local', async () => {
    const transport = new FakeTransport()
    const { client, secretKey } = await makeClient(transport)
    const staleCert = generateMailCertificate()
    transport.seed(
      createProfileEvent('nv_public_key', staleCert.publicKeyDerBase64, secretKey),
      createProfileEvent('nv_recipient_profile', '{}', secretKey),
    )

    const health = await client.checkProfile()
    expect(health.certificate).toBe('mismatch')
    expect(health.policy).toBe('ok')
  })
})

describe('repairProfile', () => {
  it('republishes missing components and becomes healthy', async () => {
    const transport = new FakeTransport()
    const { client } = await makeClient(transport)

    await client.repairProfile()
    expect(await client.checkProfile()).toEqual({
      certificate: 'ok',
      policy: 'ok',
      healthy: true,
    })
  })

  it('preserves an importable published policy rather than resetting it', async () => {
    const transport = new FakeTransport()
    const { client, secretKey, pubkey } = await makeClient(transport)

    // Someone (or an earlier session) published a real policy; the cert event
    // is missing. Repair must keep the policy intact.
    const existing = new RecipientPolicy().setAllowUntrustedPolicy({ leadingZeros: 8 })
    transport.seed(createProfileEvent('nv_recipient_profile', existing.toJson(), secretKey))

    await client.repairProfile()
    expect(await client.checkProfile()).toMatchObject({ healthy: true })

    const policy = await fetchRecipientPolicy(transport, pubkey, RELAYS)
    expect(policy?.toWire()).toEqual(existing.toWire())
  })

  it('an explicit policy argument wins during repair', async () => {
    const transport = new FakeTransport()
    const { client } = await makeClient(transport)
    const replacement = new RecipientPolicy().setGlobalMinimum({ leadingZeros: 12 })

    await client.repairProfile(replacement)
    const health = await client.checkProfile()
    expect(health.healthy).toBe(true)
  })
})
