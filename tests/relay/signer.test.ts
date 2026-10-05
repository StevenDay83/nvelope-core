import { describe, expect, it } from 'vitest'
import { generateSecretKey } from 'nostr-tools/pure'
import { NsecSigner, buildUnsignedEvent, publicKeyOf, verifyNostrEvent } from '../../src/index.js'

describe('NsecSigner', () => {
  it('reports the pubkey matching the nsec', async () => {
    const secretKey = generateSecretKey()
    const signer = new NsecSigner(secretKey)
    expect(await signer.getPublicKey()).toBe(publicKeyOf(secretKey))
  })

  it('signs events that verify', async () => {
    const secretKey = generateSecretKey()
    const signer = new NsecSigner(secretKey)
    const event = await signer.signEvent(buildUnsignedEvent({ content: 'signed by signer' }))

    expect(event.pubkey).toBe(publicKeyOf(secretKey))
    expect(verifyNostrEvent(event)).toBe(true)
  })

  it('rejects malformed nsecs', () => {
    expect(() => new NsecSigner(new Uint8Array(16))).toThrow(RangeError)
    expect(() => new NsecSigner('not-bytes' as unknown as Uint8Array)).toThrow(RangeError)
  })
})
