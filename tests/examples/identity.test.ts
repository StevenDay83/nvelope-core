import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { getPublicKey } from 'nostr-tools/pure'
import { identityPath, identityPubkey, loadOrCreateIdentity } from '../../examples/identity.js'

let dir: string
const originalEnv = process.env.IDENTITY_FILE

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'nvelope-identity-'))
  process.env.IDENTITY_FILE = join(dir, 'identity.json')
})

afterEach(() => {
  if (originalEnv === undefined) {
    delete process.env.IDENTITY_FILE
  } else {
    process.env.IDENTITY_FILE = originalEnv
  }
  rmSync(dir, { recursive: true, force: true })
})

describe('demo identity keystore', () => {
  it('creates an identity file on first use and reuses it after', () => {
    const first = loadOrCreateIdentity()
    expect(first.created).toBe(true)
    expect(identityPath()).toBe(join(dir, 'identity.json'))

    const second = loadOrCreateIdentity()
    expect(second.created).toBe(false)
    expect(identityPubkey(second.identity)).toBe(identityPubkey(first.identity))
    expect(second.identity.certificatePrivateKeyPem).toBe(
      first.identity.certificatePrivateKeyPem,
    )
  })

  it('seeds the nsec from NSEC_HEX when set', () => {
    const nsecHex = 'ab'.repeat(32)
    process.env.NSEC_HEX = nsecHex
    const { identity } = loadOrCreateIdentity()
    expect(identityPubkey(identity)).toBe(getPublicKey(new Uint8Array(Buffer.from(nsecHex, 'hex'))))
    delete process.env.NSEC_HEX
  })

  it('throws a helpful error on a malformed file', () => {
    writeFileSync(identityPath(), '{"nsecHex":"not-hex"}')
    expect(() => loadOrCreateIdentity()).toThrow(/malformed/)
  })

  it('throws a helpful error on non-JSON content', () => {
    writeFileSync(identityPath(), 'definitely not json')
    expect(() => loadOrCreateIdentity()).toThrow(/not valid JSON/)
  })

  it('stores the certificate alongside the nsec', () => {
    const { identity } = loadOrCreateIdentity()
    const raw = JSON.parse(readFileSync(identityPath(), 'utf8'))
    expect(raw.certificatePublicKeyDerBase64).toBe(identity.certificatePublicKeyDerBase64)
    expect(raw.certificatePrivateKeyPem).toContain('PRIVATE KEY')
  })
})
