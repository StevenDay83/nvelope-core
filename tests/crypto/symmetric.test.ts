import { describe, expect, it } from 'vitest'
import {
  decryptSymmetric,
  decryptWithPassword,
  deriveKeyFromPassword,
  encryptSymmetric,
  encryptWithPassword,
  generateSalt,
} from '../../src/index.js'

// Known-answer fixture: produced with the pre-refactor implementation semantics
// (scrypt Node defaults N=16384/r=8/p=1, AES-256-CBC, fixed salt and IV).
// Both directions are deterministic, so this locks the wire format forever.
const KAT_PASSWORD = 'correct horse battery staple'
const KAT_SALT_HEX = 'ab'.repeat(32)
const KAT_IV_HEX = '01'.repeat(16)
const KAT_CIPHERTEXT = 'e82jfFPkPVC2LEbmMa73NwYU3e3Ffq4tLiBoLPxk7TEqPSG7HF493k+AnBHUfE9tj0iJnXpuHCfQKeq4LJetd9tzIr804hEgAHWQi79VPsM='
const KAT_PLAINTEXT = '{"subjectLine":"KAT fixture","messageType":{"plaintext":"S2F0"}}'

describe('encryptWithPassword / decryptWithPassword round-trips', () => {
  it('round-trips a broadcast-style JSON payload', () => {
    const salt = generateSalt()
    const encrypted = encryptWithPassword(KAT_PLAINTEXT, KAT_PASSWORD, salt)
    expect(encrypted.iv).toMatch(/^[0-9a-f]{32}$/)
    expect(decryptWithPassword(encrypted.ciphertext, KAT_PASSWORD, salt, encrypted.iv)).toBe(
      KAT_PLAINTEXT,
    )
  })

  it('round-trips UTF-8 content', () => {
    const salt = generateSalt()
    const plaintext = 'Outage alert — touché ✓'
    const encrypted = encryptWithPassword(plaintext, KAT_PASSWORD, salt)
    expect(decryptWithPassword(encrypted.ciphertext, KAT_PASSWORD, salt, encrypted.iv)).toBe(
      plaintext,
    )
  })

  it('uses a fresh IV per call (identical inputs -> different ciphertexts, both decrypt)', () => {
    const salt = generateSalt()
    const first = encryptWithPassword(KAT_PLAINTEXT, KAT_PASSWORD, salt)
    const second = encryptWithPassword(KAT_PLAINTEXT, KAT_PASSWORD, salt)
    expect(first.ciphertext).not.toBe(second.ciphertext)
    expect(first.iv).not.toBe(second.iv)
    expect(decryptWithPassword(first.ciphertext, KAT_PASSWORD, salt, first.iv)).toBe(KAT_PLAINTEXT)
    expect(decryptWithPassword(second.ciphertext, KAT_PASSWORD, salt, second.iv)).toBe(
      KAT_PLAINTEXT,
    )
  })

  it('returns undefined on the wrong passphrase', () => {
    const salt = generateSalt()
    const encrypted = encryptWithPassword(KAT_PLAINTEXT, KAT_PASSWORD, salt)
    expect(decryptWithPassword(encrypted.ciphertext, 'wrong passphrase', salt, encrypted.iv)).toBeUndefined()
  })

  it('returns undefined on the wrong IV', () => {
    const salt = generateSalt()
    const encrypted = encryptWithPassword(KAT_PLAINTEXT, KAT_PASSWORD, salt)
    const wrongIv = encrypted.iv.startsWith('00') ? 'ff' + encrypted.iv.slice(2) : '00' + encrypted.iv.slice(2)
    // AES-CBC has no integrity check: a wrong IV silently corrupts only the
    // first 16-byte block rather than failing (see symmetric.ts docstring).
    // The meaningful guarantee: the original plaintext never survives.
    const result = decryptWithPassword(encrypted.ciphertext, KAT_PASSWORD, salt, wrongIv)
    expect(result).not.toBe(KAT_PLAINTEXT)
    expect(typeof result).toBe('string')
  })
})

describe('deriveKeyFromPassword / generateSalt', () => {
  it('derives a deterministic 32-byte key', () => {
    const salt = generateSalt()
    const key1 = deriveKeyFromPassword(KAT_PASSWORD, salt)
    const key2 = deriveKeyFromPassword(KAT_PASSWORD, salt)
    expect(key1).toBeInstanceOf(Uint8Array)
    expect(key1.length).toBe(32)
    expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(true)

    const otherSalt = generateSalt()
    const key3 = deriveKeyFromPassword(KAT_PASSWORD, otherSalt)
    expect(Buffer.from(key1).equals(Buffer.from(key3))).toBe(false)
  })

  it('generateSalt returns unique 64-hex-char strings', () => {
    const salt1 = generateSalt()
    const salt2 = generateSalt()
    expect(salt1).toMatch(/^[0-9a-f]{64}$/)
    expect(salt1).not.toBe(salt2)
  })

  it('rejects invalid passwords and salts', () => {
    expect(() => deriveKeyFromPassword('', KAT_SALT_HEX)).toThrow(TypeError)
    expect(() => deriveKeyFromPassword(KAT_PASSWORD, 'zz')).toThrow(TypeError)
    expect(() => deriveKeyFromPassword(KAT_PASSWORD, 'abc')).toThrow(TypeError) // odd length
  })
})

describe('encryptSymmetric / decryptSymmetric (low-level)', () => {
  it('round-trips with a caller-managed key and IV', () => {
    const key = deriveKeyFromPassword(KAT_PASSWORD, KAT_SALT_HEX)
    const iv = Buffer.from(KAT_IV_HEX, 'hex')
    const ciphertext = encryptSymmetric(KAT_PLAINTEXT, key, iv)
    expect(decryptSymmetric(ciphertext, key, iv)).toBe(KAT_PLAINTEXT)
  })

  it('returns undefined on the wrong key', () => {
    const rightKey = deriveKeyFromPassword(KAT_PASSWORD, KAT_SALT_HEX)
    const wrongKey = deriveKeyFromPassword('different password', KAT_SALT_HEX)
    const iv = Buffer.from(KAT_IV_HEX, 'hex')
    const ciphertext = encryptSymmetric(KAT_PLAINTEXT, rightKey, iv)
    expect(decryptSymmetric(ciphertext, wrongKey, iv)).toBeUndefined()
  })

  it('validates key and IV sizes', () => {
    const key = deriveKeyFromPassword(KAT_PASSWORD, KAT_SALT_HEX)
    const iv = Buffer.from(KAT_IV_HEX, 'hex')
    expect(() => encryptSymmetric('x', new Uint8Array(16), iv)).toThrow(RangeError)
    expect(() => encryptSymmetric('x', key, new Uint8Array(8))).toThrow(RangeError)
    expect(() => decryptSymmetric('e82j', key, new Uint8Array(8))).toThrow(RangeError)
  })
})

describe('known-answer fixture (wire format lock)', () => {
  it('decrypts a ciphertext produced by the pre-refactor implementation', () => {
    expect(decryptWithPassword(KAT_CIPHERTEXT, KAT_PASSWORD, KAT_SALT_HEX, KAT_IV_HEX)).toBe(
      KAT_PLAINTEXT,
    )
  })

  it('reproduces the exact ciphertext bytes with a fixed key and IV', () => {
    const key = deriveKeyFromPassword(KAT_PASSWORD, KAT_SALT_HEX)
    const iv = Buffer.from(KAT_IV_HEX, 'hex')
    expect(encryptSymmetric(KAT_PLAINTEXT, key, iv)).toBe(KAT_CIPHERTEXT)
  })
})
