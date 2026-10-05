import { describe, expect, it } from 'vitest'
import {
  decryptEnvelope,
  encryptEnvelope,
  generateMailCertificate,
  maxEnvelopeChunkBytes,
  publicKeyDerBase64ToPem,
} from '../../src/index.js'

// Known-answer fixture: produced with the pre-refactor implementation semantics
// (node:crypto RSA-OAEP defaults, 2048-bit key, 214-byte chunks). Decryption is
// deterministic, so this locks the wire format forever.
const KAT_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAzBRXvb5Dfrk9
fs5sMHQWwIVC7xoz02WjZL9u1FSh6LMgAJgzvo/483mUsV0QzkrniyECuK3gDksK
81YC+xcqtT0fweIoNCakLXOwFIauMQjRvVv10Vg8UV1nNoD7YRkVPMErd5hooVU5
feER7YZDAcY/x8zyag2nqupdVIfiE6jMur+tpLlQXnVDxMOxpXKVk5b5SsmvwrG0
m8GMLKm4I5u6MbsK5Pizy1DpZGCcgur2Fa0pI0i4zr2EkKyHu1MWSUQhhIelSNdp
Af3bjPxm7tQjde2Xl0+eEpwrhb3GLuVNls+8eWGWlCUIeqGIbPdnLs9kwEEbtYkL
ruIOYlu9AgMBAAECggEACtx0WO0LhungraIzJs0j/RQjbb3ikADcvPO0BR5ZFjXx
wV/HM0MNAU1WEBZd09CLT7f6yBh3UyP6/kbvFYPnrjQ/mUZm4zTs6FrXJZhCbhW9
FXPBdnuwqNU8mc/sPD0gGJ4vk69NGrfcAT0iLMxgv+2dqYIr/YwT8NokEdXtQcMY
mCwpSynj1XPkhsDQ577TYznSSJAWpsQyliDFXELoZsUZMAQCrEVGUn+nRafe2BTG
8p+3fnf7vZt/rqmDdrl2gtUrqVFXLWlfaIGgTUlM/pIljFyeTdNj1FnM9vGrLYYd
vMweVNMkIUOzdt8dpSyNP+ytBxkGAd1i5cbyJ2VrAQKBgQD2rlpIoK54YRrpC+As
VPPeMdmNGovcuoKEmgbPB5EiOkADp+ELERBYDb7Uuej3mGP4Je0Pb6g2duJEUP9P
OmD2SxN1hHZwA0s22R/HC5xq/IOEIg9ne36eSJ7dkf8P4ONmnbdLsZPssdPspRXa
u173wutdcbUFn8dyMdySF95qzQKBgQDIFJ3vv1vV661cVF4Y2T7QbwO18XEK/e21
H+VqirDW+gptSAoNbO/n8ehOVLUQ0fIVhjJ0PzPqNTfTMUQcqV796tnUQ/RDiqeX
AGssEh3ldq6zrgsWuGh041h47n3vIWQ7Fl3F/O0oCaanJwdFiGUypGhEeodpUzNg
IYduT0yUsQKBgAPAsUTrlNvl9kfXU2i5PiCCN6IK5lfMSpID2diqb83KfxDPLABE
GTCNvPp1fZLOsa6jvRCADVoOwvBxHwEwjSsSB1DBXB/mHO3PrckUZyPFhaar8foM
CegUiL4sK2otbKgx/AjdwbdXGTc/Z661LQOt5nC8exmDzb/x/D4IuOx9AoGANpMJ
EWAM2KjUPJ72m6iGLaxaQsJ8pxbkQ8dTeGAkJD9HoM9JjqfsOEQPrW4FhXT+p0hX
csXaj0O82mpRvc+lDXWFvRRcCCBF3jZLBVZbuT9KH9CVTbk3JMruUu4ag6OEB2nu
Yha/SXB4eJd4sEqn78xQdH1Hej8rgEkk+729kcECgYEA8lJJUD+yc4IKWybuta4i
k0EIF0yPfQYrskwidQMcFRbrt6ECUl0bqhWjf79mz31BIF73vbHSnCrTJto2vBip
FO+zros8uKmJyn8yYtUr8ZtdhmPIO8C5oxIk8K9EkHaVJksBPsl5aAt9yeOmoLeT
VvmFYnD2MIj54xVFxBv7HDc=
-----END PRIVATE KEY-----
`
const KAT_CHUNKS: string[] = ["f0VqvZhnesGvidobiXYS4GlEIyK7dC5AKgtKy5P7oAJ7azDuR7YvF1GBsgX3kjiZMnfCjGso8PKVFt3E2co1Jg6xoK0mQX870A3t4qooPGyvL4NytOaD1F0KpwKofEliuogjrGrBVGtd1JT00v1IYIuTsxzHRLCAZO/8PYdbJW4Siu3sHNoRrmU+xi/SwTqvNXk+2qOWmJ8nsMqOBmcC/+gdAz+qbJIouLnjQKPoQdbFoMlmdt//EZ/+n1OWAUYDRejlU9PrgU8/pXbWjMmPrjMCW3VeC66Wp1YNzI6p8JB+23A9cYbNYls4nLNGRH2natfIQHAQFepFjx6Fnxgr9A=="]
const KAT_PLAINTEXT = 'Hello from the old world — café ✓'

function makeCertificatePair(): { privateKeyPem: string; publicKeyPem: string } {
  const cert = generateMailCertificate()
  return {
    privateKeyPem: cert.privateKeyPem,
    publicKeyPem: publicKeyDerBase64ToPem(cert.publicKeyDerBase64),
  }
}

describe('encryptEnvelope / decryptEnvelope round-trips', () => {
  it('short ASCII message', () => {
    const { privateKeyPem, publicKeyPem } = makeCertificatePair()
    const plaintext = 'Hello, nVelope!'
    const chunks = encryptEnvelope(plaintext, publicKeyPem)
    expect(chunks).toHaveLength(1)
    expect(decryptEnvelope(chunks, privateKeyPem)).toBe(plaintext)
  })

  it('multi-chunk message chunks at 214 bytes for a 2048-bit certificate', () => {
    const { privateKeyPem, publicKeyPem } = makeCertificatePair()
    const plaintext = 'The quick brown fox jumps over the lazy dog. '.repeat(150) // 6,750 bytes
    const chunks = encryptEnvelope(plaintext, publicKeyPem)
    expect(maxEnvelopeChunkBytes(publicKeyPem)).toBe(214)
    expect(chunks).toHaveLength(Math.ceil(Buffer.byteLength(plaintext, 'utf8') / 214))
    expect(decryptEnvelope(chunks, privateKeyPem)).toBe(plaintext)
  })

  it('UTF-8 heavy message: chunks never split multi-byte characters', () => {
    const { privateKeyPem, publicKeyPem } = makeCertificatePair()
    const plaintext = '✓'.repeat(300) // 300 chars, 900 UTF-8 bytes
    const chunks = encryptEnvelope(plaintext, publicKeyPem)
    // Each plaintext chunk is at most 214 bytes, so 900 bytes of plaintext
    // require at least ceil(900 / 214) chunks. (Each RSA ciphertext chunk is
    // always 256 bytes for a 2048-bit key no matter the plaintext length —
    // ciphertext size is not a meaningful bound to assert here.)
    expect(chunks.length).toBeGreaterThanOrEqual(Math.ceil(900 / 214))
    expect(chunks.length).toBeLessThanOrEqual(Math.ceil(900 / 214) + 1)
    const decrypted = decryptEnvelope(chunks, privateKeyPem)
    if (decrypted === undefined) throw new Error('decryption failed')
    expect(decrypted).toBe(plaintext)
    expect(decrypted).not.toContain('\uFFFD') // no replacement characters
  })

  it('astral characters (emoji) survive chunking intact', () => {
    const { privateKeyPem, publicKeyPem } = makeCertificatePair()
    // 212 ASCII bytes + 50 emoji (4 UTF-8 bytes each) + 212 ASCII bytes = 428 bytes.
    // The first 214-byte boundary would land inside the first emoji without snapping.
    const plaintext = 'a'.repeat(212) + '🙂'.repeat(50) + 'b'.repeat(212)
    const chunks = encryptEnvelope(plaintext, publicKeyPem)
    expect(chunks.length).toBeGreaterThan(1)
    const decrypted = decryptEnvelope(chunks, privateKeyPem)
    if (decrypted === undefined) throw new Error('decryption failed')
    expect(decrypted).toBe(plaintext)
    expect(decrypted).not.toContain('\uFFFD')
  })

  it('empty string produces a single chunk and round-trips', () => {
    const { privateKeyPem, publicKeyPem } = makeCertificatePair()
    const chunks = encryptEnvelope('', publicKeyPem)
    expect(chunks).toHaveLength(1)
    expect(decryptEnvelope(chunks, privateKeyPem)).toBe('')
  })

  it('chunk size scales with certificate key size', () => {
    const cert = generateMailCertificate(4096)
    const publicKeyPem = publicKeyDerBase64ToPem(cert.publicKeyDerBase64)
    expect(maxEnvelopeChunkBytes(publicKeyPem)).toBe(512 - 42)

    const plaintext = 'x'.repeat(470) // exactly the 4096-bit one-chunk maximum
    const chunks = encryptEnvelope(plaintext, publicKeyPem)
    expect(chunks).toHaveLength(1)
    expect(decryptEnvelope(chunks, cert.privateKeyPem)).toBe(plaintext)
  })
})

describe('decryptEnvelope failure modes', () => {
  it('returns undefined when decrypted with the wrong certificate', () => {
    const alice = makeCertificatePair()
    const bob = makeCertificatePair()
    const chunks = encryptEnvelope('secret', alice.publicKeyPem)
    expect(decryptEnvelope(chunks, bob.privateKeyPem)).toBeUndefined()
  })

  it('returns undefined on a tampered chunk', () => {
    const { privateKeyPem, publicKeyPem } = makeCertificatePair()
    const chunks = encryptEnvelope('secret', publicKeyPem)
    const tampered = chunks.map((chunk, index) => (index === 0 ? chunk.slice(0, -2) + 'zz' : chunk))
    expect(decryptEnvelope(tampered, privateKeyPem)).toBeUndefined()
  })

  it('throws TypeError on invalid input shapes', () => {
    const { privateKeyPem, publicKeyPem } = makeCertificatePair()
    expect(() => encryptEnvelope(42 as unknown as string, publicKeyPem)).toThrow(TypeError)
    expect(() => encryptEnvelope('x', 'not a pem')).toThrow(TypeError)
    expect(() => decryptEnvelope('nope' as unknown as string[], privateKeyPem)).toThrow(TypeError)
    expect(() => decryptEnvelope([42] as unknown as string[], privateKeyPem)).toThrow(TypeError)
  })
})

describe('known-answer fixture (wire format lock)', () => {
  it('decrypts a chunk array produced by the pre-refactor implementation', () => {
    expect(decryptEnvelope(KAT_CHUNKS, KAT_PRIVATE_KEY_PEM)).toBe(KAT_PLAINTEXT)
  })
})
