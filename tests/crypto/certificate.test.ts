import { describe, expect, it } from 'vitest'
import {
  DEFAULT_CERTIFICATE_KEY_SIZE,
  generateMailCertificate,
  publicKeyDerBase64FromPrivateKeyPem,
  publicKeyDerBase64ToPem,
} from '../../src/index.js'

describe('generateMailCertificate', () => {
  it('generates a 2048-bit certificate by default', () => {
    expect(DEFAULT_CERTIFICATE_KEY_SIZE).toBe(2048)
    const cert = generateMailCertificate()
    expect(cert.privateKeyPem).toContain('BEGIN PRIVATE KEY')
    expect(cert.publicKeyDerBase64.length).toBeGreaterThan(200)

    const der = Buffer.from(cert.publicKeyDerBase64, 'base64')
    expect(der.length).toBe(294) // a 2048-bit RSA spki DER key is exactly 294 bytes
    expect(der[0]).toBe(0x30) // DER SEQUENCE marker
  })

  it('honours a custom key size', () => {
    const cert = generateMailCertificate(3072)
    expect(cert.privateKeyPem).toContain('BEGIN PRIVATE KEY')
    const der = Buffer.from(cert.publicKeyDerBase64, 'base64')
    expect(der.length).toBeGreaterThan(300)
  })

  it('rejects invalid key sizes', () => {
    expect(() => generateMailCertificate(512)).toThrow(RangeError)
    expect(() => generateMailCertificate(1023.5)).toThrow(RangeError)
    expect(() => generateMailCertificate(-2048)).toThrow(RangeError)
  })
})

describe('publicKeyDerBase64ToPem (wire format -> usable PEM)', () => {
  it('converts the published DER base64 public key to PEM', () => {
    const cert = generateMailCertificate()
    const pem = publicKeyDerBase64ToPem(cert.publicKeyDerBase64)
    expect(pem).toContain('BEGIN PUBLIC KEY')
    expect(pem.endsWith('\n')).toBe(true)
  })

  it('rejects invalid input', () => {
    expect(() => publicKeyDerBase64ToPem('not valid base64 !!!')).toThrow(TypeError)
    expect(() => publicKeyDerBase64ToPem('')).toThrow(TypeError)
  })
})

describe('publicKeyDerBase64FromPrivateKeyPem (keystore recovery)', () => {
  it('derives the same public key that was generated', () => {
    const cert = generateMailCertificate()
    expect(publicKeyDerBase64FromPrivateKeyPem(cert.privateKeyPem)).toBe(cert.publicKeyDerBase64)
  })

  it('rejects invalid PEM', () => {
    expect(() => publicKeyDerBase64FromPrivateKeyPem('not a private key')).toThrow(TypeError)
  })
})
