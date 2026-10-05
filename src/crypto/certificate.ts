/**
 * Nostr-Mail certificates: the RSA keypair used to encrypt mail to a recipient.
 *
 * Wire formats (locked by known-answer tests):
 * - Public key: DER (spki), base64-encoded — published in the `nv_public_key`
 *   mail-profile event.
 * - Private key: PKCS#8 PEM — held by the recipient's client, never published.
 *
 * The recipient's client stores the private key however it sees fit (e.g. an
 * encrypted keystore in nVelope-Client); this library never persists secrets.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto'
import type { KeyObject } from 'node:crypto'

/** Default RSA modulus length for mail certificates (matches pre-refactor behavior). */
export const DEFAULT_CERTIFICATE_KEY_SIZE = 2048

/** Minimum RSA modulus length this library will generate. */
export const MIN_CERTIFICATE_KEY_SIZE = 1024

/** A mail certificate: the public part is published, the private part stays secret. */
export interface MailCertificate {
  /** DER (spki) public key, base64 — the wire format published to relays. */
  publicKeyDerBase64: string
  /** PKCS#8 private key, PEM — for the client's secure storage only. */
  privateKeyPem: string
}

/**
 * Generate a new mail certificate (RSA keypair).
 *
 * @param keySize RSA modulus length in bits. Defaults to 2048; larger sizes
 *   give bigger envelope chunks (more plaintext per RSA operation) at the cost
 *   of slower generation and larger ciphertexts.
 */
export function generateMailCertificate(keySize = DEFAULT_CERTIFICATE_KEY_SIZE): MailCertificate {
  if (!Number.isInteger(keySize) || keySize < MIN_CERTIFICATE_KEY_SIZE) {
    throw new RangeError(`keySize must be an integer >= ${MIN_CERTIFICATE_KEY_SIZE}, got: ${keySize}`)
  }
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: keySize,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  return {
    publicKeyDerBase64: Buffer.from(publicKey).toString('base64'),
    privateKeyPem: privateKey as string,
  }
}

/**
 * Convert a wire-format public key (DER base64, as published in the
 * `nv_public_key` event) to PEM for use with the envelope functions.
 *
 * @throws {TypeError} if the input is not a valid DER (spki) public key.
 */
export function publicKeyDerBase64ToPem(derBase64: string): string {
  try {
    const der = Buffer.from(derBase64, 'base64')
    return createPublicKey({ key: der, format: 'der', type: 'spki' }).export({
      format: 'pem',
      type: 'spki',
    }) as string
  } catch {
    throw new TypeError('Invalid public key: expected base64-encoded DER (spki)')
  }
}

/**
 * Recover the wire-format public key (DER base64) from a private key PEM.
 * Useful for clients that store only the private key in their keystore.
 *
 * @throws {TypeError} if the input is not a valid PKCS#8 private key.
 */
export function publicKeyDerBase64FromPrivateKeyPem(privateKeyPem: string): string {
  try {
    const publicKey: KeyObject = createPublicKey(createPrivateKey(privateKeyPem))
    return Buffer.from(publicKey.export({ format: 'der', type: 'spki' }) as Uint8Array).toString(
      'base64',
    )
  } catch {
    throw new TypeError('Invalid private key: expected PKCS#8 PEM')
  }
}
