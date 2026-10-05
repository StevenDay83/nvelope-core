/**
 * Symmetric encryption for broadcast mail: AES-256-CBC with keys derived by
 * scrypt from a passphrase.
 *
 * Wire format (locked by known-answer tests): ciphertext is base64; the
 * broadcast event's `key_info` tag carries `{ salt, iv }` as hex strings — 64
 * hex chars (32 bytes) of scrypt salt and 32 hex chars (16 bytes) of CBC IV.
 * scrypt uses Node's defaults (N=16384, r=8, p=1), matching the pre-refactor
 * implementation, so keys derived from old passphrases still work.
 *
 * NOTE: AES-CBC provides confidentiality but NOT integrity. A wrong IV or a
 * tampered ciphertext usually decrypts to garbage rather than failing (only
 * invalid padding makes decryption throw, which is why a wrong PASSWORD tends
 * to return undefined but a wrong IV returns mojibake). Callers that need
 * tamper-evidence must add a MAC or signature at a higher layer.
 *
 * Security fix versus the pre-refactor implementation: a FRESH random IV is
 * generated for every `encryptWithPassword` call. The old code reused one IV
 * per key across all messages — a known CBC vulnerability (identical plaintext
 * blocks across messages leak information). The wire format is unchanged: the
 * IV has always traveled per-message inside `key_info`.
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'

export const SYMMETRIC_CIPHER = 'aes-256-cbc'
export const SYMMETRIC_KEY_BYTES = 32
export const SYMMETRIC_IV_BYTES = 16
export const SYMMETRIC_SALT_BYTES = 32

const HEX_PATTERN = /^[0-9a-fA-F]+$/

/** The output of passphrase encryption: base64 ciphertext plus its hex IV. */
export interface PasswordEncryption {
  /** Base64 AES-256-CBC ciphertext. */
  ciphertext: string
  /** 16-byte IV as 32 hex chars (goes into the event's `key_info` tag). */
  iv: string
}

/** Generate a fresh random scrypt salt (64 hex chars / 32 bytes) for a new broadcast key. */
export function generateSalt(): string {
  return randomBytes(SYMMETRIC_SALT_BYTES).toString('hex')
}

/**
 * Derive a 32-byte AES key from a passphrase and salt (scrypt, Node defaults).
 *
 * @throws {TypeError} on empty/non-string password or invalid hex salt.
 */
export function deriveKeyFromPassword(password: string, saltHex: string): Uint8Array {
  if (typeof password !== 'string' || password.length === 0) {
    throw new TypeError('password must be a non-empty string')
  }
  return scryptSync(password, hexToBytes(saltHex, undefined, 'salt'), SYMMETRIC_KEY_BYTES)
}

/** AES-256-CBC encrypt. `key` must be 32 bytes, `iv` 16 bytes. Returns base64. */
export function encryptSymmetric(plaintext: string, key: Uint8Array, iv: Uint8Array): string {
  if (typeof plaintext !== 'string') {
    throw new TypeError(`plaintext must be a string, got: ${typeof plaintext}`)
  }
  assertKeyAndIv(key, iv)
  const cipher = createCipheriv(SYMMETRIC_CIPHER, key, iv)
  return cipher.update(plaintext, 'utf8', 'base64') + cipher.final('base64')
}

/**
 * AES-256-CBC decrypt.
 *
 * @returns the plaintext, or `undefined` if decryption fails (wrong key/IV or
 *   corrupt ciphertext). Input-shape problems throw instead.
 */
export function decryptSymmetric(
  ciphertextBase64: string,
  key: Uint8Array,
  iv: Uint8Array,
): string | undefined {
  if (typeof ciphertextBase64 !== 'string' || ciphertextBase64.length === 0) {
    throw new TypeError('ciphertextBase64 must be a non-empty base64 string')
  }
  assertKeyAndIv(key, iv)
  try {
    const decipher = createDecipheriv(SYMMETRIC_CIPHER, key, iv)
    return decipher.update(ciphertextBase64, 'base64', 'utf8') + decipher.final('utf8')
  } catch {
    return undefined
  }
}

/**
 * Encrypt with a passphrase, deriving the key with scrypt. A FRESH random IV is
 * generated on every call (see module docstring).
 */
export function encryptWithPassword(
  plaintext: string,
  password: string,
  saltHex: string,
): PasswordEncryption {
  const key = deriveKeyFromPassword(password, saltHex)
  const iv = randomBytes(SYMMETRIC_IV_BYTES)
  return {
    ciphertext: encryptSymmetric(plaintext, key, iv),
    iv: iv.toString('hex'),
  }
}

/**
 * Decrypt with a pre-derived key and a hex IV. Use this when a client caches
 * derived keys for a list, so it does not re-run scrypt for every message.
 *
 * @returns the plaintext, or `undefined` on failure.
 */
export function decryptWithKey(
  ciphertextBase64: string,
  key: Uint8Array,
  ivHex: string,
): string | undefined {
  return decryptSymmetric(ciphertextBase64, key, hexToBytes(ivHex, SYMMETRIC_IV_BYTES, 'iv'))
}

/**
 * Decrypt with a passphrase. `ivHex` is the 32-hex-char IV from the event's
 * `key_info` tag.
 *
 * @returns the plaintext, or `undefined` on failure (wrong passphrase/IV).
 */
export function decryptWithPassword(
  ciphertextBase64: string,
  password: string,
  saltHex: string,
  ivHex: string,
): string | undefined {
  const key = deriveKeyFromPassword(password, saltHex)
  return decryptSymmetric(ciphertextBase64, key, hexToBytes(ivHex, SYMMETRIC_IV_BYTES, 'iv'))
}

function assertKeyAndIv(key: Uint8Array, iv: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== SYMMETRIC_KEY_BYTES) {
    throw new RangeError(`key must be a ${SYMMETRIC_KEY_BYTES}-byte Uint8Array`)
  }
  if (!(iv instanceof Uint8Array) || iv.length !== SYMMETRIC_IV_BYTES) {
    throw new RangeError(`iv must be a ${SYMMETRIC_IV_BYTES}-byte Uint8Array`)
  }
}

function hexToBytes(hex: string, expectedBytes?: number, label = 'hex value'): Uint8Array {
  if (
    typeof hex !== 'string' ||
    hex.length === 0 ||
    hex.length % 2 !== 0 ||
    !HEX_PATTERN.test(hex)
  ) {
    throw new TypeError(`Invalid ${label}: expected a non-empty even-length hex string`)
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    throw new RangeError(`Invalid ${label}: expected ${expectedBytes} bytes, got ${bytes.length}`)
  }
  return bytes
}
