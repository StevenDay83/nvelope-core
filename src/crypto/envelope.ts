/**
 * Envelope encryption: RSA-OAEP chunk-encryption of mail content to a
 * recipient's certificate public key.
 *
 * Wire format (locked by known-answer tests): the blinded envelope's content is
 * JSON.stringify(<array of base64 RSA-OAEP chunks>). Each chunk holds at most
 * `modulusBytes - 42` bytes of UTF-8 plaintext (42 = OAEP-with-SHA-1 overhead),
 * which is 214 bytes for the standard 2048-bit certificate.
 *
 * Two deliberate fixes versus the pre-refactor implementation:
 * - Chunking is by UTF-8 BYTE length, not UTF-16 character count. The old code
 *   split by JS string length, so messages heavy in non-ASCII text produced
 *   oversized chunks and crashed inside publicEncrypt ("data too large").
 * - The old code appended a spurious empty chunk when the message length was an
 *   exact multiple of the chunk size.
 * - Chunk boundaries are snapped back to UTF-8 character boundaries, so
 *   multi-byte text (CJK, emoji) can never split into replacement characters.
 *   (The old code also risked splitting UTF-16 surrogate pairs when it chunked
 *   by character count.)
 *
 * Decryption is unaffected by either fix: it concatenates chunk plaintexts, so
 * envelopes produced by the old code (ASCII mail) decrypt identically.
 */
import { createPrivateKey, createPublicKey, privateDecrypt, publicEncrypt } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { DEFAULT_CERTIFICATE_KEY_SIZE } from './certificate.js'

/** OAEP padding overhead when using SHA-1: 2 * hLen + 2 = 42 bytes. */
const OAEP_SHA1_OVERHEAD = 42

/**
 * Maximum plaintext bytes encryptable per chunk for the given public key.
 * 214 for a 2048-bit certificate, 470 for 4096-bit.
 *
 * @throws {TypeError} if the PEM is not a valid RSA public key.
 */
export function maxEnvelopeChunkBytes(publicKeyPem: string): number {
  return envelopeChunkBytesFor(parsePublicKeyPem(publicKeyPem))
}

/**
 * Encrypt a UTF-8 string to a recipient's certificate public key, returning
 * the wire format: an array of base64 RSA-OAEP chunks.
 *
 * @throws {TypeError} on non-string plaintext or invalid public key PEM.
 */
export function encryptEnvelope(plaintext: string, publicKeyPem: string): string[] {
  if (typeof plaintext !== 'string') {
    throw new TypeError(`plaintext must be a string, got: ${typeof plaintext}`)
  }
  const publicKey = parsePublicKeyPem(publicKeyPem)
  const maxChunk = envelopeChunkBytesFor(publicKey)

  const data = Buffer.from(plaintext, 'utf8')
  const encryptChunk = (chunk: Uint8Array): string =>
    publicEncrypt(publicKey, chunk).toString('base64')

  // Match the pre-refactor behavior for empty plaintext: a single encrypted
  // (empty) chunk, so the wire array is never empty.
  if (data.length === 0) {
    return [encryptChunk(new Uint8Array(0))]
  }

  const chunks: string[] = []
  let offset = 0
  while (offset < data.length) {
    const end = utf8SafeSliceEnd(data, offset, offset + maxChunk)
    chunks.push(encryptChunk(data.subarray(offset, end)))
    offset = end
  }
  return chunks
}

/**
 * Return the largest end <= desiredEnd that does not split a multi-byte UTF-8
 * character. Continuation bytes have the top bits 10xxxxxx, so walk back past
 * any run of them to the character's leading byte. (Splitting a character
 * would decode to U+FFFD replacement characters on the recipient's side.)
 */
function utf8SafeSliceEnd(data: Buffer, start: number, desiredEnd: number): number {
  let end = Math.min(desiredEnd, data.length)
  // A boundary is clean when the NEXT byte starts a new character, i.e. it is
  // not a UTF-8 continuation byte (top bits 10xxxxxx). Walk back past any run
  // of continuation bytes to the character's leading byte.
  while (end > start && end < data.length && (data.readUInt8(end) & 0xc0) === 0x80) {
    end--
  }
  return end
}

/**
 * Decrypt an envelope chunk array with the recipient's certificate private key.
 *
 * @returns the plaintext, or `undefined` if decryption fails — expected when a
 *   scanned blinded envelope was not encrypted for this key (wrong recipient or
 *   corrupt data). Input-shape problems throw instead.
 * @throws {TypeError} on invalid input types or an unparseable private key.
 */
export function decryptEnvelope(chunks: string[], privateKeyPem: string): string | undefined {
  if (!Array.isArray(chunks)) {
    throw new TypeError(`chunks must be an array, got: ${typeof chunks}`)
  }
  for (const chunk of chunks) {
    if (typeof chunk !== 'string' || chunk.length === 0) {
      throw new TypeError('chunks must be non-empty base64 strings')
    }
  }

  let privateKey: KeyObject
  try {
    privateKey = createPrivateKey(privateKeyPem)
  } catch {
    throw new TypeError('Invalid private key: expected a PEM private key')
  }

  try {
    const parts = chunks.map((chunk) =>
      privateDecrypt(privateKey, Buffer.from(chunk, 'base64')).toString('utf8'),
    )
    return parts.join('')
  } catch {
    return undefined
  }
}

function envelopeChunkBytesFor(publicKey: KeyObject): number {
  const modulusLength = publicKey.asymmetricKeyDetails?.modulusLength ?? DEFAULT_CERTIFICATE_KEY_SIZE
  return Math.floor(modulusLength / 8) - OAEP_SHA1_OVERHEAD
}

function parsePublicKeyPem(publicKeyPem: string): KeyObject {
  try {
    return createPublicKey(publicKeyPem)
  } catch {
    throw new TypeError('Invalid public key: expected a PEM public key')
  }
}
