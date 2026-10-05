/**
 * Demo identity keystore — SHARED by the example scripts.
 *
 * Stores a development identity (nsec + mail certificate) in a JSON file so
 * `demo:setup` and `demo:relay` can reuse the same recipient across runs.
 *
 * DEMO ONLY: this file is PLAINTEXT. Never use it for a real Nostr identity
 * or anything of value. Delete it to rotate. A real client (nVelope-Client)
 * will keep these in an encrypted keystore instead.
 */
import { existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs'
import { join } from 'node:path'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { generateMailCertificate } from '../src/index.js'

export interface DemoIdentity {
  secretKey: Uint8Array
  certificatePrivateKeyPem: string
  certificatePublicKeyDerBase64: string
}

interface IdentityFile {
  version: 1
  nsecHex: string
  certificatePrivateKeyPem: string
  certificatePublicKeyDerBase64: string
  createdAt: number
}

/** Path of the demo keystore; override with the IDENTITY_FILE env var. */
export function identityPath(): string {
  return process.env.IDENTITY_FILE ?? join(process.cwd(), 'nvelope-identity.json')
}

/**
 * Load the demo identity, creating it (fresh nsec + fresh 2048-bit mail
 * certificate) on first use. If NSEC_HEX is set in the environment it is used
 * as the nsec instead of generating one.
 */
export function loadOrCreateIdentity(): { identity: DemoIdentity; created: boolean } {
  const path = identityPath()
  if (existsSync(path)) {
    return { identity: parseIdentity(readFileSync(path, 'utf8'), path), created: false }
  }

  const envNsec = process.env.NSEC_HEX
  const nsecHex =
    envNsec !== undefined && /^[0-9a-f]{64}$/.test(envNsec)
      ? envNsec
      : Buffer.from(generateSecretKey()).toString('hex')
  const cert = generateMailCertificate()

  const file: IdentityFile = {
    version: 1,
    nsecHex,
    certificatePrivateKeyPem: cert.privateKeyPem,
    certificatePublicKeyDerBase64: cert.publicKeyDerBase64,
    createdAt: Date.now(),
  }
  writeFileSync(path, JSON.stringify(file, null, 2))
  try {
    chmodSync(path, 0o600) // best effort; ignored where unsupported
  } catch {
    /* windows etc. */
  }
  return { identity: fileToIdentity(file), created: true }
}

function parseIdentity(text: string, path: string): DemoIdentity {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new TypeError(`Identity file ${path} is not valid JSON — delete it to start fresh`)
  }
  const file = parsed as Partial<IdentityFile>
  if (
    typeof file.nsecHex !== 'string' ||
    !/^[0-9a-f]{64}$/.test(file.nsecHex) ||
    typeof file.certificatePrivateKeyPem !== 'string' ||
    !file.certificatePrivateKeyPem.includes('PRIVATE KEY') ||
    typeof file.certificatePublicKeyDerBase64 !== 'string'
  ) {
    throw new TypeError(`Identity file ${path} is malformed — delete it to start fresh`)
  }
  return fileToIdentity(file as IdentityFile)
}

function fileToIdentity(file: IdentityFile): DemoIdentity {
  return {
    secretKey: new Uint8Array(Buffer.from(file.nsecHex, 'hex')),
    certificatePrivateKeyPem: file.certificatePrivateKeyPem,
    certificatePublicKeyDerBase64: file.certificatePublicKeyDerBase64,
  }
}

/** The npub (hex) of an identity. */
export function identityPubkey(identity: DemoIdentity): string {
  return getPublicKey(identity.secretKey)
}
