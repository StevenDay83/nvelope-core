/**
 * Signing abstraction.
 *
 * nVelope-Client may keep the nsec in an encrypted keystore, or delegate to
 * NIP-07/NIP-46 later; the library only ever sees this interface. NsecSigner is
 * the simple default for Node scripts and tests.
 */
import type { Hex256 } from '../types.js'
import { finalizeWithNsec, publicKeyOf } from '../protocol/events.js'
import type { NostrEvent, UnsignedEvent } from '../protocol/events.js'

export interface Signer {
  /** The signer's npub (hex). */
  getPublicKey(): Promise<Hex256>
  /** Produce a fully signed event from an unsigned one. */
  signEvent(unsigned: UnsignedEvent): Promise<NostrEvent>
}

/** Signer holding a raw nsec (Uint8Array, 32 bytes). */
export class NsecSigner implements Signer {
  private readonly secretKey: Uint8Array

  constructor(secretKey: Uint8Array) {
    if (!(secretKey instanceof Uint8Array) || secretKey.length !== 32) {
      throw new RangeError('nsec must be a 32-byte Uint8Array')
    }
    this.secretKey = secretKey
  }

  getPublicKey(): Promise<Hex256> {
    return Promise.resolve(publicKeyOf(this.secretKey))
  }

  signEvent(unsigned: UnsignedEvent): Promise<NostrEvent> {
    return Promise.resolve(finalizeWithNsec(unsigned, this.secretKey))
  }
}
