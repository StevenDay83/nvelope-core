import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { decode, naddrEncode, npubEncode } from 'nostr-tools/nip19'
import {
  createBroadcastFilter,
  decodeBroadcastNaddr,
  encodeBroadcastNaddr,
} from '../../src/index.js'

const AUTHOR = 'a'.repeat(64)

/** Build a raw naddr with arbitrary internals, to feed the decoder malformed inputs. */
function encodeNaddrLike(kind: number, pubkey: string, identifier: string): string {
  return naddrEncode({ kind, pubkey, identifier })
}

describe('encodeBroadcastNaddr / decodeBroadcastNaddr', () => {
  it('round-trips author, password, and topic', () => {
    const naddr = encodeBroadcastNaddr({
      author: AUTHOR,
      password: 's3cret list password',
      topic: 'announcements',
    })
    expect(naddr.startsWith('naddr1')).toBe(true)

    const decoded = decodeBroadcastNaddr(naddr)
    expect(decoded).toEqual({
      author: AUTHOR,
      password: 's3cret list password',
      topic: 'announcements',
    })
  })

  it('encodes kind 8500 and the author pubkey in the bech32 itself', () => {
    const authorKey = generateSecretKey()
    const naddr = encodeBroadcastNaddr({
      author: getPublicKey(authorKey),
      password: 'pw',
      topic: 't',
    })
    const decoded = decode(naddr)
    expect(decoded.type).toBe('naddr')
    if (decoded.type !== 'naddr') throw new Error('unreachable')
    expect(decoded.data.kind).toBe(8500)
    expect(decoded.data.pubkey).toBe(getPublicKey(authorKey))
    expect(JSON.parse(decoded.data.identifier)).toEqual(['pw', 't'])
  })

  it('rejects an npub (valid bech32, wrong type)', () => {
    expect(() => decodeBroadcastNaddr(npubEncode(AUTHOR))).toThrow(TypeError)
  })

  it('rejects garbage input', () => {
    expect(() => decodeBroadcastNaddr('not bech32 at all')).toThrow(TypeError)
  })

  it('rejects naddrs of the wrong kind or with malformed identifiers', () => {
    expect(() =>
      decodeBroadcastNaddr(encodeNaddrLike(30023, AUTHOR, JSON.stringify(['pw', 't']))),
    ).toThrow(TypeError)
    expect(() =>
      decodeBroadcastNaddr(encodeNaddrLike(8500, AUTHOR, '"just a string"')),
    ).toThrow(TypeError)
    expect(() => decodeBroadcastNaddr(encodeNaddrLike(8500, AUTHOR, '{oops'))).toThrow(TypeError)
    expect(() => decodeBroadcastNaddr(encodeNaddrLike(8500, AUTHOR, '["a","b","c"]'))).toThrow(
      TypeError,
    )
  })

  it('rejects invalid credentials on encode', () => {
    expect(() =>
      encodeBroadcastNaddr({ author: 'nope', password: 'p', topic: 't' }),
    ).toThrow(TypeError)
    expect(() =>
      encodeBroadcastNaddr({ author: AUTHOR, password: '', topic: 't' }),
    ).toThrow(TypeError)
    expect(() =>
      encodeBroadcastNaddr({ author: AUTHOR, password: 'p', topic: '' }),
    ).toThrow(TypeError)
  })
})

describe('createBroadcastFilter', () => {
  it('matches all broadcast envelopes from an author', () => {
    expect(createBroadcastFilter(AUTHOR)).toEqual({
      kinds: [8500],
      authors: [AUTHOR],
      '#l': ['broadcast_message'],
    })
  })

  it('supports multiple authors and a since bound', () => {
    const other = 'b'.repeat(64)
    expect(createBroadcastFilter([AUTHOR, other], { since: 1720000000 })).toEqual({
      kinds: [8500],
      authors: [AUTHOR, other],
      '#l': ['broadcast_message'],
      since: 1720000000,
    })
  })

  it('rejects non-hex authors', () => {
    expect(() => createBroadcastFilter('nope')).toThrow(TypeError)
  })
})
