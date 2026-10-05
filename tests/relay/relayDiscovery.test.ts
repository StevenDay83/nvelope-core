import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  buildUnsignedEvent,
  fetchRelaysKind3Legacy,
  fetchRelaysNip65,
  finalizeWithNsec,
  unionRelays,
} from '../../src/index.js'
import { FakeTransport } from './fakeTransport.js'

const RELAYS = ['wss://relay.example']

describe('fetchRelaysNip65', () => {
  it('parses r tags with read/write markers; unmarked counts for both', async () => {
    const ownerKey = generateSecretKey()
    const owner = getPublicKey(ownerKey)
    const transport = new FakeTransport()

    transport.seed(
      finalizeWithNsec(
        buildUnsignedEvent({
          kind: 10002,
          content: '',
          tags: [
            ['r', 'wss://read.relay', 'read'],
            ['r', 'wss://write.relay', 'write'],
            ['r', 'wss://both.relay'],
            ['r', 'not-a-url', 'read'],
          ],
          createdAt: 1000,
        }),
        ownerKey,
      ),
    )

    const hints = await fetchRelaysNip65(transport, owner, RELAYS)
    expect(hints.read).toEqual(['wss://read.relay', 'wss://both.relay'])
    expect(hints.write).toEqual(['wss://write.relay', 'wss://both.relay'])
  })

  it('returns empty hints when no NIP-65 list is published', async () => {
    const transport = new FakeTransport()
    const hints = await fetchRelaysNip65(transport, 'a'.repeat(64), RELAYS)
    expect(hints).toEqual({ read: [], write: [] })
  })

  it('uses the latest kind-10002 event', async () => {
    const ownerKey = generateSecretKey()
    const owner = getPublicKey(ownerKey)
    const transport = new FakeTransport()

    transport.seed(
      finalizeWithNsec(
        buildUnsignedEvent({
          kind: 10002,
          content: '',
          tags: [['r', 'wss://old.relay']],
          createdAt: 1000,
        }),
        ownerKey,
      ),
      finalizeWithNsec(
        buildUnsignedEvent({
          kind: 10002,
          content: '',
          tags: [['r', 'wss://new.relay']],
          createdAt: 2000,
        }),
        ownerKey,
      ),
    )

    const hints = await fetchRelaysNip65(transport, owner, RELAYS)
    expect(hints.read).toEqual(['wss://new.relay'])
  })
})

describe('fetchRelaysKind3Legacy', () => {
  it('reads relay URLs from the kind-3 content object keys', async () => {
    const ownerKey = generateSecretKey()
    const owner = getPublicKey(ownerKey)
    const transport = new FakeTransport()

    transport.seed(
      finalizeWithNsec(
        buildUnsignedEvent({
          kind: 3,
          content: JSON.stringify({
            'wss://alpha.relay': { read: true, write: true },
            'wss://beta.relay': { read: true },
            'not-a-url': {},
          }),
          createdAt: 1000,
        }),
        ownerKey,
      ),
    )

    const hints = await fetchRelaysKind3Legacy(transport, owner, RELAYS)
    expect(hints.read).toEqual(['wss://alpha.relay', 'wss://beta.relay'])
    expect(hints.write).toEqual(['wss://alpha.relay', 'wss://beta.relay'])
  })

  it('tolerates unparseable kind-3 content', async () => {
    const ownerKey = generateSecretKey()
    const owner = getPublicKey(ownerKey)
    const transport = new FakeTransport()
    transport.seed(
      finalizeWithNsec(
        buildUnsignedEvent({ kind: 3, content: '{broken', createdAt: 1000 }),
        ownerKey,
      ),
    )
    const hints = await fetchRelaysKind3Legacy(transport, owner, RELAYS)
    expect(hints).toEqual({ read: [], write: [] })
  })
})

describe('unionRelays (publish superset for recipient-relay obfuscation)', () => {
  it('deduplicates preserving first-appearance order and drops junk', () => {
    const merged = unionRelays(
      ['wss://mine.one', 'wss://theirs.read'],
      ['wss://theirs.read', 'wss://extra.obfuscation'],
      ['garbage', 'wss://mine.one'],
    )
    expect(merged).toEqual(['wss://mine.one', 'wss://theirs.read', 'wss://extra.obfuscation'])
  })

  it('produces the documented obfuscation pattern', async () => {
    const recipientHints = { read: ['wss://recipient.relay'], write: [] }
    const myRelays = ['wss://relay.damus.io', 'wss://nos.lol']
    const publishSet = unionRelays(myRelays, recipientHints.read, ['wss://decoy.relay'])
    // The recipient's relay is in the set, but an observer cannot tell which
    // relays in the set actually matter.
    expect(publishSet).toContain('wss://recipient.relay')
    expect(publishSet.length).toBeGreaterThan(1)
  })
})
