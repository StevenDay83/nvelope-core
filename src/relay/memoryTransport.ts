import type { Filter } from 'nostr-tools'
import type { NostrEvent, PublishResult, Transport } from '../../src/index.js'

/**
 * In-memory Transport: seeded events, filter matching, records publishes and
 * queries. No network involved — ideal for tests, offline demos, and as a
 * reference implementation of the Transport interface.
 */
export class MemoryTransport implements Transport {
  readonly events: NostrEvent[] = []
  readonly published: Array<{ event: NostrEvent; relays: string[] }> = []
  /** Record of every query, for test assertions. */
  readonly queries: Array<{ filters: Filter[]; relays: string[] }> = []

  seed(...events: NostrEvent[]): void {
    this.events.push(...events)
  }

  async query(filters: Filter | Filter[], relays: string[]): Promise<NostrEvent[]> {
    const filterArray = Array.isArray(filters) ? filters : [filters]
    this.queries.push({ filters: filterArray, relays: [...relays] })
    const byId = new Map<string, NostrEvent>()
    for (const filter of filterArray) {
      let matched = this.events.filter((event) => matchesFilter(event, filter))
      if (filter.limit !== undefined) {
        matched = matched.slice(0, filter.limit)
      }
      for (const event of matched) {
        byId.set(event.id, event)
      }
    }
    return [...byId.values()].sort((a, b) => b.created_at - a.created_at)
  }

  async publish(event: NostrEvent, relays: string[]): Promise<PublishResult> {
    this.published.push({ event, relays })
    this.events.push(event)
    return { accepted: [...relays], rejected: [] }
  }
}

function matchesFilter(event: NostrEvent, filter: Filter): boolean {
  if (filter.ids !== undefined && !filter.ids.includes(event.id)) return false
  if (filter.kinds !== undefined && !filter.kinds.includes(event.kind)) return false
  if (filter.authors !== undefined && !filter.authors.includes(event.pubkey)) return false
  if (filter.since !== undefined && event.created_at < filter.since) return false
  if (filter.until !== undefined && event.created_at > filter.until) return false
  for (const [key, values] of Object.entries(filter)) {
    if (!key.startsWith('#') || !Array.isArray(values)) continue
    const tagName = key.slice(1)
    const eventValues = event.tags.filter((tag) => tag[0] === tagName).map((tag) => tag[1])
    const wanted = values as string[]
    if (!wanted.some((value) => eventValues.includes(value))) return false
  }
  return true
}
