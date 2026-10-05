/**
 * Relay transport abstraction.
 *
 * The library never owns relay connections itself: callers inject a Transport.
 * nVelope-Client will use NostrToolsTransport (or its own pool-backed
 * implementation); tests use an in-memory fake; a browser build could wrap
 * WebSocket directly. This is what makes the library runtime-agnostic.
 */
import type { Filter } from 'nostr-tools'
import { SimplePool } from 'nostr-tools'
import type { NostrEvent } from '../protocol/events.js'

/** The outcome of publishing one event to a set of relays. */
export interface PublishResult {
  /** Relays that accepted the event (OK). */
  accepted: string[]
  /** Relays that rejected it or timed out. */
  rejected: Array<{ relay: string; message?: string }>
}

/**
 * Minimal relay operations the library needs. `filters` follow the standard
 * Nostr filter shape (kinds, authors, since, '#l', …).
 */
export interface Transport {
  query(filters: Filter | Filter[], relays: string[]): Promise<NostrEvent[]>
  publish(event: NostrEvent, relays: string[]): Promise<PublishResult>
}

/**
 * The slice of SimplePool this transport uses. `list`/`querySync` are both
 * optional because nostr-tools has shipped both across 2.x versions — the
 * transport picks whichever the installed pool exposes.
 */
interface SimplePoolLike {
  list?: (relays: string[], filters: Filter[], params?: { maxWait?: number }) => Promise<unknown[]>
  querySync?: (
    relays: string[],
    filter: Filter,
    params?: { maxWait?: number },
  ) => Promise<unknown[]>
  publish: (relays: string[], event: NostrEvent) => Promise<unknown>[]
  close: (relays?: string[]) => void
}

/** Default Transport backed by nostr-tools' SimplePool. */
export class NostrToolsTransport implements Transport {
  private readonly pool: SimplePoolLike
  /** Per-query max wait in ms (EOSE or timeout, whichever first). */
  readonly maxWaitMs: number

  constructor(options: { pool?: SimplePool; maxWaitMs?: number } = {}) {
    this.pool = (options.pool ?? new SimplePool()) as unknown as SimplePoolLike
    this.maxWaitMs = options.maxWaitMs ?? 5000
  }

  /** Query relays; results are deduplicated by event id. */
  async query(filters: Filter | Filter[], relays: string[]): Promise<NostrEvent[]> {
    if (relays.length === 0) return []
    const filterArray = Array.isArray(filters) ? filters : [filters]

    let raw: unknown[]
    if (this.pool.list !== undefined) {
      raw = await this.pool.list(relays, filterArray, { maxWait: this.maxWaitMs })
    } else if (this.pool.querySync !== undefined) {
      raw = []
      for (const filter of filterArray) {
        raw.push(...(await this.pool.querySync(relays, filter, { maxWait: this.maxWaitMs })))
      }
    } else {
      throw new Error('Installed nostr-tools SimplePool exposes neither list() nor querySync()')
    }

    const byId = new Map<string, NostrEvent>()
    for (const event of raw as NostrEvent[]) {
      byId.set(event.id, event)
    }
    return [...byId.values()]
  }

  /** Publish to all relays; resolves when each has OK'd or timed out. */
  async publish(event: NostrEvent, relays: string[]): Promise<PublishResult> {
    if (relays.length === 0) return { accepted: [], rejected: [] }
    const attempts: Promise<unknown>[] = this.pool.publish(relays, event)
    const settled = await Promise.allSettled(attempts)
    const accepted: string[] = []
    const rejected: PublishResult['rejected'] = []
    settled.forEach((result, index) => {
      const relay = relays[index]
      if (relay === undefined) return
      if (result.status === 'fulfilled') {
        // Some nostr-tools versions resolve with the accepting relay URL.
        accepted.push(typeof result.value === 'string' ? result.value : relay)
      } else {
        const reason = result.reason
        rejected.push({
          relay,
          message: reason instanceof Error ? reason.message : String(reason),
        })
      }
    })
    return { accepted, rejected }
  }

  /** Close pool connections. Call when the client shuts down. */
  close(relays?: string[]): void {
    this.pool.close(relays ?? [])
  }
}
