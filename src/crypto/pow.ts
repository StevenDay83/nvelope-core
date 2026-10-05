/**
 * Proof-of-Work mathematics and a non-blocking miner.
 *
 * A PoW target is a 256-bit integer. On the wire (and in profile policy) it is
 * a 64-character hex string. A hash satisfies a target when `hash < target`
 * numerically — for zero-padded 64-char hex strings this is identical to the
 * lexicographic comparison the pre-refactor code used, so events mined here
 * validate under the old rules and vice versa.
 *
 * All math is exact BigInt arithmetic (the old implementation used doubles,
 * which lose precision at 2**256).
 *
 * Semantics: `leadingZeros` counts leading zero BITS, aligned with NIP-13.
 * `leadingZeros: 8` requires the eight most-significant bits of the event id
 * to be zero — expected work 2^8 = 256 hashes. The pre-refactor implementation
 * mixed bit- and digit-based math and produced incorrect targets for multiples
 * of 4 (and an off-by-one at the boundary). The on-wire fields are unchanged;
 * only the calculation is now correct and exact.
 */
import type { Hex256 } from '../types.js'

/** Number of hex digits in a 256-bit value. */
export const HEX_DIGITS_256 = 64

/** 2^256 as a bigint. */
export const TWO_POW_256 = 1n << 256n

/** Canonical target meaning "effectively no constraint" (legacy sentinel). */
export const TARGET_NO_CONSTRAINT = 'f'.repeat(HEX_DIGITS_256)

const HEX_CHARS_PATTERN = /^[0-9a-fA-F]+$/

/**
 * Type guard for 64-character hex strings (Nostr pubkeys, event ids, hashes).
 */
export function isHex256(value: unknown): value is Hex256 {
  return typeof value === 'string' && value.length === HEX_DIGITS_256 && HEX_CHARS_PATTERN.test(value)
}

/**
 * Assert that a value is a 64-character hex string (a Nostr npub or event id).
 *
 * @throws {TypeError} with a descriptive message when the assertion fails.
 */
export function assertHex256(value: unknown, label: string): asserts value is Hex256 {
  if (!isHex256(value)) {
    throw new TypeError(`${label} must be a 64-character hex string, got: ${JSON.stringify(value)}`)
  }
}

/**
 * Normalize a hex string to canonical wire form: lowercase, zero-padded to 64
 * characters. Accepts lengths 1..64 so callers may pass unpadded values.
 *
 * @throws {TypeError} if the input is empty, longer than 64 chars, or not hex.
 */
export function normalizeHex256(hex: string): Hex256 {
  if (typeof hex !== 'string' || hex.length === 0 || hex.length > HEX_DIGITS_256) {
    throw new TypeError(`Expected a hex string of length 1..${HEX_DIGITS_256}, got: ${JSON.stringify(hex)}`)
  }
  if (!HEX_CHARS_PATTERN.test(hex)) {
    throw new TypeError(`Not a hex string: ${JSON.stringify(hex)}`)
  }
  return hex.toLowerCase().padStart(HEX_DIGITS_256, '0')
}

/**
 * Compute the PoW target for a number of leading zero BITS (NIP-13 style).
 *
 * - `0` returns the legacy no-constraint sentinel (`'f'.repeat(64)`). Strictly
 *   it rejects only the all-ones hash; at probability 2^-256 this is the same
 *   as "no constraint" and matches the pre-refactor behavior exactly.
 * - `n` (1..255) returns `2^(256 - n)` as a 64-char hex string, i.e. the hash
 *   must be numerically less than that boundary.
 *
 * @throws {RangeError} for non-integers and values outside [0, 255].
 */
export function targetFromLeadingZeros(leadingZeros: number): Hex256 {
  if (!Number.isInteger(leadingZeros) || leadingZeros < 0 || leadingZeros > 255) {
    throw new RangeError(`leadingZeros must be an integer in [0, 255], got: ${leadingZeros}`)
  }
  if (leadingZeros === 0) {
    return TARGET_NO_CONSTRAINT
  }
  const target = 1n << BigInt(256 - leadingZeros)
  return target.toString(16).padStart(HEX_DIGITS_256, '0')
}

/**
 * Compute the PoW target for an expected difficulty (average hashes needed).
 * The result is `floor(2^256 / difficulty)`, clamped to the no-constraint
 * sentinel when the difficulty is 1. Note difficulty 2 equals one leading
 * zero bit, 16 equals four, and so on.
 *
 * @throws {RangeError} for difficulty < 1.
 */
export function targetFromDifficulty(difficulty: number | bigint): Hex256 {
  const d = BigInt(difficulty)
  if (d < 1n) {
    throw new RangeError(`difficulty must be >= 1, got: ${difficulty}`)
  }
  const target = TWO_POW_256 / d
  if (target >= TWO_POW_256) {
    return TARGET_NO_CONSTRAINT
  }
  return target.toString(16).padStart(HEX_DIGITS_256, '0')
}

/**
 * Convert a target back to its expected difficulty (`floor(2^256 / target)`).
 *
 * @throws {RangeError} if the target is zero (nothing could ever satisfy it).
 */
export function difficultyFromTarget(targetHex: string): bigint {
  const target = BigInt(`0x${normalizeHex256(targetHex)}`)
  if (target === 0n) {
    throw new RangeError('Target must be greater than zero')
  }
  return TWO_POW_256 / target
}

/**
 * Check whether a 256-bit hash satisfies a PoW target (`hash < target`).
 * Inputs are normalized (case-insensitive, unpadded OK).
 */
export function meetsPowTarget(hashHex: string, targetHex: string): boolean {
  const hash = BigInt(`0x${normalizeHex256(hashHex)}`)
  const target = BigInt(`0x${normalizeHex256(targetHex)}`)
  return hash < target
}

/* ------------------------------------------------------------------------ */
/* Non-blocking miner                                                        */
/* ------------------------------------------------------------------------ */

export interface MinePowOptions {
  /**
   * Hash attempts per event-loop yield. Higher = slightly faster, lower =
   * more responsive to other work. Default 10_000.
   */
  batchSize?: number
  /** Called after each batch with the total attempts so far (for progress UI). */
  onProgress?: (attempts: number) => void
  /** Abort the search; the returned promise rejects with name 'AbortError'. */
  signal?: AbortSignal
  /** Starting nonce as a decimal string, number, or bigint (useful for tests/resuming). */
  startNonce?: string | number | bigint
}

export interface MinePowResult<T> {
  /** The candidate built by `buildCandidate` for the winning nonce. */
  candidate: T
  /** The winning nonce, as a decimal string (wire format for the `nonce` tag). */
  nonce: string
  /** The winning hash (64-char lowercase hex). */
  hash: Hex256
  /** Total attempts made (including the winning one). */
  attempts: number
}

/**
 * Search for a nonce such that `hashCandidate(buildCandidate(nonce))` meets
 * `targetHex`.
 *
 * The search loop yields to the event loop between batches, so it never blocks
 * the main thread — a GUI stays responsive and can render `onProgress`. The
 * hash function is injected, keeping this module pure and portable (Node,
 * Electron, browser): for event mining, pass a Nostr event-id hasher.
 */
export async function minePow<T>(
  buildCandidate: (nonce: string) => T,
  hashCandidate: (candidate: T) => string,
  targetHex: string,
  options: MinePowOptions = {},
): Promise<MinePowResult<T>> {
  const target = BigInt(`0x${normalizeHex256(targetHex)}`)
  const batchSize = Math.max(1, Math.floor(options.batchSize ?? 10_000))

  let nonce = options.startNonce !== undefined ? BigInt(options.startNonce) : randomNonce()
  if (nonce < 0n) {
    throw new RangeError('startNonce must be >= 0')
  }

  let attempts = 0

  for (;;) {
    for (let i = 0; i < batchSize; i++) {
      if (options.signal?.aborted) {
        throw new DOMException('Proof-of-work mining aborted', 'AbortError')
      }
      const nonceString = nonce.toString(10)
      const candidate = buildCandidate(nonceString)
      const hash = normalizeHex256(hashCandidate(candidate))
      attempts += 1
      if (BigInt(`0x${hash}`) < target) {
        return { candidate, nonce: nonceString, hash, attempts }
      }
      nonce += 1n
    }
    options.onProgress?.(attempts)
    await yieldEventLoop()
  }
}

/** Random 64-bit starting nonce (via WebCrypto, available in Node 20+ and browsers). */
function randomNonce(): bigint {
  const bytes = new Uint8Array(8)
  globalThis.crypto.getRandomValues(bytes)
  let value = 0n
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte)
  }
  return value
}

/** Hand control back to the event loop so other work (GUI, timers, I/O) can run. */
function yieldEventLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0))
}
