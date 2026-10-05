import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  difficultyFromTarget,
  isHex256,
  meetsPowTarget,
  minePow,
  normalizeHex256,
  targetFromDifficulty,
  targetFromLeadingZeros,
} from '../../src/index.js'

const F = 'f'.repeat(64)
const Z = '0'.repeat(64)

describe('normalizeHex256 / isHex256', () => {
  it('normalizes case and left-pads to 64 characters', () => {
    expect(normalizeHex256('ABC')).toBe('0'.repeat(61) + 'abc')
    expect(normalizeHex256('f'.repeat(64))).toBe(F)
  })

  it('rejects empty, over-long, and non-hex input', () => {
    expect(() => normalizeHex256('')).toThrow(TypeError)
    expect(() => normalizeHex256('0'.repeat(65))).toThrow(TypeError)
    expect(() => normalizeHex256('not-hex!')).toThrow(TypeError)
  })

  it('guards 64-char hex strings', () => {
    expect(isHex256(F)).toBe(true)
    expect(isHex256('0'.repeat(63) + 'G')).toBe(false)
    expect(isHex256('abc')).toBe(false)
    expect(isHex256(42)).toBe(false)
    expect(isHex256(undefined)).toBe(false)
  })
})

describe('targetFromLeadingZeros (leading zero bits, NIP-13 style)', () => {
  it('returns the legacy no-constraint sentinel for 0', () => {
    expect(targetFromLeadingZeros(0)).toBe(F)
  })

  it('computes exact 256-bit boundaries (2^(256 - n))', () => {
    expect(targetFromLeadingZeros(1)).toBe('8' + '0'.repeat(63))
    expect(targetFromLeadingZeros(4)).toBe('1' + '0'.repeat(63))
    expect(targetFromLeadingZeros(8)).toBe('01' + '0'.repeat(62))
    expect(targetFromLeadingZeros(255)).toBe('0'.repeat(63) + '2')
  })

  it('rejects out-of-range input', () => {
    expect(() => targetFromLeadingZeros(-1)).toThrow(RangeError)
    expect(() => targetFromLeadingZeros(256)).toThrow(RangeError)
    expect(() => targetFromLeadingZeros(2.5)).toThrow(RangeError)
  })
})

describe('targetFromDifficulty / difficultyFromTarget', () => {
  it('clamps difficulty 1 to the no-constraint sentinel', () => {
    expect(targetFromDifficulty(1)).toBe(F)
    expect(targetFromDifficulty(1n)).toBe(F)
  })

  it('computes exact targets from difficulty', () => {
    expect(targetFromDifficulty(2)).toBe('8' + '0'.repeat(63))
    expect(targetFromDifficulty(16)).toBe('1' + '0'.repeat(63))
  })

  it('converts targets back to difficulty', () => {
    expect(difficultyFromTarget(F)).toBe(1n)
    expect(difficultyFromTarget('8' + '0'.repeat(63))).toBe(2n)
    expect(difficultyFromTarget('1' + '0'.repeat(63))).toBe(16n)
    expect(difficultyFromTarget(targetFromLeadingZeros(8))).toBe(256n)
  })

  it('rejects invalid input', () => {
    expect(() => targetFromDifficulty(0)).toThrow(RangeError)
    expect(() => difficultyFromTarget(Z)).toThrow(RangeError)
  })
})

describe('meetsPowTarget', () => {
  it('compares numerically, matching the legacy string comparison', () => {
    const target = targetFromLeadingZeros(1) // 2^255: only hashes with top bit zero pass
    expect(meetsPowTarget(Z, target)).toBe(true)
    expect(meetsPowTarget('0'.repeat(62) + 'ff', target)).toBe(true)
    expect(meetsPowTarget('8' + '0'.repeat(63), target)).toBe(false) // boundary: equal is not less
    expect(meetsPowTarget(F, target)).toBe(false)
  })

  it('accepts unpadded hex and rejects junk', () => {
    expect(meetsPowTarget('abc', F)).toBe(true)
    expect(() => meetsPowTarget('xyz', F)).toThrow(TypeError)
    expect(() => meetsPowTarget('0'.repeat(65), F)).toThrow(TypeError)
  })
})

describe('leading-zero semantics (bits)', () => {
  it('a hash below 2^(256-n) meets target(n); the boundary itself does not', () => {
    for (let n = 1; n <= 32; n++) {
      const justUnder = ((1n << BigInt(256 - n)) - 1n).toString(16).padStart(64, '0')
      const atBoundary = (1n << BigInt(256 - n)).toString(16).padStart(64, '0')
      expect(meetsPowTarget(justUnder, targetFromLeadingZeros(n))).toBe(true)
      expect(meetsPowTarget(atBoundary, targetFromLeadingZeros(n))).toBe(false)
    }
  })
})

describe('minePow', () => {
  const target = targetFromLeadingZeros(1)
  // Fake hasher: all hashes fail except nonce '42' which returns all zeros.
  const fakeHash = (candidate: { nonce: string }) => (candidate.nonce === '42' ? Z : F)

  it('finds the nonce whose hash meets the target', async () => {
    const result = await minePow((nonce) => ({ nonce }), fakeHash, target, { startNonce: 0 })
    expect(result.nonce).toBe('42')
    expect(result.attempts).toBe(43)
    expect(meetsPowTarget(result.hash, target)).toBe(true)
  })

  it('reports monotonically increasing progress per batch', async () => {
    const progress: number[] = []
    await minePow((nonce) => ({ nonce }), fakeHash, target, {
      startNonce: 0,
      batchSize: 10,
      onProgress: (attempts) => progress.push(attempts),
    })
    expect(progress.length).toBeGreaterThan(0)
    let previous = 0
    for (const value of progress) {
      expect(value).toBeGreaterThan(previous)
      previous = value
    }
  })

  it('rejects a negative startNonce', async () => {
    await expect(
      minePow((nonce) => ({ nonce }), fakeHash, target, { startNonce: -1 }),
    ).rejects.toThrow(RangeError)
  })

  it('supports cancellation via AbortSignal', async () => {
    const controller = new AbortController()
    const promise = minePow((nonce) => ({ nonce }), () => F, target, {
      startNonce: 0,
      batchSize: 5,
      onProgress: () => controller.abort(),
      signal: controller.signal,
    })
    await expect(promise).rejects.toMatchObject({ name: 'AbortError' })
  })

  it('yields to the event loop between batches (timers can fire mid-search)', async () => {
    const controller = new AbortController()
    let timerFired = false
    const timer = setTimeout(() => {
      timerFired = true
      controller.abort()
    }, 5)
    // A target only the all-zeros hash could meet, and our fake never returns it.
    const impossible = '0'.repeat(63) + '1'
    await expect(
      minePow((nonce) => ({ nonce }), () => F, impossible, {
        startNonce: 0,
        batchSize: 1000,
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: 'AbortError' })
    clearTimeout(timer)
    expect(timerFired).toBe(true)
  })

  it('mines real sha256 work against an easy target', async () => {
    const easyTarget = targetFromLeadingZeros(8) // ~256 expected attempts
    const result = await minePow(
      (nonce) => ({ nonce }),
      (candidate) => createHash('sha256').update(JSON.stringify(candidate)).digest('hex'),
      easyTarget,
      { batchSize: 5000 },
    )
    expect(result.attempts).toBeGreaterThan(0)
    expect(meetsPowTarget(result.hash, easyTarget)).toBe(true)
  }, 15_000)
})
