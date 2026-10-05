import { describe, expect, it } from 'vitest'
import {
  MessageContent,
  decodeBase64,
  encodeBase64,
  parseWireJson,
} from '../../src/index.js'

describe('encodeBase64 / decodeBase64', () => {
  it('round-trips UTF-8 text', () => {
    const text = 'Hello — café ✓'
    expect(decodeBase64(encodeBase64(text))).toBe(text)
  })

  it('rejects malformed base64', () => {
    expect(() => decodeBase64('!!!not-base64!!!')).toThrow(TypeError)
    expect(() => decodeBase64('ABC')).toThrow(TypeError) // invalid padding/length
  })
})

describe('parseWireJson', () => {
  it('parses objects', () => {
    expect(parseWireJson('{"a":1}')).toEqual({ a: 1 })
  })

  it('rejects non-JSON and non-objects', () => {
    expect(() => parseWireJson('{nope')).toThrow(TypeError)
    expect(() => parseWireJson('[1,2]')).toThrow(TypeError)
    expect(() => parseWireJson('"str"')).toThrow(TypeError)
    expect(() => parseWireJson(42 as unknown as string)).toThrow(TypeError)
  })
})

describe('MessageContent', () => {
  it('sets, gets, and removes formats', () => {
    const content = new MessageContent()
    expect(content.isEmpty()).toBe(true)

    content.set('plaintext', 'hello')
    content.set('md', '# hello')
    expect(content.get('plaintext')).toBe('hello')
    expect(content.has('html')).toBe(false)
    expect(content.getFormats()).toEqual(['plaintext', 'md'])

    expect(content.remove('plaintext')).toBe(true)
    expect(content.remove('plaintext')).toBe(false)
    expect(content.get('plaintext')).toBeUndefined()
  })

  it('rejects invalid input', () => {
    const content = new MessageContent()
    expect(() => content.set('', 'x')).toThrow(TypeError)
    expect(() => content.set('plaintext', 42 as unknown as string)).toThrow(TypeError)
  })

  it('wire form base64-encodes non-empty values and skips empty ones', () => {
    const content = new MessageContent()
    content.set('plaintext', 'Hello')
    content.set('html', '')
    expect(content.toWire()).toEqual({ plaintext: 'SGVsbG8=' })
  })

  it('fromWire round-trips and preserves unknown future formats', () => {
    const content = MessageContent.fromWire({ plaintext: 'SGVsbG8=', latex: 'eHl6' })
    expect(content.get('plaintext')).toBe('Hello')
    expect(content.get('latex')).toBe('xyz')
    expect(content.toWire()).toEqual({ plaintext: 'SGVsbG8=', latex: 'eHl6' })
  })

  it('fromWire rejects malformed wire content', () => {
    expect(() => MessageContent.fromWire('nope')).toThrow(TypeError)
    expect(() => MessageContent.fromWire([1])).toThrow(TypeError)
    expect(() => MessageContent.fromWire({ plaintext: 42 })).toThrow(TypeError)
    expect(() => MessageContent.fromWire({ plaintext: '!!!' })).toThrow(TypeError)
  })
})
