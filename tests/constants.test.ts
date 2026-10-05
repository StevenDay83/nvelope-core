import { describe, expect, it } from 'vitest'
import {
  BROADCAST_MESSAGE_FIELDS,
  BROADCAST_TYPE_DEFAULT,
  BROADCAST_TYPE_LIST_SERVE,
  CONTENT_TYPE_HTML,
  CONTENT_TYPE_MARKDOWN,
  CONTENT_TYPE_PLAINTEXT,
  CONTENT_TYPES,
  DIRECT_MESSAGE_FIELDS,
  IDENTIFIER_TAG,
  KEY_INFO_FIELDS,
  KEY_INFO_TAG,
  LABEL_BROADCAST_MESSAGE,
  LABEL_DIRECT_MESSAGE,
  LABEL_TAG,
  MAIL_PROFILE_KIND,
  NONCE_TAG,
  NVELOPE_EVENT_KIND,
  PROFILE_IDENTIFIER_PUBLIC_KEY,
  PROFILE_IDENTIFIER_RECIPIENT_POLICY,
  PROFILE_POLICY_FIELDS,
} from '../src/index.js'

describe('protocol constants', () => {
  it('pins the Nostr event kinds', () => {
    expect(NVELOPE_EVENT_KIND).toBe(8500)
    expect(MAIL_PROFILE_KIND).toBe(30998)
  })

  it('pins the tag names and label values', () => {
    expect(NONCE_TAG).toBe('nonce')
    expect(LABEL_TAG).toBe('l')
    expect(KEY_INFO_TAG).toBe('key_info')
    expect(IDENTIFIER_TAG).toBe('d')
    expect(LABEL_DIRECT_MESSAGE).toBe('direct_message')
    expect(LABEL_BROADCAST_MESSAGE).toBe('broadcast_message')
    expect(PROFILE_IDENTIFIER_RECIPIENT_POLICY).toBe('nv_recipient_profile')
    expect(PROFILE_IDENTIFIER_PUBLIC_KEY).toBe('nv_public_key')
  })

  it('pins the direct-message wire field names', () => {
    expect(DIRECT_MESSAGE_FIELDS).toEqual({
      mailFrom: 'mailFrom',
      mailToList: 'mailToList',
      ccList: 'ccList',
      bccTo: 'bccTo',
      replyTo: 'replyTo',
      subjectLine: 'subjectLine',
      messageType: 'messageType',
      externalReferences: 'external_references',
      threadId: 'thread_id',
    })
  })

  it('pins the broadcast-message wire field names and types', () => {
    expect(BROADCAST_MESSAGE_FIELDS).toEqual({
      broadcastMessageType: 'broadcastMessageType',
      replyTo: 'replyTo',
      subjectLine: 'subjectLine',
      author: 'author',
      topic: 'topic',
      messageType: 'messageType',
      externalReferences: 'external_references',
    })
    expect(BROADCAST_TYPE_DEFAULT).toBe(0)
    expect(BROADCAST_TYPE_LIST_SERVE).toBe(1)
  })

  it('pins the policy, key-info, and content-format names', () => {
    expect(PROFILE_POLICY_FIELDS).toEqual({
      allow: 'allow',
      deny: 'deny',
      globalMinimum: 'global_minimum',
      contacts: 'contacts',
      list: 'list',
      untrusted: 'untrusted',
      target: 'target',
      leadingZeros: 'leadingzeros',
    })
    expect(KEY_INFO_FIELDS).toEqual({ salt: 'salt', iv: 'iv' })
    expect(CONTENT_TYPES).toEqual(['plaintext', 'md', 'html'])
    expect(CONTENT_TYPE_PLAINTEXT).toBe('plaintext')
    expect(CONTENT_TYPE_MARKDOWN).toBe('md')
    expect(CONTENT_TYPE_HTML).toBe('html')
  })

  it('builds a wire object whose keys match the locked shape', () => {
    const wire = {
      [DIRECT_MESSAGE_FIELDS.mailFrom]: 'a'.repeat(64),
      [DIRECT_MESSAGE_FIELDS.mailToList]: ['b'.repeat(64)],
      [DIRECT_MESSAGE_FIELDS.subjectLine]: 'Hello',
      [DIRECT_MESSAGE_FIELDS.messageType]: { [CONTENT_TYPE_PLAINTEXT]: 'SGVsbG8=' },
    }
    expect(wire).toEqual({
      mailFrom: 'a'.repeat(64),
      mailToList: ['b'.repeat(64)],
      subjectLine: 'Hello',
      messageType: { plaintext: 'SGVsbG8=' },
    })
  })
})
