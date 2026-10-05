/**
 * Protocol constants for Nostr-Mail / nVelope.
 *
 * WARNING: everything exported here is WIRE FORMAT. These values appear verbatim
 * in the JSON of events stored on Nostr relays. Do not rename, renumber, or
 * reformat them; doing so is a new protocol version, not a refactor.
 */

/** Kind used for both the inner direct-message event and the outer blinded envelope. */
export const NVELOPE_EVENT_KIND = 8500 as const

/** Kind used for the addressable mail-profile events (recipient policy + certificate pubkey). */
export const MAIL_PROFILE_KIND = 30998 as const

/* ------------------------------------------------------------------------ */
/* Tag names                                                                 */
/* ------------------------------------------------------------------------ */

/** Tag carrying the PoW nonce on a blinded envelope. */
export const NONCE_TAG = 'nonce'

/** Classification tag ("l") distinguishing envelope types. */
export const LABEL_TAG = 'l'

/** Tag carrying passphrase key metadata (salt/iv) on broadcast messages. */
export const KEY_INFO_TAG = 'key_info'

/** Identifier tag ("d") on addressable (parameterized replaceable) events. */
export const IDENTIFIER_TAG = 'd'

/* ------------------------------------------------------------------------ */
/* Tag values                                                                */
/* ------------------------------------------------------------------------ */

/** Envelope label for direct (one-recipient-encrypted) mail. */
export const LABEL_DIRECT_MESSAGE = 'direct_message'

/** Envelope label for broadcast mail. */
export const LABEL_BROADCAST_MESSAGE = 'broadcast_message'

/** `d` tag value of the published recipient policy. */
export const PROFILE_IDENTIFIER_RECIPIENT_POLICY = 'nv_recipient_profile'

/** `d` tag value of the published mail-certificate public key. */
export const PROFILE_IDENTIFIER_PUBLIC_KEY = 'nv_public_key'

/* ------------------------------------------------------------------------ */
/* Body content formats (keys inside `messageType` on the wire)              */
/* ------------------------------------------------------------------------ */

export const CONTENT_TYPE_PLAINTEXT = 'plaintext'
export const CONTENT_TYPE_MARKDOWN = 'md'
export const CONTENT_TYPE_HTML = 'html'

export const CONTENT_TYPES = [
  CONTENT_TYPE_PLAINTEXT,
  CONTENT_TYPE_MARKDOWN,
  CONTENT_TYPE_HTML,
] as const

export type ContentType = (typeof CONTENT_TYPES)[number]

/* ------------------------------------------------------------------------ */
/* Wire field names — the direct-message JSON object                         */
/* ------------------------------------------------------------------------ */

/**
 * Field names of the direct-message JSON object. Part of the protocol:
 * changing them breaks compatibility with messages already on relays.
 */
export const DIRECT_MESSAGE_FIELDS = {
  mailFrom: 'mailFrom',
  mailToList: 'mailToList',
  ccList: 'ccList',
  bccTo: 'bccTo',
  replyTo: 'replyTo',
  subjectLine: 'subjectLine',
  messageType: 'messageType',
  externalReferences: 'external_references',
  threadId: 'thread_id',
} as const

/* ------------------------------------------------------------------------ */
/* Wire field names — the broadcast-message JSON object                      */
/* ------------------------------------------------------------------------ */

export const BROADCAST_MESSAGE_FIELDS = {
  broadcastMessageType: 'broadcastMessageType',
  replyTo: 'replyTo',
  subjectLine: 'subjectLine',
  author: 'author',
  topic: 'topic',
  messageType: 'messageType',
  externalReferences: 'external_references',
} as const

export const BROADCAST_TYPE_DEFAULT = 0
export const BROADCAST_TYPE_LIST_SERVE = 1

/* ------------------------------------------------------------------------ */
/* Wire field names — the recipient-policy JSON object                       */
/* ------------------------------------------------------------------------ */

export const PROFILE_POLICY_FIELDS = {
  allow: 'allow',
  deny: 'deny',
  globalMinimum: 'global_minimum',
  contacts: 'contacts',
  list: 'list',
  untrusted: 'untrusted',
  target: 'target',
  leadingZeros: 'leadingzeros',
} as const

/** Field names inside the `key_info` tag value of broadcast events. */
export const KEY_INFO_FIELDS = {
  salt: 'salt',
  iv: 'iv',
} as const
