/**
 * Offline end-to-end demo: Alice and Bob exchange Nostr-Mail over a shared
 * in-memory transport. Run with:  npx tsx examples/demo-offline.ts
 */
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  BroadcastMessage,
  DirectMessage,
  MemoryTransport,
  NsecSigner,
  NvelopeClient,
  RecipientPolicy,
  encodeBroadcastNaddr,
  generateMailCertificate,
} from '../src/index.js'

const RELAYS = ['wss://demo.local'] // placeholder URLs; MemoryTransport ignores them

function makeUser(name: string, transport: MemoryTransport) {
  const secretKey = generateSecretKey()
  const cert = generateMailCertificate()
  const client = new NvelopeClient({
    transport,
    signer: new NsecSigner(secretKey),
    relays: RELAYS,
    certificatePrivateKeyPem: cert.privateKeyPem,
  })
  console.log(`${name}: ${getPublicKey(secretKey).slice(0, 16)}…`)
  return { client, pubkey: getPublicKey(secretKey) }
}

async function main() {
  const transport = new MemoryTransport()
  const alice = makeUser('Alice', transport)
  const bob = makeUser('Bob  ', transport)

  // Bob publishes his profile: anyone may send, but untrusted senders must
  // attach 8 leading zeros of proof-of-work.
  await bob.client.publishProfile(new RecipientPolicy().setAllowUntrustedPolicy({ leadingZeros: 8 }))
  console.log('Bob published his mail profile (untrusted senders: 8 leading zeros)')

  // Alice sends Bob a message. The client resolves Bob's certificate and
  // policy, mines the required PoW, seals and publishes — one call.
  await alice.client.sendDirectMail(
    new DirectMessage().addRecipientTo(bob.pubkey).setSubject('nVelope demo').setPlaintext('Hello Bob — sent over Nostr-Mail!'),
  )
  console.log('Alice -> Bob: envelope sealed (PoW mined) and published')

  // Bob checks his inbox.
  const { inbox, rejected } = await bob.client.checkDirectInbox()
  for (const mail of inbox) {
    console.log(`Bob's inbox: "${mail.message.getSubject()}" from ${mail.senderPubkey.slice(0, 16)}…`)
  }
  console.log(`(${rejected.length} envelope(s) decrypted but rejected by Bob's policy)`)

  // Bob runs an announcements list; Alice subscribes via its naddr.
  await bob.client.publishBroadcast(
    new BroadcastMessage().setTopic('announcements').setSubject('List is live').setPlaintext('welcome!'),
    'announcements-password',
  )
  const naddr = encodeBroadcastNaddr({
    author: bob.pubkey,
    password: 'announcements-password',
    topic: 'announcements',
  })
  alice.client.addBroadcastCredential(naddr)
  console.log('Bob published a broadcast list; Alice subscribed via naddr')

  const broadcast = await alice.client.checkBroadcastInbox()
  for (const mail of broadcast) {
    console.log(`Alice's broadcast inbox: [${mail.message.getTopic()}] "${mail.message.getSubject()}"`)
  }

  console.log('\nDemo complete — no network was involved.')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
