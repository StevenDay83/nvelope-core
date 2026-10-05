/**
 * demo:setup — create (or reuse) a demo identity and publish its Nostr-Mail
 * profile with basic defaults: an open recipient policy (everyone may send,
 * no proof-of-work required) and a fresh 2048-bit mail certificate.
 *
 * Run:  npm run demo:setup
 *
 * Afterwards, send mail to the printed npub with:
 *   npm run demo:relay -- <npub> "Subject" "Body"
 * (omit -- args to send from this same identity to itself).
 */
import { NostrToolsTransport, NsecSigner, NvelopeClient, RecipientPolicy } from '../src/index.js'
import { identityPath, identityPubkey, loadOrCreateIdentity } from './identity.js'

const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol']

async function main() {
  const { identity, created } = loadOrCreateIdentity()
  const pubkey = identityPubkey(identity)

  if (created) {
    console.log(`Created demo identity at ${identityPath()} (plaintext — demo use only!)`)
  } else {
    console.log(`Reusing demo identity at ${identityPath()}`)
  }
  console.log(`npub (hex): ${pubkey}`)

  const client = new NvelopeClient({
    transport: new NostrToolsTransport(),
    signer: new NsecSigner(identity.secretKey),
    relays: RELAYS,
    certificatePrivateKeyPem: identity.certificatePrivateKeyPem,
    certificatePublicKeyDerBase64: identity.certificatePublicKeyDerBase64,
  })

  console.log('Publishing mail profile: open policy (everyone may send, no PoW required)...')
  const results = await client.publishProfile(new RecipientPolicy())
  for (const result of results) {
    console.log(`  accepted by ${result.accepted.length} relay(s)`)
  }

  console.log('\nSetup complete. To test, send mail to yourself:')
  console.log(`  npm run demo:relay -- ${pubkey} "Hello" "First live Nostr-Mail!"`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
