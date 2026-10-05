/**
 * Real-relay demo: send Nostr-Mail over live relays.
 *
 * Identity comes from the demo keystore (created by `npm run demo:setup`;
 * override its location with IDENTITY_FILE). To use a specific nsec instead,
 * set NSEC_HEX before running setup — the keystore takes precedence once it
 * exists, so delete it to switch identities.
 *
 * Usage:
 *   npm run demo:relay -- <recipient-npub-hex> [subject] [body]
 *
 * Prerequisites: YOUR profile must be published (run demo:setup once), and
 * the RECIPIENT must have published a mail certificate.
 */
import {
  DirectMessage,
  NostrToolsTransport,
  NsecSigner,
  NvelopeClient,
  RecipientPolicy,
} from '../src/index.js'
import { identityPubkey, loadOrCreateIdentity } from './identity.js'

const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol']

async function main() {
  const [recipient, subject = 'Hello from nVelope', body = 'Sent with nvelope-core.'] =
    process.argv.slice(2)
  if (!recipient || !/^[0-9a-f]{64}$/.test(recipient)) {
    console.error('Usage: npm run demo:relay -- <recipient-hex> [subject] [body]')
    console.error('Run `npm run demo:setup` first to create/publish an identity.')
    process.exit(1)
  }

  const { identity } = loadOrCreateIdentity()
  const client = new NvelopeClient({
    transport: new NostrToolsTransport(),
    signer: new NsecSigner(identity.secretKey),
    relays: RELAYS,
    certificatePrivateKeyPem: identity.certificatePrivateKeyPem,
    certificatePublicKeyDerBase64: identity.certificatePublicKeyDerBase64,
  })

  console.log(`Identity: ${identityPubkey(identity)}`)
  console.log('Ensuring your profile is published...')
  await client.publishProfile(new RecipientPolicy())

  console.log(`Sending to ${recipient}...`)
  const sent = await client.sendDirectMail(
    new DirectMessage().addRecipientTo(recipient).setSubject(subject).setPlaintext(body),
    { onProgress: (attempts) => console.log(`  mining PoW... ${attempts} attempts`) },
  )
  for (const result of sent) {
    console.log(
      `Envelope published to ${result.published.accepted.length} relay(s): ${result.published.accepted.join(', ')}`,
    )
  }
  console.log('Done. The recipient can read it with checkDirectInbox().')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
