# nvelope-core
nvelope nostr mail library

*The below is from the Nostr Mail nVelope White Paper posting at [nVelope nost-mail white paper](https://yakihonne.com/article/naddr1qvzqqqr4gupzqvvyf6u8ha0qja9zq2r7xlznzlv3z5qzk2uv5pkwhp3guamyhh9tqy2hwumn8ghj7un9d3shjtnyv9kh2uewd9hj7qq4xvcyx422x9c5se3cxarx7629ddgnjmp5w5tcjxpr)*

## What is Nostr Mail?

Nostr-Mail is a protocol built on top of the Nostr protocol to allow npub (Nostr accounts) to communicate with each other in a secure, private way. It is designed to be opt-in for receiving email to disallow unwanted and malicious messages. Privacy is handled in a way to prevent any 3rd party from intercepting messages or metadata between two or more participants in the protocol. Lastly, the protocol is designed to have safe guards in the event of a nsec key leak where an attacker will need several pieces of secret information to completely take over an account.

Nostr-Mail is not a specific email client or server. Software utilizing the Nostr-Mail protocol would be used by Nostr users to set up, send, and receive emails.

## Components of Nostr-Mail

The Nostr-Mail protocol is made up of multiple components that senders and recipients use for coordination and communication. These components are built on top of the existing Nostr data such as Nostr profiles (Kind 0) and relay lists.

### Nostr-Mail profile

Just as Nostr users may have a Nostr profile (Kind 0) to provide information such as a avatar picture, reference name, etc, a Nostr-Mail profile extends this to Nostr-Mail specific data for interacting with the protocol.

A Nostr-Mail profile is composed of the following:

**Public Certificate:** This is the "public key" used by sends to encrypt messages intended for the user. A corresponding Private Certificate is stored safely by the user to decrypt emails sent to them.
**Recipient Policy:** This is the policy the Nostr-Mail user has defined for which Nostr npubs are allowed to send messages to the recipient as well as other constraints like Proof-of-Work minimums.
**Global Filter:** Proof of Work minimum for all senders. This is designed to reduce the burden of a recipient's Nostr-Mail client in which messages to attempt to process.

#### Nostr-Mail Public Key

Nostr-Mail public key are a base prerequisite for being able to receive emails on the Nostr-Mail protocol. It privates all senders a means to encrypt messages that will be published on Nostr relays and later retrieved by the recipient. A Nostr-Mail pubkey should be generated and published as part of the setup of a new Nostr-Mail participant. 

The pubkey is a RSA fixed length public private key pair. The private key component of the certificate would be stored with the recipient and usually on the recipient's Nostr-Mail client. If this key were exposed, anyone would be able to read all messages sent using that certificate.

The expectation will be that a strong certificate key pair will be generated and in use for a couple of years before being rotated out and a new certificate being published for senders to utilize.

The Nostr-Mail profile pubkey also safeguards a Nostr-Mail user who may have had their nsec secret key compromised. Even in this scenario an attacker would still need the Nostr-Mail private key to read past or present emails.

#### Nostr-Mail Recipient Policy

The Nostr-Mail protocol is designed to be opt-in for receiving emails from other participants. This means that the recipient policy will determine the rules allowing the recipient to process and store the message. 

The recipient policy is not enforced on the Nostr protocol level and it will be up to Nostr-Mail clients to follow the enforcement rules. The recipient policy is also designed within trust layers.

The Nostr-Mail Recipient Policy trust layers are as followed:

**Paired Trusts:** These are the most trusted senders within a recipient policy. A paired trust is established using a pre-shared key, either sent using an special message invitation on the Nostr-Mail protocol or handled out-of-band between users. It is presumed that a paired trust has little risk of sending unwanted or malicious messages. The pre-shared key that will be embedded in each email will also ensure the authenticity of the sender.

**Explicitly allowed senders:** These are senders that are allowed by a Nostr-Mail recipient in a created allow list. For privacy purposes, an allow list is not published to a relay and will need to be known ahead of time by the sender. The recipient will trust that the npubs they place on the list will not send unwanted or malicious messages.

**Nostr follow list:** These are senders that are publicly known over the Nostr protocol. I will be presumed based on the policy that these messages will be slightly riskier to receive. Senders will be able to determine if they are allowed to send an email to a recipient by checking if they are on a recipient's follow list.

**Everyone else:** Any npubs not grouped above will be placed in this group, if they aren't explicitly blocked. This is the riskiest group as the cost of creating an npub is trivial. It is recommended that this trust layer is the most locked down.

**Blocked users:** This group will be a combination of mute lists and explicitly denied npubs defined locally on a Nostr-Mail client. Nostr-Mail recipients will reject all messages from these npubs.

All the above trust layers will have the following attributes to configure:

**Allow:** Allow the npub to send messages to the recipient
**Deny:** Reject messages from the sender npub
**Restricted:** Signals that some npubs may not be guaranteed to send messages to a recipient. For example, a recipient may restrict their follow list and add specific npubs in a explicit allow list.
**Proof of Work:** In addition to the Global Filter, this sets the POW burden for a sender. A Nostr-Mail recipient may want to receive emails from any npubs and set a very high POW burden (i.e. It will take on average 10 minutes to calculate POW on a sent email). 

### Proof of Work

In addition to the Nostr-Mail Recipient Policy to set the parameters on allowed communication, the Nostr-Mail protocol also incorporates cryptographic Proof-of-Work both globally as a minimum standard and for any specific trust layer. This is designed to deter unwanted messages and reduce the burden on processing messages.

As it will be explained in a later section, Nostr-Mail messages are encrypted in Nostr Events that are encrypted called Blinded Envelopes. These Blinded Envelopes are signed by throwaway random keys and do not provide any information on sender, receiver, or message contents. Blinded Envelopes have a tradeoff that a recipient will not be able to determine which messages are intended for them and will need to attempt to decrypt messages with their certificate private key. 

The Global Filter defined in the Nostr-Mail Recipient Policy helps reduce the processing of Blinded Envelopes by discarding any Blinded Envelopes that do not meet the minimum threshold. For example if a Nostr-Mail client has pulled in any potential messages sent to them, it will filter out any of the Blinded Envelopes that do not meet the minimum POW requirements without ever attempting to decrypt any messages. 

Additionally, a Nostr-Mail recipient may want to allow any npubs to send messages, such as for feedback or opt-in solicitation. Messages grouped in the “Everyone else” trust layer could require enough POW to ensure only deliberate emails get sent or that unwanted messages take too much processing power and time to continue doing. 

Any trust layer group that does not have a POW assigned will default to the Global Filter minimum. 

## Nostr-Mail Messages

The Nostr-Mail protocol has a few core message types that will be utilized for communication. The three types are as follows:

- Direct - An E-mail messages sent from one sender to one of more recipients.
- Special Direct - Similar to a Direct Message but carries special meta-data for coordination activities, such as establishing a paired trust.
- Broadcast - An E-mail message that is published and viable by anyone with a pre-shared key to decrypt the message.

### Direct Message

Direct Messages, not to be confused with chat DMs, are messages that have a defined sender and recipient. The best comparison to SMTP email would be a basic e-mail when one thinks of e-mail in general.

Direct messages can have multiple recipients defined in the "to" field and will generate a separate message for each recipient. This allows each message to be properly encrypted to the intended recipient and written to the intended relay. For example if an Direct Message were being sent to 20 recipients, 20 different messages would need to be generated and sent. At a certain point sending emails to many recipients may be better handled by a Broadcast Message.

Direct Messages, while existing as a properly formatted and signed Nostr event, are never directly written to a relay and are encapsulated in an encrypted event called a Blinded Envelope. Blinded Envelopes act as the privacy and transport function for Direct and Special Direct messages.

#### Blinded Envelopes

Blinded Envelopes are the only method to send Direct and Special Direct messages to recipients. Blinded Envelopes provide the following functions:

Encryption:
	All Blinded Envelopes are encrypted using the recipients public key. This ensures that the contents of Direct and Special Direct message contents are not read by anyone except the holder of the certificate private key. 
	The contents in the Blinded Envelope will be encoded in Base64 for compactness and compatibility purposes.

Privacy:
	Blinded Envelopes are "Blind" because these events can and should be signed by a random Nostr keypair. Only the sender will know which event was signed and only the recipient will be able to process through any listed Blinded Envelopes to find the one intended for them. 
	This ensures that no metadata, such as sender and receiver are leaked when writing the event to a relay, which is publicly accessible. This also prevents any nsec key leaks from further compromising any prior communications. 

Proof of Work:
	Proof of work, mentioned earlier will only be applied to the Blinded Envelope level. The underlying event containing Direct or Special Direct Message data will not require any POW constraints. 
	The sender would need to process the Blinded Envelope event with the an event ID that satisfies the recipient POW requirements.

There are tradeoffs to using Blinded Envelopes that will place some burden on Nostr-Mail clients. All metadata is hidden and there is no way to determine whether a message is for a certain recipient without attempting to decrypt the message. This means that a Nostr-Mail client could spend more time trying to process messages if there are a high amount of Blinded Envelopes on a relay.

Attackers can generate throw away events that will increase the amount of messages a client would need to process. To counter this, a POW Global Filter would always be recommended as a hurdle to any would-be attackers from generating millions of events instantly.

### Broadcast Message

Broadcast messages are messages that do not have a defined recipient specified and are posted for anyone with the correct key to decrypt and read. Broadcast messages help solve the problem of sending messages meant for a large recipient pool, such as a newsletter or notification e-mails.

Broadcast messages have the following components:

- Sender - Defined by the pubkey
- Encryption Key - Symmetric key used to encrypt the message to publish and decrypt for reading
- Topic - Within a broadcast message multiple message topics can be used to filter. For instance if a broadcast message had a topic for outage alerts and one for release updates for a software platform, a recipient can opt to filter out "release updates".

Since Broadcast messages cannot be "sent" to a recipient in the same way a direct message is sent, an out-of-band method of communicating the metadata will need to performed, such as on a website, a social media posting, or using a direct message initially to have recipients "sign up".

Broadcast message metadata would include:
- npub of the message sender
- Preferred relays of the message sender
- Broadcast message topic
- Symmetric Key
#### Publishing a Broadcast message

The process of publishing a Broadcast message is similar to a direct message. The body of the message will contain the contents, encoded in Base64, with all other standard message metadata except no recipient in the message.

- Sender creates the content of the message.
- Sender encrypts message with symmetric key.
- Sender publishes a Blinded Envelope message on Nostr relays that the sender publishes other events to.

The encrypted message will also be placed in a Blinded envelope with the tag indicating it is a Broadcast message.

Please note that Broadcast messages are not subject to any POW filtering and that a message can be published without having to perform any POW operations.
#### Receiving a Broadcast message

The recipient of a Broadcast message will have had received the Broadcast message details beforehand. The recipient's Nostr-Mail client should accept the Broadcast message details and can start scanning for messages.
Events will need to be pulled for Blinded Envelopes of type "broadcast" off of the specified relays where the messages will be published. These messages can then be checked with the provided key to decrypt the message and check if the message is valid.

- Recipient imports broadcast message information into Nostr-Mail client
- Nostr-Mail client will look for Blinded Envelopes for broadcast messages on the provided relay addresses
- Each message will be tried against the symmetric key to unlock the message
- The message will be checked for the following:
	- Nostr npub matches broadcast message information
	- Topic matches

It is important that a Nostr-Mail client checks that the sender of the Nostr-Mail as well as if the message was previously received as anyone with knowledge of the symmetric key can rebroadcast a message or send a message with the key.

#### Use cases for Broadcast messages

Broadly, Broadcast messages fill a use case where sending multiple copies of a message with varying proof of work is impractical.

Some proposed use cases:

**Newsletters**
Broadcast messages are ideal for sending out newsletters to many people. A subscription model can include getting access to the broadcast message sender data. Keys could be replaced after a subscription duration and multiple topics can be expanded out for specific newsletter interests.

**Notification emails**
Broadcast messages can also be subscribed to for product or service notifications. Different "topics" for the broadcast messages can also filter out informational messages vs urgent outage notifications.

**Mailing Lists**
Mailing lists could be provided where individual users send direct messages to a certain npub and it is resent out as a broadcast message. Block and allow lists could limit email participants while anyone could subscribe to read the messages. Topics could break out the specific lists.