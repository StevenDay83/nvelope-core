const { finalizeEvent, generateSecretKey, getPublicKey, getEventHash, verifyEvent } = require('nostr-tools/pure');
const { nip19 } = require('nostr-tools');
const { encryptDataPSK } = require('./encryption.js');

const NVelopeKind = 8500;

function createMessageEvent(broadcastMessageObject, secretKey){
    var broadcastMessageEvent;

    if (secretKey && broadcastMessageObject && typeof(broadcastMessageObject) === 'object' &&
    broadcastMessageObject.authorPubkey == getPublicKey(secretKey)){
        var encryptedBroadcastMessage = encryptDataPSK(JSON.stringify(broadcastMessageObject.generateEmailMessage()),
        broadcastMessageObject.preSharedKey, Buffer.from(broadcastMessageObject.passwordIV, 'hex', 16));

        var keyInfo = {};
        keyInfo["salt"] = broadcastMessageObject.passwordSalt;
        keyInfo["iv"] = broadcastMessageObject.passwordIV;
        if (encryptedBroadcastMessage) {
            broadcastMessageEvent = finalizeEvent({
                kind: NVelopeKind,
                created_at: Math.floor(Date.now() / 1000),
                tags:[["l","broadcast_message"],["key_info",JSON.stringify(keyInfo)]],
                content:encryptedBroadcastMessage
            }, secretKey);
        }
    }

    return broadcastMessageEvent;
}

function generateBroadcastSubscriptionNaddr(pubKey, topic, password, relayList){
    var broadcastNAddr;

    if (pubKey && typeof(pubKey) === 'string' && topic && typeof(topic) === 'string' && 
    password && typeof(password) === 'string'){
        broadcastNAddr = nip19.naddrEncode({
            identifier:password,
            pubkey:pubKey,
            kind:NVelopeKind,
            relays:(relayList && Array.isArray(relayList)) ? relayList : []
        });
    }

    return broadcastNAddr;
}

module.exports.createMessageEvent = createMessageEvent;
module.exports.generateBroadcastSubscriptionNaddr = generateBroadcastSubscriptionNaddr;