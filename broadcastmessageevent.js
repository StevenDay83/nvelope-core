const { finalizeEvent, generateSecretKey, getPublicKey, getEventHash, verifyEvent } = require('nostr-tools/pure');
const { nip19 } = require('nostr-tools');
const { encryptDataPSK, decryptDataPassword } = require('./encryption.js');
const { getEvents, getTag } = require('./nostr.js');

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
            identifier: JSON.stringify([password,topic]),
            pubkey:pubKey,
            kind:NVelopeKind,
            relays:(relayList && Array.isArray(relayList)) ? relayList : []
        });
    }

    return broadcastNAddr;
}

async function getBroadcastMessagesByNAddress(startTime, endTime, NAddress, defaultRelayList, callback){
    return new Promise(async (resolve, reject) => {
        try {
            var subscribedMessagesList = [];

            if (NAddress && typeof(NAddress) === 'string') {
                var nAddressJSON = nip19.decode(NAddress).data;

                var identifierArray = JSON.parse(nAddressJSON.identifier);
                var password = identifierArray[0];
                var topic = identifierArray[1];
                var author = nAddressJSON.pubkey;

                var relayList = nAddressJSON.relays && Array.isArray(nAddressJSON.relays) ? nAddressJSON.relays : defaultRelayList;

                subscribedMessagesList = await getBroadcastMessages(startTime, endTime, author, password, topic, relayList);
            } 

            callback ? callback(subscribedMessagesList, undefined) : resolve(subscribedMessagesList);
        } catch (e) {
            callback ? callback(undefined, e) : reject(e);
        }
    });
}

async function getBroadcastMessages(startTime, endTime, pubKey, password, topic, relayList, callback) {
    return new Promise(async (resolve, reject) => {
        try {
            var subscribedMessagesList = [];
            var definedEndTime = endTime != undefined ? endTime : Math.floor(Date.now() / 1000);

            if (definedEndTime > startTime) {
                var broadcastMessageSearchCriteria = {
                    kinds: [8500],
                    '#l': ["broadcast_message"],
                    authors:[pubKey],
                    since:startTime,
                    until:definedEndTime
                };

                var eventList = await getEvents(broadcastMessageSearchCriteria, relayList);

                if (eventList && Array.isArray(eventList) && eventList.length > 0){

                    for (var i = 0; i < eventList.length; i++){
                        var thisBroadcastEvent = eventList[i];

                        var encryptedContent = thisBroadcastEvent.content;
                        var keyInfo = JSON.parse(getTag(thisBroadcastEvent, 'key_info', 0));

                        try {
                            var decryptedText = decryptDataPassword(encryptedContent, password, keyInfo);

                            if (decryptedText && typeof(decryptedText) === 'string'){
                                var thisBroadcastMessage = JSON.parse(decryptedText);

                                if (thisBroadcastMessage.author == pubKey && thisBroadcastMessage.topic == topic){
                                    subscribedMessagesList.push([thisBroadcastEvent,thisBroadcastMessage]);
                                }
                            }
                        } catch (err) {
                            continue;
                        }
                    }
                    callback ? callback(subscribedMessagesList, undefined) : resolve(subscribedMessagesList);
                } else {
                    callback ? callback([], undefined) : resolve([]);
                }
            } else {
                callback ? callback([], undefined) : resolve([]);
            }
        } catch (e) {
            callback ? callback([], e) : reject(e);
        }

    });
}

module.exports.createMessageEvent = createMessageEvent;
module.exports.generateBroadcastSubscriptionNaddr = generateBroadcastSubscriptionNaddr;
module.exports.getBroadcastMessagesByNAddress = getBroadcastMessagesByNAddress;
module.exports.getBroadcastMessages = getBroadcastMessages;