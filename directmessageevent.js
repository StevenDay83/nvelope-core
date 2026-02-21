// import { finalizeEvent } from 'nostr-tools/pure';

const { finalizeEvent, generateSecretKey, getPublicKey, getEventHash, verifyEvent } = require('nostr-tools/pure');
const { padPrefix64BitHash } = require('./pow.js');
const { getEvents } = require('./nostr.js');

const NVelopeKind = 8500;

function createMessageEvent(directMessage, secretKey){
    var messageEvent;

    if (secretKey && directMessage && typeof(directMessage) === 'object' &&
    directMessage.mailFrom == getPublicKey(secretKey)){
        messageEvent = finalizeEvent({
            kind: NVelopeKind,
            created_at: Math.floor(Date.now() / 1000),
            tags:[],
            content:JSON.stringify(directMessage)
        }, secretKey);
    }

    return messageEvent;
}

function createBlindedEnvelope(encryptedData, timeOffset, nonce, secretKey){
    var blindedEvelopeEvent;

    if (encryptedData && Array.isArray(encryptedData) && !isNaN(nonce) &&
    !isNaN(timeOffset) && secretKey){
        // blindedEvelopeEvent = finalizeEvent({
        //     kind:NVelopeKind,
        //     created_at: Math.floor(Date.now() / 1000) + timeOffset,
        //     tags:[["nonce", nonce.toString()]],
        //     content:JSON.stringify(encryptedData)
        // }, secretKey);

        blindedEvelopeEvent = {
            kind:NVelopeKind,
            pubkey:getPublicKey(secretKey),
            created_at: Math.floor(Date.now() / 1000) + timeOffset,
            tags:[["nonce", nonce.toString()],["l","direct_message"]],
            content:JSON.stringify(encryptedData)
        };

        var eventHash = getEventHash(blindedEvelopeEvent);

        if (eventHash){
            blindedEvelopeEvent['id'] = eventHash;
        }
    }

    return blindedEvelopeEvent;
}

function generatePOWBlindedEnvelopeSync(encryptedData, targetHash, secretKey){
    var blindedEnvelopeEvent;

    if (targetHash && typeof(targetHash) === 'string' && encryptedData && Array.isArray(encryptedData)){
        targetHash = padPrefix64BitHash(targetHash);

        if (!secretKey){
            // Create throwaway key, more secure

            secretKey = generateSecretKey();
        }

        var hashFound = false;

        while (!hashFound) {
            var nonce = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
            var newBlindEnv = createBlindedEnvelope(encryptedData, 0, nonce, secretKey);

            if (newBlindEnv){
                if (newBlindEnv.id < targetHash){
                    hashFound = true;
                    blindedEnvelopeEvent = finalizeEvent(newBlindEnv, secretKey);
                    // break;
                }
            }
        }

    }

    return blindedEnvelopeEvent;
}

async function getBlindedEnvelopes(startTime, endTime, relayList, targetDifficultyFilter, callback){
    return new Promise(async (resolve, reject) => {
        try {
            var targetDifficulty = padPrefix64BitHash(targetDifficultyFilter);
    
            var definedEndTime = endTime != undefined ? endTime : Math.floor(Date.now() / 1000);
            if (definedEndTime > startTime) {
                var blindedEnvelopeSearchCriteria = {
                    kinds:[8500],
                    '#l':["direct_message"],
                    since:startTime,
                    until:definedEndTime
                };
    
                var eventList = await getEvents(blindedEnvelopeSearchCriteria, relayList);
    
                if (eventList && Array.isArray(eventList) && eventList.length > 0){
                    var blindedEnvelopeList = [];
                    for (var i = 0; i < eventList.length; i++){
                        var thisBlindedEnvelope = eventList[i];
    
                        if (thisBlindedEnvelope && verifyEvent(thisBlindedEnvelope) && thisBlindedEnvelope.id != undefined){
                            if (thisBlindedEnvelope.id < targetDifficulty){
                                blindedEnvelopeList.push(thisBlindedEnvelope);
                            }
                        }
                    }
                    callback ? callback(blindedEnvelopeList, undefined) : void(0);
                    resolve(blindedEnvelopeList);
                } else {
                    callback ? callback([], undefined) : void(0);
                    resolve([]);
                }
            } else {
                callback ? callback([], undefined) : void(0);
                resolve([]);
            }
        } catch(e) {
            callback ? callback(undefined, e) : void(0);
            reject(e);
        }
    });
}

// function generateBlindedEnvelopePOW(encryptedData, secretKey) {
//     return new Promise(resolve => {
        
//     });
// }

module.exports.createMessageEvent = createMessageEvent;
module.exports.createBlindedEnvelope = createBlindedEnvelope;
module.exports.generatePOWBlindedEnvelopeSync = generatePOWBlindedEnvelopeSync;
module.exports.getBlindedEnvelopes = getBlindedEnvelopes;