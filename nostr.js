const ntools = require('nostr-tools/pure');
const { finalizeEvent, generateSecretKey, getPublicKey, getEventHash, verifyEvent } = require('nostr-tools/pure');
const { SimplePool } = require('nostr-tools/pool');
const { MailProfile } = require('./mailprofile.js');
const { useWebSocketImplementation } = require('nostr-tools/relay');
const { WebSocket } = require('ws');


const PROFILE_KIND = 30998;

async function publishRecipientProfile(recipientProfileObject, relayList, sk, callback){
    return new Promise(async (resolve, reject) => {
        useWebSocketImplementation(WebSocket);
        if (recipientProfileObject && typeof(recipientProfileObject) === 'object' &&
        recipientProfileObject.recipientProfile){
            try {
                var recipientProfileJSON = recipientProfileObject.generateRecipientPolicyContent();
    
                if (Object.keys(recipientProfileJSON) && Object.keys(recipientProfileJSON).length > 0){
                    // Generate event
                    var recipientProfileEvent = finalizeEvent({
                        created_at:Math.floor(Date.now() / 1000),
                        kind:PROFILE_KIND,
                        tags:[["d","nv_recipient_profile"]],
                        content:JSON.stringify(recipientProfileJSON)
                    }, sk);
    
                    var relayPool = new SimplePool();
    
                    // await Promise.any(relayPool.publish(relayList, recipientProfileEvent));
                    Promise.any(relayPool.publish(relayList, recipientProfileEvent));
    
                    relayPool.close(relayList);
    
                    callback ? callback(recipientProfileEvent, undefined) : void(0);
                    return resolve(recipientProfileEvent);
    
                } else {
                    callback ? callback(undefined, undefined) : void(0);
                    return resolve(undefined);
                }
            } catch (e){
                callback ? callback(undefined, e) : void(0);
                return reject(e);
            }
        } else {
            var recipientError = new Error("Invalid recipient profile object");
            callback ? callback(undefined, recipientError) : void(0);
            return reject(recipientError);
        }
    
    });
    
}

async function getRecipientProfile(pubkey, relayList, callback){
    return new Promise(async (resolve, reject) => {
        var thisRecipientProfile = new MailProfile();
        var hasRecipientPolicy = false;
        var hasPublicKey = false;
        try {
            if (pubkey && typeof(pubkey) === 'string' && pubkey.length == 64){
                thisRecipientProfile.pubkey = pubkey;
                var relayPool = new SimplePool();
                var eventList = await relayPool.querySync(relayList,{
                    authors:[pubkey],
                    kinds:[30998],
                    '#d':["nv_recipient_profile","nv_public_key"]
                });
    
                if (eventList && Array.isArray(eventList) && eventList.length > 0){
                    for (var i = 0; i < eventList.length; i++){
                        var thisEvent = eventList[i];
                        var dTag = getDTag(thisEvent);
    
                        if (dTag == 'nv_recipient_profile'){
                            thisRecipientProfile.importRecipientProfile(pubkey, JSON.parse(thisEvent.content));
                            hasRecipientPolicy = true;
                        } else if (dTag == 'nv_public_key'){
                            thisRecipientProfile.nvPublicKey = thisEvent.content;
                            hasPublicKey = true;
                        }
                    }
    
                    if (hasRecipientPolicy && hasPublicKey){
                        callback ? callback(thisRecipientProfile, undefined) : void(0);
                        return resolve(thisRecipientProfile);
                    }
                } else {
                    callback ? callback(undefined, undefined) : void(0);
                    return resolve(undefined);

                }
            } else {
                callback ? callback(undefined, undefined) : void(0);
                return resolve(undefined);
            }
        } catch (e) {
            callback ? callback(undefined, e) : void(0);
            return reject(e);
        }
    });
}

function publishPublicKey(recipientProfileObject, relayList, sk, callback) {
    return new Promise(async (resolve, reject) => {
        if (recipientProfileObject && typeof(recipientProfileObject) === 'object' &&
        recipientProfileObject.nvPublicKey && typeof(recipientProfileObject.nvPublicKey) === 'string' &&
        recipientProfileObject.nvPublicKey.length > 0){
                try {
    
                    var nvPublicKeyEvent = finalizeEvent({
                                created_at:Math.floor(Date.now() / 1000),
                                kind:PROFILE_KIND,
                                tags:[["d","nv_public_key"]],
                                content:recipientProfileObject.nvPublicKey
                            }, sk);
    
                    var relayPool = new SimplePool();
    
                    Promise.any(relayPool.publish(relayList, nvPublicKeyEvent));
    
                    relayPool.close(relayList);
    
                    callback ? callback(nvPublicKeyEvent, undefined) : void(0);
                    return resolve(nvPublicKeyEvent);
                } catch (e) {
                    callback ? callback(undefined, e) : void(0);
                    return reject(e);
                }
        } else {
            var thrownError = new Error("Invalid Object");
            callback ? callback(undefined, thrownError) : void(0);
            return reject(thrownError);
        }
    });
    
}

async function publishEvent(thisEvent, relayList, callback) {
    return new Promise(async (resolve, reject) => {
        if (thisEvent && typeof(thisEvent) === 'object') {
            if (relayList && Array.isArray(relayList)) {
                if (verifyEvent(thisEvent)){
                    var relayPool = new SimplePool();
    
                    Promise.any(relayPool.publish(relayList, thisEvent));
                    
                    relayPool.close(relayList);
    
                    callback ? callback(thisEvent, undefined) : void(0);
                    resolve(thisEvent);
                } else {
                    callback ? callback(undefined, new Error("Invalid Event")) : void(0);
                    reject(new Error("Invalid Event"));
                }
            } else {
                callback ? callback(undefined, new Error("Invalid relay list")) : void(0);
                reject(new Error("Invalid relay list"));
            }
        } else {
            callback ? callback(undefined, new Error("Invalid Event")) : void(0);
            reject(new Error("Invalid Event"));
        }
    });
}

async function getEvents(criteria, relayList, callback) {
    return new Promise(async (resolve, reject) => {
        try {
        criteria = (criteria && typeof(criteria)) === 'object' ? criteria : {};
    
            if (relayList && Array.isArray(relayList) && relayList.length > 0){
                var relayPool = new SimplePool();
                var eventList = await relayPool.querySync(relayList, criteria);
    
                if (eventList && Array.isArray(eventList) && eventList.length > 0){
                    callback ? callback(eventList, undefined) : void(0);
                    resolve(eventList);
                } else {
                    callback ? callback(undefined, undefined) : void(0);
                    resolve(undefined);
                }
            } else {
                var thisError = new Error("No relays specified");
                callback ? callback(undefined, thisError) : void(0);
                reject(e);
            }
        } catch (e) {
            callback ? callback(undefined, e) : void(0);
            reject(e);
        }
    });
}

function getDTag(eventObject, valueNumber = 0){
    var dTagValue;

    if (eventObject && typeof(eventObject) === 'object'){
        if (eventObject.tags && Array.isArray(eventObject.tags)){
            for (var i = 0; i < eventObject.tags.length; i++){
                var thisTag = eventObject.tags[i];

                if (thisTag.length > (valueNumber + 1) && thisTag[0] == "d"){
                    dTagValue = thisTag[valueNumber + 1];
                    break;
                }
            }
        }
    }

    return dTagValue;
}

async function getNostrProfileEvent(pubkey, relayList, callback) {
    
    return new Promise(async (resolve, reject) => {
        var relayPool = new SimplePool();
        var nostrProfileEvent;

        try {
            var eventList = await relayPool.querySync(relayList,{
                authors:[pubkey],
                kinds:[0]
            });
        
            if (eventList && Array.isArray(eventList) && eventList.length > 0){
                nostrProfileEvent = eventList[0];
                callback ? callback(nostrProfileEvent, undefined) : void(0);
            } else {
                callback ? callback(undefined, undefined) : void(0);
            }
    
            return resolve(nostrProfileEvent);

        } catch (e) {
            callback ? callback(undefined, e) : void(0);
            return reject(e);
        }
    });
}

async function getNostrContactRelayList(pubkey, relayList, callback){
    
    return new Promise(async (resolve, reject) => {
        var relayPool = new SimplePool();
        var nostrContactListEvent;
    
        try {
            var eventList = await relayPool.querySync(relayList,{
                authors:[pubkey],
                kinds:[3]
            });
        
            if (eventList && Array.isArray(eventList) && eventList.length > 0){
                nostrContactListEvent = eventList[0];
                callback ? callback(nostrContactListEvent, undefined) : void(0);
            } else {
                callback ? callback(undefined, undefined) : void(0)
            }

            return resolve(nostrContactListEvent);
        } catch (e){
            callback ? callback(undefined, e) : void(0);
            return reject(e);
        }
    });
}

function getRecipientPolicyForPubkey(recipientProfile, nostrProfile, thisPubKey){
    if (thisPubKey && typeof(thisPubKey) === 'string' && recipientProfile && typeof(recipientProfile) === 'object' && 
        nostrProfile && typeof(nostrProfile) == 'object'){
        
            var isContact = false;
            if ((nostrProfile.pubkey == thisPubKey) || (nostrProfile.contactList && Object.keys(nostrProfile.contactList).length > 0)){
                isContact = true;
            }

            if (recipientProfile.deny){
                if (recipientProfile.deny.list && Array.isArray(recipientProfile.deny.list)){
                    if (recipientProfile.deny.list.indexOf(thisPubKey) > -1){
                        return {deny: recipientProfile.deny.list};
                    }
                }
                if (recipientProfile.deny.contacts && isContact){
                    return {deny: {contacts: true}};
                }
                if (recipientProfile.deny.untrusted && !isContact){
                    return {deny: {untrusted: true}};
                }
            }
            if (recipientProfile.allow){
                if (recipientProfile.allow.list && Array.isArray(Object.keys(recipientProfile.allow.list))){
                    if (recipientProfile.allow.list[thisPubKey]){
                        var policyObj = {allow:{}};
                        policyObj.allow[thisPubKey] = recipientProfile.allow.list[thisPubKey];
                        return policyObj;
                    }
                }
                if (recipientProfile.allow.contacts && isContact){
                    return {allow: {contacts: recipientProfile.allow.contacts}};
                } else if (recipientProfile.allow.untrusted && !isContact){
                    return {allow: {untrusted: recipientProfile.allow.untrusted}}
                } else {
                    return { deny : {untrusted: true}};
                }
            } else {
                return { deny : {untrusted: true}};
            }
    } else {
        return undefined;
    }
}

module.exports.publishRecipientProfile = publishRecipientProfile;
module.exports.publishPublicKey = publishPublicKey;
module.exports.getRecipientProfile = getRecipientProfile;
module.exports.publishEvent = publishEvent;
module.exports.getNostrProfileEvent = getNostrProfileEvent;
module.exports.getNostrContactRelayList = getNostrContactRelayList;
module.exports.getRecipientPolicyForPubkey = getRecipientPolicyForPubkey;
module.exports.getEvents = getEvents;