// Functions
// Generate Nostr Mail Public\Private Keypair
// Get Nostr Mail Profile Public Key
// 

class MailProfile {
    constructor(publicKey){
        this.pubkey = publicKey;
        this.recipientProfile = {
            allow:{
                contacts:{},
                list:{},
                untrusted:{}
            },
            deny:{
                list:[],
                untrusted:false,
                contacts:false
            },
            global_minimum:{}
        };

        this.nvPublicKey = '';
    }

    importRecipientProfile(thisPubKey, thisProfile){
        var isSuccess = false;

        if (thisProfile && thisPubKey && typeof(thisPubKey) === 'string') {
            if (thisProfile.allow){
                if (thisProfile.allow.contacts){
                    if (thisProfile.allow.contacts.target && typeof(thisProfile.allow.contacts.target) === 'string'){
                        this.setAllowContactsTargetPolicy(thisProfile.allow.contacts.target);
                    } else if (thisProfile.allow.contacts.leadingzeros != undefined && !isNaN(thisProfile.allow.contacts.leadingzeros)){
                        this.setAllowContactsLeadingZeroPolicy(thisProfile.allow.contacts.leadingzeros);
                    }
                }
                if (thisProfile.allow.list && typeof(thisProfile.allow.list) === 'object'){
                    var pubKeyList = Object.keys(thisProfile.allow.list);

                    for (var i = 0; i < pubKeyList.length; i++){
                        var thisPubKey = pubKeyList[i];
                        var pubKeyPolicy = thisProfile.allow.list[thisPubKey];

                        this.addAllowListPubkeyPolicy(thisPubKey, pubKeyPolicy.target, pubKeyPolicy.leadingzeros);
                    }
                }
                if (thisProfile.allow.untrusted){
                    if (thisProfile.allow.untrusted.target && typeof(thisProfile.allow.untrusted.target) === 'string'){
                        this.setAllowUntrustedTargetPolicy(thisProfile.allow.untrusted.target);
                    } else if (thisProfile.allow.untrusted.leadingzeros != undefined && !isNaN(thisProfile.allow.untrusted.leadingzeros)){
                        this.setAllowUntrustedLeadingZeroPolicy(thisProfile.allow.untrusted.leadingzeros);
                    }
                }

                if (thisProfile.deny){
                    if (thisProfile.deny.list && Array.isArray(thisProfile.deny.list)){
                        for (var i = 0; i < thisProfile.deny.list.length; i++){
                            this.addDenyListPubKey(thisProfile.deny.list[i]);
                        }
                    }
                    if (thisProfile.deny.untrusted){
                        if (thisProfile.deny.untrusted.target && typeof(thisProfile.deny.untrusted.target) === 'string'){
                            this.setDenyUntrustedPolicy(thisProfile.deny.untrusted);
                        }
                    }
                }

                if (thisProfile.global_minimum && typeof(thisProfile.global_minimum) === 'object'){
                    if (thisProfile.global_minimum.target && typeof(thisProfile.global_minimum.target) === 'string'){
                        this.setGlobalMinimumTargetPolicy(thisProfile.global_minimum.target);
                    } else if (thisProfile.global_minimum.leadingzeros != undefined && !isNaN(thisProfile.global_minimum.leadingzeros)){
                        this.setGlobalMinimumLeadingZeroPolicy(thisProfile.global_minimum.leadingzeros);
                    }
                }
                isSuccess = true;
            }
        }

        if (!isSuccess){
            this.recipientProfile = {};
        }

        return isSuccess;
    }

    setAllowContactsTargetPolicy(target){
        if (target && typeof(target) === 'string' &&
        target.length > 0 && target.length <= 64) {
            var trimmedTarget = removeLeadingZeros(target);

            this.recipientProfile.allow.contacts["target"] = trimmedTarget;

            this.clearAllowContactsLeadingZeroPolicy();
        }
    }

    setAllowContactsLeadingZeroPolicy(leadingZeros){
        if (leadingZeros != undefined && !isNaN(leadingZeros) && 
        leadingZeros >= 0 && leadingZeros <= 64){
            this.recipientProfile.allow.contacts["leadingzeros"] = leadingZeros;

            this.clearAllowContactsTargetPolicy();
        }
    }

    clearAllowContactsLeadingZeroPolicy(){
        if (this.recipientProfile.allow.contacts["leadingzeros"]) {
                delete this.recipientProfile.allow.contacts["leadingzeros"];
        }
    }

    clearAllowContactsTargetPolicy(){
        if (this.recipientProfile.allow.contacts["target"]) {
                delete this.recipientProfile.allow.contacts["target"];
        }
    }

    setAllowUntrustedTargetPolicy(target){
        if (target && typeof(target) === 'string' &&
        target.length > 0 && target.length <= 64) {
            var trimmedTarget = removeLeadingZeros(target);

            this.recipientProfile.allow.untrusted["target"] = trimmedTarget;

            this.clearAllowUntrustedsLeadingZeroPolicy();
        }
    }

    setAllowUntrustedLeadingZeroPolicy(leadingZeros){
        if (leadingZeros && !isNaN(leadingZeros) && 
        leadingZeros >= 0 && leadingZeros <= 64){
            this.recipientProfile.allow.untrusted["leadingzeros"] = leadingZeros;

            this.clearAllowUntrustedTargetPolicy();
        }
    }

    clearAllowUntrustedsLeadingZeroPolicy(){
        if (this.recipientProfile.allow.untrusted["leadingzeros"]) {
                delete this.recipientProfile.allow.untrusted["leadingzeros"];
        }
    }

    clearAllowUntrustedTargetPolicy(){
        if (this.recipientProfile.allow.untrusted["target"]) {
                delete this.recipientProfile.allow.untrusted["target"];
        }
    }

    setGlobalMinimumTargetPolicy(target){
        if (target && typeof(target) === 'string' &&
        target.length > 0 && target.length <= 64) {
            var trimmedTarget = removeLeadingZeros(target);

            this.recipientProfile.global_minimum["target"] = trimmedTarget;

            this.clearGlobalMinimumLeadingZeroPolicy();
        }
    }

    setGlobalMinimumLeadingZeroPolicy(leadingZeros){
        if (leadingZeros && !isNaN(leadingZeros) && 
        leadingZeros >= 0 && leadingZeros <= 64){
            this.recipientProfile.global_minimum["leadingzeros"] = leadingZeros;

            this.clearGlobalMinimumTargetPolicy();
        }
    }

    clearGlobalMinimumLeadingZeroPolicy(){
        if (this.recipientProfile.global_minimum["leadingzeros"]) {
                delete this.recipientProfile.global_minimum["leadingzeros"];
        }
    }

    clearGlobalMinimumTargetPolicy(){
        if (this.recipientProfile.global_minimum["target"]) {
                delete this.recipientProfile.global_minimum["target"];
        }
    }

    addAllowListPubkeyPolicy(pubkey, target, leadingzeros){
        if (pubkey && typeof(pubkey) === 'string' && pubkey.length == 64){
            if (target && typeof(target) === 'string' && target.length > 0 &&
            target.length <= 64){
                var trimmedTarget = removeLeadingZeros(target);

                this.recipientProfile.allow.list[pubkey] = { target: trimmedTarget };
            } else if (leadingzeros != undefined && !isNaN(leadingzeros) && leadingzeros >= 0 &&
            leadingzeros <= 64){
                this.recipientProfile.allow.list[pubkey] = { leadingzeros: leadingzeros};
            }
        }
    }

    removeAllowListPubkey(pubkey){
        delete this.recipientProfile.allow.list[pubkey];
    }

    setDenyUntrustedPolicy(isDeny){
        this.recipientProfile.deny["untrusted"] = isDeny;
    }

    addDenyListPubKey(pubkey){
        if (pubkey && typeof(pubkey) === 'string' &&
        pubkey.length == 64){
            pubKeyExists = this.recipientProfile.deny.list.indexOf(pubkey) == -1 ? false : true;

            if (!pubKeyExists){
                this.recipientProfile.deny.list.push(pubkey);
            }
        }
    }

    removeDenyListPubKey(pubkey){
        if (pubkey && typeof(pubkey) === 'string' &&
        pubkey.length == 64){
            pubKeyIndex = this.recipientProfile.deny.list.indexOf(pubkey);

            if (pubKeyIndex >= 0){
                this.recipientProfile.deny.list.splice(pubKeyIndex, 1);
            }
        }
    }

    getAllowPolicyPubKey(pubkey){
        var pubkeyAllowPolicy;
        
        if (pubkey && typeof(pubkey) === 'string' &&
        pubkey.length == 64){
            pubkeyAllowPolicy = this.recipientProfile.allow.list[pubkey];
        }

        return pubkeyAllowPolicy;
    }

    setNVPublicKey(nvPublicKey){
        if (nvPublicKey && typeof(nvPublicKey) === 'string'){
            this.nvPublicKey = nvPublicKey;
        }
    }

    generateRecipientPolicyContent(){
        var generatedContentJSON = {};

        generatedContentJSON["allow"] = {};
        if (this.recipientProfile.allow.contacts){
            if (this.recipientProfile.allow.contacts.target) {
                generatedContentJSON.allow["contacts"] = {
                    target:this.recipientProfile.allow.contacts.target
                };
            } else {
                generatedContentJSON.allow["contacts"] = {
                    leadingzeros: this.recipientProfile.allow.contacts.leadingzeros != undefined ? this.recipientProfile.allow.contacts.leadingzeros : 0
                };
            }
        }
        
        if (this.recipientProfile.allow.list){
            generatedContentJSON.allow["list"] = this.recipientProfile.allow.list;
        }

        if (this.recipientProfile.allow.untrusted){
            if (this.recipientProfile.allow.untrusted.target) {
            generatedContentJSON.allow["untrusted"] = {
                target:this.recipientProfile.allow.untrusted.target
            };
            } else {
                generatedContentJSON.allow["untrusted"] = {
                    leadingzeros: this.recipientProfile.allow.untrusted.leadingzeros != undefined ? this.recipientProfile.allow.untrusted.leadingzeros : 0
                };
            }
        }

        generatedContentJSON["deny"] = {};
        if (this.recipientProfile.deny.list){
            generatedContentJSON.deny["list"] = this.recipientProfile.deny.list;
        }
        generatedContentJSON.deny["untrusted"] = this.recipientProfile.deny.untrusted ? this.recipientProfile.deny.untrusted : false;

        if (this.recipientProfile.global_minimum){
            generatedContentJSON["global_minimum"] = {};
            if (this.recipientProfile.global_minimum.target) {
                generatedContentJSON.global_minimum = {
                    target:this.recipientProfile.global_minimum.target
                };
            } else {
                generatedContentJSON.global_minimum = {
                    leadingzeros: this.recipientProfile.global_minimum.leadingzeros ? this.recipientProfile.global_minimum.leadingzeros : 0
                };
            }
        }

        return generatedContentJSON;
    }
}

function removeLeadingZeros(hexString){
    var trimmedHexString = '';

    if (hexString && typeof(hexString) === 'string' && 
    hexString.length > 0 && hexString.length <= 64){
        trimmedHexString = hexString == '0' ? '0' : hexString.replace(/^0+(?=\d)/,'');
    }

    return trimmedHexString;
}

module.exports.MailProfile = MailProfile;