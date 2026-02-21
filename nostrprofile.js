
class NostrProfile {
    constructor (eventImport = undefined){
        this.pubkey = eventImport.pubkey
        this.profileContent = (eventImport && eventImport.content) ? JSON.parse(eventImport.content) : {};
        this.contactList = {};
        this.relayList = {};
    }

    setProfileAttribute(field, value){
        var success = false;

        if (field && typeof(field) === 'string'){
            if (value != undefined && (typeof(value) === 'string' || !isNaN(value) || typeof(value) === 'boolean')){
                this.profileContent[field] = value;
                success = true;
            }
        }

        return success;
    }

    deleteProfileAttribute(field) {
        if (field && typeof(field) === 'string' && this.profileContent[field] != undefined){
            delete this.profileContent[field];
        }
    }

    importProfileContent(pubkey, profileContent){
        var success = false;

        try {
            if (profileContent){
                this.pubkey = pubkey;
                if (typeof(profileContent) === 'string'){
                    this.profileContent = JSON.parse(profileContent);
                    success = true;
                } else if (typeof(profileContent) === 'object'){
                    this.profileContent = profileContent;
                    success = true;
                }
            }
        } catch (e){
            console.error(e);
        }

        return success;
    }

    importContactEvent(contactListEvent) {
        var isSuccess = false;

        if (contactListEvent && typeof(contactListEvent) === 'object'){
            if (contactListEvent.tags){
                isSuccess = this.importContactList(contactListEvent.tags) && this.importRelayList(contactListEvent.content);
            }
        }

        return isSuccess;
    }
    importContactList(contactListArray){
        var success = false;

        if (contactListArray && Array.isArray(contactListArray) && contactListArray.length > 0){
            for (var i = 0; i < contactListArray.length; i++){
                var thisContact = contactListArray[i];

                if (thisContact && Array.isArray(thisContact) && thisContact.length >= 2 && thisContact[0] == 'p'){
                    var thisContactPubkey = thisContact[1];

                    this.contactList[thisContactPubkey] = thisContact;
                }
            }
            success = true;
        }

        return success;
    }

    exportContactList(){
        return Object.values(this.contactList);
    }

    importRelayList(importedRelayList){
        var success = false;
        try {
            if (importedRelayList){
                if (typeof(importedRelayList) === 'string'){
                    this.relayList = JSON.parse(importedRelayList);
                    success = true;
                } else if (typeof(importedRelayList) === 'object'){
                    this.relayList = importedRelayList;
                    success = true;
                }
            }
        } catch (e){
            console.error(e);
        }

        return success;
    }

    getAllRelays(){
        return Object.keys(this.relayList);
    }

    getRelaysByAttribute(isRead, isWrite){
        var requestedRelays = [];
        var allRelaysList = this.getAllRelays();

        for (var i = 0; i < allRelaysList.length; i++){
            var thisRelayURL = allRelaysList[i];

            var relayAttribute = this.relayList[thisRelayURL];

            if (relayAttribute){
                if ( (((relayAttribute.read ? relayAttribute.read : false) == isRead) || isRead == undefined) && (((relayAttribute.write ? relayAttribute.write : false) == isWrite) || isWrite == undefined)){
                    requestedRelays.push(thisRelayURL);
                }
            }
        }

        return requestedRelays;
    }
}

module.exports.NostrProfile = NostrProfile;