const PlainText = "plaintext";
const MarkDown = "md";
const HTML = "html";

const DEFAULT = '0';
const LIST_SERVE = '1';

const { randomBytes, scryptSync } = require('crypto');

module.exports.BroadcastMessage = class BroadcastMessage {
    constructor(){
        this.messageContent = {};
        this.messageContent[PlainText] = "";
        this.messageContent[MarkDown] = "";
        this.messageContent[HTML] = "";

        this.messageType = DEFAULT;
        this.replyTo = "";
        this.subjectLine = "";

        this.externalReferences = [];

        this.pubkey;
        this.preSharedKeyPassword = '';
        this.pskSaltHex = '';
        this.preSharedKeyValue;
        this.topic = '';


    }

    setContent(thisContent, contentType = PlainText){
        if (thisContent && typeof(thisContent) === 'string'){
            this.messageContent[contentType] = thisContent;
        }
    }

    setSubjectLine(thisSubject){
        if (thisSubject && typeof(thisSubject) === 'string'){
            this.subjectLine = thisSubject;
        }
    }

    setReplyTo(thisReplyTo){
        if (thisReplyTo && typeof(thisReplyTo) === 'string'){
            this.replyTo = thisReplyTo.toLowerCase();
        }
    }

    addExternalReference(thisExtReference){
        if (thisExtReference && Array.isArray(thisExtReference) &&
    thisExtReference.length > 1){
            this.externalReferences.push(thisExtReference);
        }
    }

    getContentText(contentType = PlainText){
        if (this.messageContent && this.messageContent[contentType]){
            return this.messageContent[contentType]
        }
    }

    setPresharedKeyPassphrase(pskText, pskSaltHexString){
        if (pskText && typeof(pskText) === 'string'){
            this.preSharedKeyPassword = pskText;
            this.pskSaltHex = (pskSaltHexString && typeof(pskSaltHexString) === 'string' && this.isHexValue(pskSaltHexString)) ?
            pskSaltHexString : pskSaltHexString = randomBytes(32).toString('hex');
        }
    }

    isHexValue(hexText){
        return hexText != undefined && typeof(hexText) === 'string' ? Buffer.from(hexText, 'hex').length > 0 : false;
    }
}