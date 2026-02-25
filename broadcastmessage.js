const PlainText = "plaintext";
const MarkDown = "md";
const HTML = "html";

const DEFAULT = 0;
const LIST_SERVE = 1;

const crypto = require('crypto');

module.exports.BroadcastMessage = class BroadcastMessage {
    constructor(){
        this.messageContent = {};
        this.messageContent[PlainText] = "";
        this.messageContent[MarkDown] = "";
        this.messageContent[HTML] = "";

        this.broadcastMessageType = DEFAULT;
        this.replyTo = "";
        this.subjectLine = "";

        this.externalReferences = [];

        this.authorPubkey;
        this.password;
        this.passwordSalt;
        this.passwordIV;
        this.preSharedKey;
        this.topic = '';
    }

    setAuthorPubKey(thisPubKey){
        if (thisPubKey && typeof(thisPubKey) === 'string' && this.isHexValue(thisPubKey)){
            this.authorPubkey = thisPubKey;
        }
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

    setTopic(thisTopic){
        this.topic = thisTopic && typeof(thisTopic) === 'string' ? thisTopic : '';
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

    setPresharedKeyWithPassphrase(thisPassword, thisSalt){
        if (thisPassword && typeof(thisPassword) === 'string' && thisPassword.length > 0){
            this.password = thisPassword;

            this.passwordSalt = (thisSalt && typeof(thisSalt) === 'string' && thisSalt.length == 64 && this.isHexValue(thisSalt)) ? thisSalt : crypto.randomBytes(32).toString('hex');

            if (!this.generatePresharedKey()){
                this.password = '';
                this.passwordSalt = '';
            }
        }
    }

    generatePresharedKey(){
        var isSuccess = true;
        try {
            if (this.password && this.passwordSalt){
                this.preSharedKey = crypto.scryptSync(this.password, Buffer.from(this.passwordSalt, 'hex'), 32);
                this.passwordIV = crypto.randomBytes(16).toString('hex');;
            } else {
                isSuccess = false;
            }
        } catch (e) {
            isSuccess = false;
        }
        return isSuccess;
    }

    isHexValue(hexText){
        return hexText != (undefined && typeof(hexText) === 'string') ? Buffer.from(hexText, 'hex').length > 0 : false;
    }

    generateEmailMessage(){
        var formattedMessage = {};

        formattedMessage["broadcastMessageType"] = this.broadcastMessageType != undefined && !isNaN(this.broadcastMessageType) ? this.broadcastMessageType : DEFAULT;
        
        if (this.replyTo && this.replyTo.length > 0){
            formattedMessage["replyTo"] = this.replyTo;
        }

        if (this.subjectLine && this.subjectLine.length > 0){
            formattedMessage["subjectLine"] = this.subjectLine;
        }

        if (this.authorPubkey){
            formattedMessage["author"] = this.authorPubkey;
        }

        if (this.topic) {
            formattedMessage["topic"] = this.topic;
        }

        var messageTypes = Object.keys(this.messageContent);
        if (messageTypes.length > 0){
            formattedMessage["messageType"] = {};
            for (var i = 0; i < messageTypes.length; i++){
                var thisMessageType = messageTypes[i];
                var thisMessageTypeContent = this.messageContent[thisMessageType];

                if (thisMessageTypeContent.length > 0){
                    formattedMessage["messageType"][thisMessageType] = Buffer.from(thisMessageTypeContent).toString('base64');
                }
            }
        }

        if (this.externalReferences.length > 0){
            formattedMessage["external_references"] = this.externalReferences;
        }

        return formattedMessage;
    }

    importMessage(broadcastMessageObject) {
        var isSuccess = false;
        try {
            if (broadcastMessageObject && typeof(broadcastMessageObject) === 'object'){
                
                if (broadcastMessageObject.author) {
                    this.authorPubkey = broadcastMessageObject.author;
                }

                if (broadcastMessageObject.topic) {
                    this.topic = broadcastMessageObject.topic;
                }

                if (broadcastMessageObject.replyTo && broadcastMessageObject.replyTo.length > 0){
                    this.replyTo = broadcastMessageObject.replyTo;
                }

                if (broadcastMessageObject.subjectLine && broadcastMessageObject.subjectLine.length > 0){
                    this.subjectLine = broadcastMessageObject.subjectLine;
                }

                this.broadcastMessageType = broadcastMessageObject.broadcastMessageType != undefined && !isNaN(broadcastMessageObject.broadcastMessageType) ? 
                broadcastMessageObject.broadcastMessageType : DEFAULT;

                if (broadcastMessageObject.messageType && typeof(broadcastMessageObject.messageType) === 'object'){
                    var messageTypes = Object.keys(broadcastMessageObject.messageType);

                    for (var i = 0; i < messageTypes.length; i++){
                        this.messageContent[messageTypes[i]] = broadcastMessageObject.messageType[messageTypes[i]] ? 
                        Buffer.from(broadcastMessageObject.messageType[messageTypes[i]], 'base64').toString() : ''
                    }
                }

                this.externalReferences = broadcastMessageObject["external_references"] ? broadcastMessageObject["external_references"] : [];

                isSuccess = true;
            }
        } catch (e) {
            console.error(e);
        }

        return isSuccess;
    }
}