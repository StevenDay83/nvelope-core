const PlainText = "plaintext";
const MarkDown = "md";
const HTML = "html";

module.exports.DirectMessage = class DirectMessage {
    constructor(){
        this.messageContent = {};
        this.messageContent[PlainText] = "";
        this.messageContent[MarkDown] = "";
        this.messageContent[HTML] = "";

        this.replyTo = "";
        this.subjectLine = "";

        this.mailFrom = "";
        this.mailToList = [];
        this.ccList = [];
        this.bccList = [];

        this.externalReferences = [];

        this.messageThreadId;
    }

    setContent(thisContent, contentType = PlainText){
        if (thisContent && contentType && typeof(thisContent) === 'string' &&
    typeof(contentType) === 'string'){
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
            this.mailFrom = thisReplyTo.toLowerCase();
        }
    }

    setMailFrom(thisMailFrom){
        if (thisMailFrom && typeof(thisMailFrom) === 'string'){
            this.mailFrom = thisMailFrom.toLowerCase();
        }
    }

    addRecipientTo(thisRecipient){
        if (thisRecipient && typeof(thisRecipient) === 'string'){
            if (this.mailToList.indexOf(thisRecipient.toLowerCase()) < 0){
                this.mailToList.push(thisRecipient.toLowerCase());
            }
        }
    }

    addCCTo(thisCCRecipient) {
        if (thisCCRecipient && typeof(thisCCRecipient) === 'string'){
            if (this.ccList.indexOf(thisCCRecipient.toLowerCase()) < 0){
                this.ccList.push(thisCCRecipient.toLowerCase());
            }
        }
    }

    addBCCTo(thisBCCRecipient) {
        if (thisBCCRecipient && typeof(thisBCCRecipient) === 'string'){
            if (this.bccList.indexOf(thisBCCRecipient.toLowerCase()) < 0){
                this.bccList.push(thisBCCRecipient.toLowerCase());
            }
        }
    }

    // setReplyTo(thisReplyTo) {
    //     if (thisReplyTo && typeof(thisReplyTo) === 'string'){
    //         this.replyTo = thisReplyTo;
    //     }
    // }

    // setSubjectLine(thisSubjectLine){
    //     if (thisSubjectLine && typeof(thisSubjectLine) === 'string'){
    //         this.subjectLine = thisSubjectLine;
    //     }
    // }

    setMessageThread(thisThreadId) {
        if (thisThreadId && typeof(thisThreadId) === 'string'){
            this.messageThreadId = thisThreadId;
        }
    }

    addExternalReference(thisExtReference){
        if (thisExtReference && Array.isArray(thisExtReference) &&
    thisExtReference.length > 1){
            this.externalReferences.push(thisExtReference);
        }
    }

    removeRecipientTo(thisRecipient){
        var success = false;

        if (thisRecipient && typeof(thisRecipient) === 'string'){
            var foundIndex = this.mailToList.indexOf(thisRecipient.toLowerCase());

            if (foundIndex > 0){
                this.mailToList.splice(foundIndex,1);
                success = true;
            }
        }

        return success;
    }

    removeCCTo(thisCCRecipient){
        var success = false;

        if (thisCCRecipient && typeof(thisCCRecipient) === 'string'){
            var foundIndex = this.mailToList.indexOf(thisCCRecipient.toLowerCase());

            if (foundIndex > 0){
                this.ccList.splice(foundIndex,1);
                success = true;
            }
        }

        return success;
    }

    removeBCCTo(thisBCCRecipient){
        var success = false;

        if (thisBCCRecipient && typeof(thisBCCRecipient) === 'string'){
            var foundIndex = this.mailToList.indexOf(thisBCCRecipient.toLowerCase());

            if (foundIndex > 0){
                this.bccList.splice(foundIndex,1);
                success = true;
            }
        }

        return success;
    }

    getContentText(contentType = PlainText){
        if (this.messageContent && this.messageContent[contentType]){
            return this.messageContent[contentType]
        }
    }

    generateEmailMessage(){
        var formattedMessage = {};

        if (this.mailToList.length > 0){
            formattedMessage["mailToList"] = this.mailToList;
        }

        if (this.mailFrom) {
            formattedMessage["mailFrom"] = this.mailFrom;
        }

        if (this.ccList.length > 0) {
            formattedMessage["ccList"] = this.ccList;
        }

        if (this.replyTo.length > 0) {
            formattedMessage["replyTo"] = this.replyTo;
        }

        if (this.subjectLine.length > 0) {
            formattedMessage["subjectLine"] = this.subjectLine;
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

        if (this.messageThreadId){
            formattedMessage["thread_id"] = this.messageThreadId;
        }

        return formattedMessage;
    }

    importMessageEvent(messageEventObject){
        var isSuccess = false;

        if (messageEventObject && typeof(messageEventObject) === 'object' && 
        (messageEventObject.id && messageEventObject.pubkey && messageEventObject.content && messageEventObject.created_at != undefined &&
            messageEventObject.sig
        )){
            this.mailFrom = messageEventObject.pubkey;
            var messageEventContent = JSON.parse(messageEventObject.content);

            // Todo parse back into object
            if (messageEventContent.messageType && typeof(messageEventContent.messageType) === 'object'){
                var messageTypes = Object.keys(messageEventContent.messageType);

                for (var i = 0; i < messageTypes.length; i++){
                    this.messageContent[messageTypes[i]] = messageEventContent.messageType[messageTypes[i]] ? Buffer.from(messageEventContent.messageType[messageTypes[i]], 'base64').toString() : '';
                }
            }

            this.mailToList = (messageEventContent.mailToList && Array.isArray(messageEventContent.mailToList)) ? messageEventContent.mailToList : [];
            this.ccList = (messageEventContent.ccList && Array.isArray(messageEventContent.ccList)) ? messageEventContent.ccList : [];
            
            this.replyTo = messageEventContent.replyTo ? messageEventContent.replyTo : '';
            this.subjectLine = messageEventContent.subjectLine ? messageEventContent.subjectLine : '';

            this.externalReferences = messageEventContent["external_references"] ? messageEventContent["external_references"] : [];
            this.messageThreadId = messageEventContent["thread_id"] ? messageEventContent["thread_id"] : '';

            isSuccess = true;
        }
        return isSuccess;
    }

    generateBCCMessages(){
        var formattedBCCMessages = [];
        var formattedMessage = this.generateEmailMessage();

        for (var i = 0; i < this.bccList.length; i++){
            var thisFormattedBCCMessage = {};
            var thisBCCRecipient = this.bccList[i];

            thisFormattedBCCMessage["bccTo"] = thisBCCRecipient;
            thisFormattedBCCMessage["bcc_content"] = formattedMessage;

            formattedBCCMessages.push(thisFormattedBCCMessage);
        }

        return formattedBCCMessages;
    }
}

