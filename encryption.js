const { generateKeyPairSync, publicEncrypt, privateDecrypt, createPublicKey } = require('crypto');
const forge = require('node-forge');
const { monitorEventLoopDelay } = require('perf_hooks');

const DEFAULT_CHUNK = 214;

function encryptData(textData, publicKeyPEM){
    var encryptedDataBase64 = [];
    
    if (textData && typeof(textData) === 'string' && 
publicKeyPEM && typeof(publicKeyPEM) === 'string'){
        if (textData.length > DEFAULT_CHUNK){
            var numberOfChunks = Math.floor(textData.length / DEFAULT_CHUNK);
            var leftoverBytes = textData.length % DEFAULT_CHUNK;

            for (var i = 0; i < numberOfChunks; i++){
                var textChunk = textData.substring(i * DEFAULT_CHUNK, (i * DEFAULT_CHUNK) + DEFAULT_CHUNK);
                var encryptOut = publicEncrypt(publicKeyPEM, textChunk);

                encryptedDataBase64.push(encryptOut.toString('base64'));
            }

            encryptedDataBase64.push(publicEncrypt(publicKeyPEM, textData.substring(textData.length - leftoverBytes, textData.length)).toString('base64'));
        } else {
            var encryptOut = publicEncrypt(publicKeyPEM, textData);
            encryptedDataBase64.push(encryptOut.toString('base64'));
        }
    }

    return encryptedDataBase64;
}

function decryptData(encryptedDataBase64Array, privateKeyPEM){
    // Steps
    // Step 1 - Validate data, PrivKeyPEM and KeySize (2048+)
    // Step 2 - Convert encryptedData to binary
    // Step 3 - break binary into chunks based on key size
    // Step 4 - Decrypt each one
    // Step 5 - Combine
    try {
        var decryptedText = '';
    
        if (encryptedDataBase64Array && Array.isArray(encryptedDataBase64Array) && 
        privateKeyPEM && typeof(privateKeyPEM) === 'string'){
    
            for (var i = 0; i < encryptedDataBase64Array.length; i++){
                var thisEncryptedBase64Text = encryptedDataBase64Array[i];
                var encryptedBinary = Buffer.from(thisEncryptedBase64Text, 'base64');
                
                var thisDecryptedText = privateDecrypt(privateKeyPEM, encryptedBinary);
    
                // console.log("Decrypt ", i, " = ", thisDecryptedText.toString());
                decryptedText += thisDecryptedText.toString();
            }
        }
    } catch (e) {
        return undefined;
    }

    return decryptedText;
}

function generateMailKeyPair(keySize = 2048){
    var keyPair = {
        public:'',
        private:''
    };

    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: keySize,
        publicKeyEncoding: {
            type: 'spki',
            format: 'der'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    keyPair.public = publicKey.toString('base64');
    keyPair.private = privateKey;

    return keyPair;
}

function Der64ToPemPublic(DerB64String){
    var PemPublicKey;

    try {
        if (DerB64String && typeof(DerB64String) === 'string') {
            var derPublicKey = Buffer.from(DerB64String, 'base64');
    
            var derPublicKeyObj = createPublicKey({
                key:derPublicKey,
                format:'der',
                type:'spki'
            });
    
            PemPublicKey = derPublicKeyObj.export({
                format:'pem',
                type:'spki'
            });
        }
    } catch (e){
        console.error(e);
    }

    return PemPublicKey;
}

module.exports.encryptData = encryptData;
module.exports.decryptData = decryptData;
module.exports.generateMailKeyPair = generateMailKeyPair;
module.exports.Der64ToPemPublic = Der64ToPemPublic;