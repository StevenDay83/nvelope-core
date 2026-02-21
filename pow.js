function getTargetFromDifficulty(difficultyHashes) {
  var hashTarget = undefined;

  if (difficultyHashes > 0 && difficultyHashes <= 2**256){
    var targetNumber = 2**256 / difficultyHashes;

    if (targetNumber >= 2 ** 256){
      targetNumber = 2 ** 255;
    }

    hashTarget = targetNumber.toString(16);
  }

  return hashTarget;
}

function getDifficultyFromTarget(targetHash) {
    var difficulty;
    var targetHashInteger = parseInt(targetHash,16);
    targetHashInteger = (!isNaN(targetHashInteger) && targetHashInteger > 0) ? targetHashInteger : 1;

    if (targetHash){
        difficulty = 2**256 / parseInt(targetHash,16);

        difficulty = difficulty < 1 ? 0 : difficulty;
    }

    return difficulty;
}

function padPrefix64BitHash(hash){
  var hash64Bit = undefined;

  if (hash.length <= 64){
    hash64Bit = hash.padStart(64, '0');
  }

  return hash64Bit;
}

async function sha256(message) {
  // encode as UTF-8
  const msgBuffer = new TextEncoder('utf-8').encode(message);

  // hash the message
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

  // convert ArrayBuffer to Array
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  // convert bytes to hex string
  const hashHex = hashArray.map(b => ('00' + b.toString(16)).slice(-2)).join('');
  // console.log(hashHex);
  return hashHex;
}

function getTargetFromLeadingZeros(leadingZeroCount) {
    var target;

    if (leadingZeroCount == 256){
        target = '0';
    } else if (leadingZeroCount == 0) {
        target = 'f'.repeat(64);
    } else if (leadingZeroCount < 256 && leadingZeroCount > 0){
        var binaryChars = '1'.repeat(4 - (leadingZeroCount % 4));
        binaryChars = binaryChars == '' ? '0' : binaryChars;
        var hexChar = parseInt(binaryChars, 2).toString(16);

        var remainingCharacters = (hexChar == 'f' ? 63 : 64) - Math.ceil(leadingZeroCount / 4);

        target = hexChar == '0' ? '' : hexChar + 'f'.repeat(remainingCharacters);
    }

    return target;
}



module.exports.padPrefix64BitHash = padPrefix64BitHash;
module.exports.getTargetFromLeadingZeros = getTargetFromLeadingZeros;
module.exports.getDifficultyFromTarget = getDifficultyFromTarget;
module.exports.getTargetFromDifficulty = getTargetFromDifficulty;