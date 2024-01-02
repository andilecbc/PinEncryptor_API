const express = require('express');
const forge = require('node-forge');
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const VERSION = "js-v1.0.1";
const ERRORS = {
    ERR_SUCCESS: {
        code: 0,
        description: "Success"
    },
    ERR_PIN_TOO_SHORT: {
        code: 101,
        description: "The pin is too short"
    },
    ERR_PIN_CONTAINS_LETTERS: {
        code: 102,
        description: "The pin can't contains letters"
    },
    ERR_PIN_TOO_MANY_DUPLICATES: {
        code: 103,
        description: "The pin has too many duplicates"
    },
    ERR_PIN_IS_SEQUENCE: {
        code: 104,
        description: "The pin is a sequence"
    },
    ERR_PIN_IS_PATTERN: {
        code: 105,
        description: "The pin is a pattern"
    },
    ERR_PIN_IS_PINPAD_PATTERN: {
        code: 106,
        description: "The pin is a pattern on the pin pad"
    },
    ERR_PIN_IS_BIRTHDATE: {
        code: 107,
        description: "The pin is likely a birthdate"
    },
    ERR_PIN_USED_OFTEN: {
        code: 108,
        description: "The pin is used too often, to be safe"
    }
}

var uid = "123aaa33198dc8f3s4k77dsc78";
var publicKey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUEzbm1YdUxRN0RGa2JlZC8rcGdBKwpqUGNPZ2pYaGxEaXVYRFVZNThBVGU0SDF3ZWxJalVBTTNyZkZsd3RVUVhXQ1NTeGtNb0NPK016V1pTblpOdFYxCm9BZnZ4a2t6MFErQkpUSENCTHpzMnpvUzlrMXM3cVZEbUJVdnV2VmVrZUZBUkkzV2lOeE52RTdWYTJWU1dqRjcKZ3hYTDBTVTFKUk8xTFJSb0N4WTI4dFFFcTg1bXVJUmpFQXNjLzRkL0hjY1NWUkRTaDFuQmNsMVVjZWxQVW9HZgpObjlCODBBZXJlMnBJYWRiQXVBSEZBZWc1WnUyb2haOGNXVHhKUUVJQlMwZFlyWWN6ZTZXdVBiRk9OYWpacXN6CnFqTWhLblV1bTV4Q1U2YXZRZUxJc0JoUlNkVEpBN09IVFJwemgvSlBuYzJUYXpxYlFVWVR0R1Iwb1BHRmQwaEIKSjZpMjAwdVgxSWcybURQZGRGd1EzZk1nYWxUSVcyeTNDMEhjR0JMbVQrUjVGZkh0c0dpanVTdG5zZTU3NFdSQQpUaDNFaURxSk03TXY4eWdVQUNSZWxaKzNlZEJoTnBWNFEwZS95aHp5ZGRvMFRQMmFDaExPb0dlQ0xEU3IxcTFRCnFJZnNjSWp2VGwvMVdoYVU2aXlYc0t3Yjl5SkJiNGpuQjBvVm5YS25SVzNRd1B1d1QzNG9oc2REZkV1dmwxWVMKU09CSDNRWHcxTWp1TjFXL251NkFtN1pobFdPM3ArNFlNMDdnVGFlcjNwTFljK1JnbnZ3V3IvL3IxenRSakhwUgo2UlZYS0ZDRW5SUWQzSUtDY01WM3RjQzFlU1RuOWh5Z0kybStoTC9abWpoeDIvdW04MXlYdWJnSERIUmNCZ3lPCnZpdVh4ZzI5VFZSSFZvM0FNZDArK2RFQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=";
var encryptor = new PinEncryptor(uid, publicKey);

function PinEncryptor(uid, publicKey) {
  this.uid = uid;
  this.publicKey = publicKey;

  this.version = function () {
    return VERSION
  };
  this.encrypt = function (pin) {
    var res = isWeak(pin);
    if (res != null) {
      return {
        version: VERSION,
        error: res
      }
    }

    var pinBlock = encodePin(pin);
    var aesKey = forge.random.getBytesSync(32);
    var aesIv = forge.random.getBytesSync(12);

    const cipher = forge.cipher.createCipher("AES-GCM", aesKey);
    cipher.start({ iv: aesIv });
    cipher.update(forge.util.createBuffer(pinBlock));
    cipher.finish();

    var encPinBlockWithoutIvAndAuthTag = cipher.output.bytes();
    var authTag = cipher.mode.tag.bytes();
    var encodedMessage = forge.util.encode64(encPinBlockWithoutIvAndAuthTag);
    var details = String.fromCharCode(aesKey.length) + aesKey + String.fromCharCode(aesIv.length) + aesIv + String.fromCharCode(authTag.length) + authTag;
    var publicKey = forge.util.decode64(this.publicKey);
    var rsaPublicKey = forge.pki.publicKeyFromPem(publicKey);
    var encryptedDetails = rsaPublicKey.encrypt(details, 'RSA-OAEP', {
      md: forge.md.sha256.create()
    });
    var encodedDetails = forge.util.encode64(encryptedDetails);

    return {
      version: VERSION,
      error: ERRORS.ERR_SUCCESS,
      uid: this.uid,
      encryptedPin: encodedMessage,
      sessionKey: encodedDetails
    }
  };

  // isWeak validates the pin value
  var isWeak = function (pin) {
    var funcsArr = [];
    funcsArr.push(function isTooShort(value) {
      if (value.length < 4) {
        return ERRORS.ERR_PIN_TOO_SHORT
      }
      return null
    });
    funcsArr.push(function isNumber(value) {
      if (/^\d*$/.test(value) == false) {
        return ERRORS.ERR_PIN_CONTAINS_LETTERS
      }
      return null
    });
    funcsArr.push(function hasDuplicates(value) {
      var digitsToCompare = [value[0], value[1]];
      for (var i = 0; i < value.length; i++) {
        var count = 0;
        for (var j = 0; j < value.length; j++) {
          if (value[j] == digitsToCompare[i]) {
            count++;
          }
        }
        if (count > 2) {
          return ERRORS.ERR_PIN_TOO_MANY_DUPLICATES
        }
      }
      return null
    });
    funcsArr.push(function isSequence(value) {
      var inner_isSequence = function (value) {
        var differences = [];
        for (i = 0; i < value.length - 1; i++) {
          var difference = value[i + 1] - value[i];
          differences.push(difference);
        }
        for (i = 0; i < differences.length - 1; i++) {
          if (differences[i] != differences[i + 1]) {
            return false;
          }
        }
        return true
      }
      var digits = [];
      for (var i = 0; i < value.length; i++) {
        digits.push(parseInt(value[i]));
      }
      if (inner_isSequence(digits) == true) {
        return ERRORS.ERR_PIN_IS_SEQUENCE
      }
      for (i = 0; i < digits.length; i++) {
        if (digits[i] == 0) {
          digits[i] = 10;
        }
      }
      if (inner_isSequence(digits) == true) {
        return ERRORS.ERR_PIN_IS_SEQUENCE
      }
      return null
    });
    funcsArr.push(function isPatternABAB(value) {
      var parts = [];
      for (var i = 0; i < value.length; i += 2) {
        parts.push(value.substring(i, i + 2));
      }
      for (var i = 0; i < parts.length; i++) {
        if (parts[0] != parts[i]) {
          return null
        }
      }
      return ERRORS.ERR_PIN_IS_PATTERN
    });
    funcsArr.push(function isPatternAABB(value) {
      if (value[0] == value[1] && value[2] == value[3]) {
        return ERRORS.ERR_PIN_IS_PATTERN
      }
      return null
    });
    funcsArr.push(function isPinPadPattern(value) {
      if (value.includes('1') && value.includes('3') && value.includes('7') && value.includes('9')) {
        return ERRORS.ERR_PIN_IS_PINPAD_PATTERN
      }
      if (value == "2580" || value == "0852") {
        return ERRORS.ERR_PIN_IS_PINPAD_PATTERN
      }
      return null
    });
    funcsArr.push(function isLikelyBirthdate(value) {
      var upper = new Date().getFullYear() - 25;
      var lower = new Date().getFullYear() - 60;
      var pin = parseInt(value);
      if (pin >= lower && pin <= upper) {
        return ERRORS.ERR_PIN_IS_BIRTHDATE
      }
      return null
    });
    funcsArr.push(function isTopUsedPin(value) {
      if (value == "1004" || value == "2001") {
        return ERRORS.ERR_PIN_USED_OFTEN
      }
      return null
    });
    for (var i = 0; i < funcsArr.length; i++) {
      var res = funcsArr[i](pin);
      if (res != null) {
        return res
      }
    }
    return null
  }
  // Encode PIN value and return a PIN block, explained in "PIN block encode.docx" file.
  var encodePin = function (pin) {
    var encodedPinArray = [];
    var hasDuplicates = true;

    while (hasDuplicates == true) {
      encodedPinArray = genRanHex(50);
      hasDuplicates = hasRandomPositionsDuplicates(encodedPinArray, pin.length);
    }
    // Changing the first element in map with the PIN length value.
    encodedPinArray[0] = pin.length.toString();
    // Changing the elements in map with the PIN digits indicated in "random generated positions block (explained in "PIN block encode.docx" file)".
    for (var i = 0; i < pin.length; i++) {
      var position = parseInt(encodedPinArray[i + 1], 16);
      encodedPinArray[1 + pin.length + position] = pin[i];
    }
    // Create a string from map and convert values to upper case.
    return encodedPinArray.join("").toUpperCase();
  }
  // Verify if PIN digit positions are not duplicated, explained in "PIN block encode.docx" file.
  var hasRandomPositionsDuplicates = function (array, pinLength) {
    var valuesSoFar = [];
    for (var i = 1; i <= pinLength; ++i) {
      var value = array[i];
      if (valuesSoFar.indexOf(value) !== -1) {
        return true;
      }
      valuesSoFar.push(value);
    }
    return false;
  }
  // Generates a map of randomly generated HEX values
  var genRanHex = size => [...Array(size)].map(() => Math.floor(Math.random() * 16).toString(16));
};

app.listen(PORT, function () {
  console.log("Server Listening on PORT:", PORT);
});

app.get('/encryptPin/:pin', function (request, response) {
  var oResponse = encryptor.encrypt(request.params.pin);
  response.send(oResponse);
});

app.post('/encryptPin/:pin', function (request, response) {
  var oResponse = encryptor.encrypt(request.params.pin);
  response.send(oResponse);
});