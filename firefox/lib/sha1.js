const { Cc, Ci } = require("chrome");

function sha1(str) {
    var hasher = Cc["@mozilla.org/security/hash;1"].createInstance(Ci.nsICryptoHash);
    var byteArray = toByteArray(str);

    hasher.init(hasher.SHA1);
    hasher.update(byteArray, byteArray.length);

    var hash = hasher.finish(false);
    var hexString = [toHexString(hash.charCodeAt(i)) for (i in hash)].join("");

    return hexString;
}

function toByteArray(str) {
    var converter = Cc["@mozilla.org/intl/scriptableunicodeconverter"].createInstance(Ci.nsIScriptableUnicodeConverter);
    converter.charset = "UTF-8";
    return converter.convertToByteArray(str, {});
}

function toHexString(charCode) {
    return ("0" + charCode.toString(16)).slice(-2);
}

exports.sha1 = sha1;