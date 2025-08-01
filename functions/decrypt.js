const crypto = require('crypto');

function sha256Hex(str) {
    return crypto.createHash('sha256').update(str).digest('hex');
}
function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 1)
      bytes.push(hex.charCodeAt(c));
    return new Uint8Array(bytes);
}
function b64UrlSafeDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return str;
}
function base64ToArrayBuffer(base64) {
    let binary = global.atob(base64);
    let len = binary.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

exports.handler = async function(event) {
  try {
    const { xdata, timestamp, key } = JSON.parse(event.body);
    if (!xdata || !timestamp || !key) {
      return { statusCode: 400, body: JSON.stringify({ error: 'xdata, timestamp & key required' }) };
    }

    const keyHex = sha256Hex(key).slice(0,32);
    const keyBytes = hexToBytes(keyHex);
    
    const ivHex  = sha256Hex(String(timestamp)).slice(0,16);
    const ivBytes  = hexToBytes(ivHex);

    // base64url → base64
    const safeXdata = b64UrlSafeDecode(xdata);
    const ctBuffer = base64ToArrayBuffer(safeXdata);

    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBytes, ivBytes);
    decipher.setAutoPadding(true);
    
    var plainText = decipher.update(ctBuffer, 'binary', 'utf8') + decipher.final('utf8');

    // pretty‐print JSON if applicable
    try {
      const obj = JSON.parse(plainText);
      plainText = JSON.stringify(obj, null, 2);
    } catch {}

    return {
      statusCode: 200,
      body: JSON.stringify({ plainText }),
    };
  } catch (err) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'decryption failed', detail: err.message }),
    };
  }
};
