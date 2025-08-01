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

function b64UrlSafeEncode(str) {
    return str.replace(/\+/g, '-').replace(/\//g, '_');
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    let bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
    }
    return global.btoa(binary);
}

exports.handler = async function(event) {
  try {
    const { plaintext, timestamp, key } = JSON.parse(event.body);
    if (!plaintext || !timestamp || !key) {
      return { statusCode: 400, body: JSON.stringify({ error: 'plaintext, timestamp & key required' }) };
    }

    // normalize JSON if possible
    let pt = plaintext;
    try { pt = JSON.stringify(JSON.parse(plaintext)); } catch (_) {}

    const keyHex = sha256Hex(key).slice(0,32);
    const keyBytes = hexToBytes(keyHex);
    
    const ivHex  = sha256Hex(String(timestamp)).slice(0,16);
    const ivBytes  = hexToBytes(ivHex);

    const ptBytes = hexToBytes(pt);

    const cipher = crypto.createCipheriv('aes-256-cbc', keyBytes, ivBytes);
    var cipherText = Buffer.concat([cipher.update(ptBytes), cipher.final()]);

    // base64url encode
    const cipherB64 = arrayBufferToBase64(cipherText);
    const xdata = b64UrlSafeEncode(cipherB64);

    return {
      statusCode: 200,
      body: JSON.stringify({ xdata }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'encryption failed', detail: err.message }),
    };
  }
};
