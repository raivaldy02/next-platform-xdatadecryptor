const crypto = require('crypto');

exports.handler = async function(event) {
  try {
    const { plaintext, timestamp, key } = JSON.parse(event.body);
    if (!plaintext || !timestamp || !key) {
      return { statusCode: 400, body: JSON.stringify({ error: 'plaintext, timestamp & key required' }) };
    }

    // normalize JSON if possible
    let pt = plaintext;
    try { pt = JSON.stringify(JSON.parse(plaintext)); } catch (_) {}

    // SHA256 → hex → slice → to char-codes
    const sha256Hex = str => crypto.createHash('sha256').update(str).digest('hex');
    const hexToBytes = hex => Buffer.from(hex.split('').map(c => c.charCodeAt(0)));

    const keyHex = sha256Hex(key).slice(0,32);
    const ivHex  = sha256Hex(String(timestamp)).slice(0,16);
    const keyBytes = hexToBytes(keyHex);
    const ivBytes  = hexToBytes(ivHex);

    const cipher = crypto.createCipheriv('aes-128-cbc', keyBytes, ivBytes);
    let ct = Buffer.concat([cipher.update(Buffer.from(pt, 'utf8')), cipher.final()]);

    // base64url encode
    const b64    = ct.toString('base64');
    const xdata  = b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

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
