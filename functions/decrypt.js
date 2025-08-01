const crypto = require('crypto');

exports.handler = async function(event) {
  try {
    const { xdata, timestamp, key } = JSON.parse(event.body);
    if (!xdata || !timestamp || !key) {
      return { statusCode: 400, body: JSON.stringify({ error: 'xdata, timestamp & key required' }) };
    }

    const sha256Hex = str => crypto.createHash('sha256').update(str).digest('hex');
    const hexToBytes = hex => Buffer.from(hex.split('').map(c => c.charCodeAt(0)));

    const keyHex = sha256Hex(key).slice(0,32);
    const ivHex  = sha256Hex(String(timestamp)).slice(0,16);
    const keyBytes = hexToBytes(keyHex);
    const ivBytes  = hexToBytes(ivHex);

    // base64url → base64
    let b64 = xdata.replace(/-/g,'+').replace(/_/g,'/');
    while (b64.length % 4) b64 += '=';
    const ctBuf = Buffer.from(b64, 'base64');

    const decipher = crypto.createDecipheriv('aes-128-cbc', keyBytes, ivBytes);
    let pt = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
    let plaintext = pt.toString('utf8');

    // pretty‐print JSON if applicable
    try {
      const obj = JSON.parse(plaintext);
      plaintext = JSON.stringify(obj, null, 2);
    } catch {}

    return {
      statusCode: 200,
      body: JSON.stringify({ plaintext }),
    };
  } catch (err) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'decryption failed', detail: err.message }),
    };
  }
};
