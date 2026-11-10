const crypto = require('crypto');

function weak() {
  crypto.createHash('md5');
  crypto.createHash('sha1');
  crypto.createSign('RSA-SHA256');
}
