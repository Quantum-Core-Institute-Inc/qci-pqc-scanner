const { createHash, generateKeyPairSync, createCipheriv } = require("crypto");
createHash("sha256");
generateKeyPairSync("rsa", { modulusLength: 2048 });
createCipheriv("aes-128-cbc", Buffer.alloc(16), Buffer.alloc(16));
