// Jest mock: react-native-quick-crypto implements Node's crypto API on top of
// native OpenSSL, so in tests we substitute Node's own crypto: identical
// createCipheriv/createDecipheriv/getAuthTag/setAuthTag semantics. This means
// test/aesGcm.test.ts exercises the REAL src/aesGcm.ts code path (the
// concat/split-tag logic and wire format), with only the engine swapped.
const { createCipheriv, createDecipheriv, randomBytes } = require('node:crypto');

module.exports = { createCipheriv, createDecipheriv, randomBytes, Buffer };
