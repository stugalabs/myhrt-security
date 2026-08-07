// Test mock. On device, the app uses expo-crypto's getRandomValues (a
// cryptographically secure RNG) to generate nonces and keys. In Node we back it with
// the platform WebCrypto CSPRNG, which is equivalent for the purpose of these
// tests. This mock affects tests only; the real expo-crypto module is used in
// the shipped app.
const { webcrypto } = require('node:crypto');

module.exports = {
  getRandomValues: (array) => webcrypto.getRandomValues(array),
};
