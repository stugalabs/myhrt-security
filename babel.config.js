// Minimal Babel config so Jest can run the TypeScript test against the
// TypeScript source without a separate build step. Type-checking lives in the
// main MyHRT app repo; here Babel only strips types so the crypto round-trip
// test can execute in Node.
module.exports = {
  presets: [
    ['@babel/preset-env', { targets: { node: 'current' } }],
    '@babel/preset-typescript',
  ],
};
