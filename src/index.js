const verifier = require('./verifier');
const adapters = require('./adapters');

module.exports = {
  ...verifier,
  ...adapters,
};
