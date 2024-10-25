"use strict";

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;


class Keychain {

  constructor(masterKey, salt, kvs = {}) {
    this.data = {
      salt: salt,  // Salt is public
      kvs: kvs     // Store encrypted key-value pairs
    };
    this.secrets = {
      masterKey: masterKey  // Keep the master key private
    };
  }




};

module.exports = { Keychain }
