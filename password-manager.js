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


    // Helper method to derive encryption and HMAC keys from master key
    async #deriveKeys(masterKey) {
      const hmacKey = await subtle.sign(
        "HMAC",
        masterKey,
        stringToBuffer("hmac-key")
      );
      
      const encKey = await subtle.sign(
        "HMAC",
        masterKey,
        stringToBuffer("enc-key")
      );
  
      const hmacImportedKey = await subtle.importKey(
        "raw",
        hmacKey,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
      );
  
      const encImportedKey = await subtle.importKey(
        "raw",
        encKey,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"]
      );
  
      return { hmacImportedKey, encImportedKey };
    }



};

module.exports = { Keychain }
