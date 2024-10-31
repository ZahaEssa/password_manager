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

  static async init(password) {
    if (!password || typeof password !== 'string') {
      throw new Error("Invalid password");
    }

    const salt = getRandomBytes(16);
    
    const pwKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      pwKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    return new Keychain(masterKey, salt);
  }

  


};

module.exports = { Keychain }
