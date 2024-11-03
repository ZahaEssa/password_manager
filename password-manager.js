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

  
  static async load(password, repr, trustedDataCheck) {
    if (!password || typeof password !== 'string') {
      throw new Error("Incorrect password");
    }

    let data;
    try {
      data = JSON.parse(repr);
    } catch (e) {
      throw new Error("Incorrect password");
    }

    if (!data.salt || !data.kvs) {
      throw new Error("Incorrect password");
    }

    try {
      // Verify the checksum first if provided
      if (trustedDataCheck !== undefined) {
        const checksum = await subtle.digest("SHA-256", stringToBuffer(repr));
        if (encodeBuffer(checksum) !== trustedDataCheck) {
          throw new Error("Invalid checksum - possible tampering detected");
        }
      }

      // Import the password as a key
      const pwKey = await subtle.importKey(
        "raw",
        stringToBuffer(password),
        "PBKDF2",
        false,
        ["deriveKey"]
      );

      // Decode and process the salt
      const saltArray = decodeBuffer(data.salt);
      const saltBuffer = saltArray.buffer.slice(
        saltArray.byteOffset,
        saltArray.byteOffset + saltArray.byteLength
      );

      // Derive the master key
      const masterKey = await subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: saltBuffer,
          iterations: PBKDF2_ITERATIONS,
          hash: "SHA-256"
        },
        pwKey,
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["sign"]
      );

      // Create a test instance to verify the key works
      const instance = new Keychain(masterKey, saltBuffer);
      
      // Verify the master key by attempting to derive keys
      await instance.#deriveKeys(masterKey);

      // Attempt to decrypt at least one value if any exist
      // This ensures the password is correct
      const entries = Object.entries(data.kvs);
      if (entries.length > 0) {
        const [key, value] = entries[0];
        const encrypted = decodeBuffer(value);
        const iv = encrypted.slice(0, 12);
        const ciphertext = encrypted.slice(12);
        
        const { encImportedKey } = await instance.#deriveKeys(masterKey);
        
        try {
          await subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            encImportedKey,
            ciphertext
          );
        } catch (e) {
          throw new Error("Incorrect password");
        }
      }

      // If we get here, the password was correct
      // Now populate the kvs data
      for (const [key, value] of Object.entries(data.kvs)) {
        const decodedKey = typeof key === 'string' ? key : encodeBuffer(key);
        const decodedValue = typeof value === 'string' ? value : encodeBuffer(value);
        instance.data.kvs[decodedKey] = decodedValue;
      }

      return instance;
      
    } catch (error) {
      // Any error during the process means the password was incorrect
      // or the data was tampered with
      throw new Error("Incorrect password");
    }
  }





  

};

module.exports = { Keychain }
