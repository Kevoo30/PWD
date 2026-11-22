"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

// Every password is padded to the same fixed size before encryption so that
// ciphertext length reveals nothing. A password of up to 64 characters is at
// most 64 * 4 UTF-8 bytes, plus a 2-byte length prefix.
const PADDED_SIZE = 2 + MAX_PASSWORD_LENGTH * 4;
const IV_LENGTH = 12;             // 96-bit IV, the recommended size for AES-GCM
const SALT_LENGTH = 16;           // 128-bit salt

// Domain-separation labels used to derive the two sub-keys from the master key
const HMAC_KEY_LABEL = "domain-name-hmac-key";
const AES_KEY_LABEL = "password-aes-gcm-key";

// Plaintext/AAD for the password-correctness check value
const CANARY_PLAINTEXT = "keychain-password-check";
const CANARY_AAD = "keychain-canary";

/********* Helpers ********/

function concatBuffers(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// Pads a string into a fixed-size buffer: [2-byte length][utf8 bytes][zeros]
function padValue(value) {
  const bytes = stringToBuffer(value);
  if (value.length > MAX_PASSWORD_LENGTH || bytes.length > PADDED_SIZE - 2) {
    throw "Value is too long";
  }
  const out = new Uint8Array(PADDED_SIZE);
  out[0] = (bytes.length >> 8) & 0xff;
  out[1] = bytes.length & 0xff;
  out.set(bytes, 2);
  return out;
}

function unpadValue(buf) {
  const bytes = new Uint8Array(buf);
  const len = (bytes[0] << 8) | bytes[1];
  return bufferToString(bytes.slice(2, 2 + len));
}

// AES-GCM encrypt; returns Base64 of (iv || ciphertext+tag). `aad` is bound to
// the ciphertext, so decryption fails if the record is moved under another key.
async function encryptRecord(aesKey, plaintext, aad) {
  const iv = getRandomBytes(IV_LENGTH);
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(aad) },
    aesKey,
    plaintext
  );
  return encodeBuffer(concatBuffers(iv, new Uint8Array(ct)));
}

async function decryptRecord(aesKey, record, aad) {
  const raw = new Uint8Array(decodeBuffer(record));
  const iv = raw.slice(0, IV_LENGTH);
  const ct = raw.slice(IV_LENGTH);
  return new Uint8Array(await subtle.decrypt(
    { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(aad) },
    aesKey,
    ct
  ));
}

// Derive the master key from the password with PBKDF2 (called exactly once),
// then derive the HMAC and AES sub-keys by evaluating HMAC at two labels.
async function deriveKeys(password, salt) {
  const rawKey = await subtle.importKey(
    "raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
  const masterKey = await subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    rawKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"]
  );
  const hmacBits = await subtle.sign("HMAC", masterKey, stringToBuffer(HMAC_KEY_LABEL));
  const aesBits = await subtle.sign("HMAC", masterKey, stringToBuffer(AES_KEY_LABEL));
  const hmacKey = await subtle.importKey(
    "raw", hmacBits, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const aesKey = await subtle.importKey(
    "raw", aesBits, "AES-GCM", false, ["encrypt", "decrypt"]);
  return { hmacKey, aesKey };
}

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(salt, canary, kvs, hmacKey, aesKey) {
    this.data = {
      // Public: safe for an adversary to see
      salt: salt,       // Base64 PBKDF2 salt
      canary: canary,   // encrypted constant, used to check the password on load
      kvs: kvs          // HMAC(domain) -> AES-GCM(padded password)
    };
    this.secrets = {
      // Private: never serialized
      hmacKey: hmacKey,
      aesKey: aesKey
    };
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    const salt = getRandomBytes(SALT_LENGTH);
    const { hmacKey, aesKey } = await deriveKeys(password, salt);
    const canary = await encryptRecord(
      aesKey, stringToBuffer(CANARY_PLAINTEXT), CANARY_AAD);
    return new Keychain(encodeBuffer(salt), canary, {}, hmacKey, aesKey);
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    // Rollback defense: compare against the SHA-256 from trusted storage
    if (trustedDataCheck !== undefined) {
      const hash = encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)));
      if (hash !== trustedDataCheck) {
        throw "Integrity check failed: the keychain may have been tampered with or rolled back";
      }
    }

    const parsed = JSON.parse(repr);
    const salt = decodeBuffer(parsed.salt);
    const { hmacKey, aesKey } = await deriveKeys(password, salt);

    // Wrong password -> wrong AES key -> the canary fails to authenticate
    try {
      const plain = await decryptRecord(aesKey, parsed.canary, CANARY_AAD);
      if (bufferToString(plain) !== CANARY_PLAINTEXT) throw "bad canary";
    } catch (e) {
      throw "Invalid password or corrupted keychain";
    }

    return new Keychain(parsed.salt, parsed.canary, parsed.kvs, hmacKey, aesKey);
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    const repr = JSON.stringify(this.data);
    const hash = encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)));
    return [repr, hash];
  };

  // Deterministic lookup key for a domain: Base64(HMAC(hmacKey, name))
  async _lookupKey(name) {
    const mac = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    return encodeBuffer(mac);
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    const key = await this._lookupKey(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, key)) return null;
    try {
      // The lookup key is the AAD, so a record swapped under another key fails here
      const plain = await decryptRecord(this.secrets.aesKey, this.data.kvs[key], key);
      return unpadValue(plain);
    } catch (e) {
      throw "Tampering detected: record failed authentication";
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    const key = await this._lookupKey(name);
    this.data.kvs[key] = await encryptRecord(this.secrets.aesKey, padValue(value), key);
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    const key = await this._lookupKey(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, key)) return false;
    delete this.data.kvs[key];
    return true;
  };
};

module.exports = { Keychain }
