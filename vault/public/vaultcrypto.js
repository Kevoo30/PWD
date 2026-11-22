"use strict";

/**
 * Client-side crypto for the vault. Same design as password-manager.js in the
 * project root:
 *
 *   master password --PBKDF2-SHA256--> master key
 *   master key --HMAC("vault-aes-gcm-key")--> AES-GCM key    (encrypts items)
 *   master key --HMAC("vault-auth-key")-----> auth key       (proves identity to the server)
 *
 * The AES key never leaves the browser. The server only ever sees the auth key,
 * and cannot go from it back to the AES key.
 *
 * Works in the browser (window.VaultCrypto) and in Node 20+ (module.exports).
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory(globalThis);
  else root.VaultCrypto = factory(root);
})(typeof self !== "undefined" ? self : this, function (g) {
  const subtle = g.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const DEFAULT_ITERATIONS = 600000;
  const IV_LENGTH = 12;
  const SALT_LENGTH = 16;
  const PAD_BUCKET = 256; // plaintext is padded to a multiple of this, to hide exact lengths

  const AES_LABEL = "vault-aes-gcm-key";
  const AUTH_LABEL = "vault-auth-key";

  /* ---- Base64 helpers (work in browser and Node) ---- */
  function toB64(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return g.btoa(s);
  }
  function fromB64(b64) {
    const s = g.atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  const randomBytes = (n) => g.crypto.getRandomValues(new Uint8Array(n));
  const newSalt = () => toB64(randomBytes(SALT_LENGTH));

  function uuid() {
    if (g.crypto.randomUUID) return g.crypto.randomUUID();
    const b = randomBytes(16);
    b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
    const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  /**
   * Derive the two sub-keys. `email` is mixed into the PBKDF2 salt so that two
   * users with the same password and (impossibly) the same random salt still differ.
   * Returns { aesKey: CryptoKey, authKey: string (Base64) }
   */
  async function deriveKeys(password, email, saltB64, iterations) {
    const salt = new Uint8Array([...fromB64(saltB64), ...enc.encode(email.trim().toLowerCase())]);
    const raw = await subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    const master = await subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: iterations || DEFAULT_ITERATIONS, hash: "SHA-256" },
      raw,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"]
    );
    const aesBits = await subtle.sign("HMAC", master, enc.encode(AES_LABEL));
    const authBits = await subtle.sign("HMAC", master, enc.encode(AUTH_LABEL));
    const aesKey = await subtle.importKey("raw", aesBits, "AES-GCM", false, ["encrypt", "decrypt"]);
    return { aesKey, authKey: toB64(authBits) };
  }

  /** Pad JSON text with trailing spaces (JSON.parse ignores them). */
  function pad(text) {
    const bytes = enc.encode(text);
    const total = Math.ceil((bytes.length + 1) / PAD_BUCKET) * PAD_BUCKET;
    const out = new Uint8Array(total).fill(0x20);
    out.set(bytes, 0);
    return out;
  }

  /** Encrypt an item object. The item's id is bound to the ciphertext as AAD. */
  async function encryptItem(aesKey, id, obj) {
    const iv = randomBytes(IV_LENGTH);
    const ct = new Uint8Array(await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(id) }, aesKey, pad(JSON.stringify(obj))));
    const out = new Uint8Array(iv.length + ct.length);
    out.set(iv, 0); out.set(ct, iv.length);
    return toB64(out);
  }

  /** Decrypt an item. Throws if the blob was modified or belongs to another id. */
  async function decryptItem(aesKey, id, blobB64) {
    const raw = fromB64(blobB64);
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv: raw.slice(0, IV_LENGTH), additionalData: enc.encode(id) }, aesKey, raw.slice(IV_LENGTH));
    return JSON.parse(dec.decode(pt));
  }

  /* ---- Password generator (uniform, no modulo bias) ---- */
  function randomInt(max) {
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    do { g.crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % max;
  }

  const SETS = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.<>?",
  };
  const AMBIGUOUS = /[O0oIl1|]/g;

  function generatePassword(opts) {
    const o = Object.assign({ length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: false }, opts);
    const pools = ["lower", "upper", "digits", "symbols"]
      .filter((k) => o[k])
      .map((k) => (o.avoidAmbiguous ? SETS[k].replace(AMBIGUOUS, "") : SETS[k]));
    if (!pools.length) return "";
    const length = Math.max(pools.length, Math.min(128, o.length | 0));
    const all = pools.join("");
    const chars = pools.map((p) => p[randomInt(p.length)]); // at least one of each chosen set
    while (chars.length < length) chars.push(all[randomInt(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) { // Fisher-Yates
      const j = randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
  }

  /* ---- Strength estimate (0-4), a rough entropy heuristic, not a guarantee ---- */
  const COMMON = ["password", "123456", "qwerty", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "abc123", "football", "login"];

  function passwordStrength(pw) {
    if (!pw) return { score: 0, label: "", bits: 0 };
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
    let bits = pw.length * Math.log2(Math.max(pool, 2));
    const unique = new Set(pw).size;
    if (unique < pw.length / 2) bits *= 0.6;            // lots of repeats
    if (/(.)\1{2,}/.test(pw)) bits -= 8;
    if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf|zxcv)/i.test(pw)) bits -= 12;
    const low = pw.toLowerCase();
    if (COMMON.some((c) => low.includes(c))) bits = Math.min(bits, 28);
    bits = Math.max(0, bits);
    const score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    return { score, label: ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score], bits: Math.round(bits) };
  }

  return {
    DEFAULT_ITERATIONS, toB64, fromB64, newSalt, uuid,
    deriveKeys, encryptItem, decryptItem,
    generatePassword, passwordStrength,
  };
});
