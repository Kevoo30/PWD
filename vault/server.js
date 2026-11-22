"use strict";

/**
 * Zero-knowledge vault server.
 *
 * The server stores ONLY ciphertext. Every vault item is encrypted in the
 * browser with a key derived from the master password, which never leaves the
 * browser. The server also never sees the master password: the browser derives
 * a separate "auth key" from it and sends that to log in.
 *
 * No third-party dependencies. Needs Node 22.5+ for the built-in node:sqlite.
 */

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const PUBLIC_DIR = path.join(__dirname, "public");
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;       // 12 hours
const MAX_BODY_BYTES = 256 * 1024;
const MAX_BLOB_CHARS = 64 * 1024;
const MAX_ITEMS_PER_USER = 5000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILS = 8;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}$/;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json; charset=utf-8",
};

/* ---------------------------- Database ---------------------------- */

function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      email        TEXT NOT NULL UNIQUE,
      kdf_salt     TEXT NOT NULL,      -- public, used by the browser for PBKDF2
      kdf_iters    INTEGER NOT NULL,
      auth_salt    TEXT NOT NULL,      -- server-side salt for hashing the auth key
      auth_hash    TEXT NOT NULL,      -- scrypt(authKey, auth_salt)
      created_at   INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS items (
      id           TEXT PRIMARY KEY,   -- client-generated UUID, also the AES-GCM AAD
      user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      blob         TEXT NOT NULL,      -- Base64(iv || AES-GCM ciphertext). Opaque to the server.
      created_at   INTEGER NOT NULL,
      updated_at   INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS items_user ON items(user_id);

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash   TEXT PRIMARY KEY,   -- sha256(token); the token itself is never stored
      user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at   INTEGER NOT NULL
    );
  `);
  return db;
}

/* ----------------------------- Helpers ---------------------------- */

const sha256hex = (s) => crypto.createHash("sha256").update(s).digest("hex");
const scryptHex = (secret, salt) =>
  crypto.scryptSync(secret, Buffer.from(salt, "base64"), 32, { N: 16384, r: 8, p: 1 }).toString("hex");

function safeEqualHex(a, b) {
  const ba = Buffer.from(a, "hex"), bb = Buffer.from(b, "hex");
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function send(res, status, body, headers = {}) {
  const payload = typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers,
  });
  res.end(payload);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reject(new HttpError(413, "Request too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { reject(new HttpError(400, "Invalid JSON")); }
    });
    req.on("error", reject);
  });
}

const isB64 = (s, min, max) => typeof s === "string" && s.length >= min && s.length <= max && B64_RE.test(s);

/* ------------------------------ App ------------------------------- */

function createApp({ dbFile = path.join(__dirname, "vault.db"), serverSecret } = {}) {
  const db = openDb(dbFile);
  // Used to return a stable, fake KDF salt for unknown emails, so the prelogin
  // endpoint does not reveal which emails are registered.
  const secret = serverSecret || crypto.randomBytes(32);

  const q = {
    userByEmail: db.prepare("SELECT * FROM users WHERE email = ?"),
    insertUser: db.prepare(
      "INSERT INTO users (email, kdf_salt, kdf_iters, auth_salt, auth_hash, created_at) VALUES (?,?,?,?,?,?)"),
    insertSession: db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)"),
    sessionUser: db.prepare("SELECT user_id, expires_at FROM sessions WHERE token_hash = ?"),
    deleteSession: db.prepare("DELETE FROM sessions WHERE token_hash = ?"),
    purgeSessions: db.prepare("DELETE FROM sessions WHERE expires_at < ?"),
    listItems: db.prepare("SELECT id, blob, created_at, updated_at FROM items WHERE user_id = ? ORDER BY created_at"),
    itemOwner: db.prepare("SELECT user_id FROM items WHERE id = ?"),
    countItems: db.prepare("SELECT COUNT(*) AS n FROM items WHERE user_id = ?"),
    insertItem: db.prepare("INSERT INTO items (id, user_id, blob, created_at, updated_at) VALUES (?,?,?,?,?)"),
    updateItem: db.prepare("UPDATE items SET blob = ?, updated_at = ? WHERE id = ? AND user_id = ?"),
    deleteItem: db.prepare("DELETE FROM items WHERE id = ? AND user_id = ?"),
  };

  // Failed-login tracking, in memory: key -> [timestamps]
  const fails = new Map();
  function tooManyFails(key) {
    const now = Date.now();
    const arr = (fails.get(key) || []).filter((t) => now - t < LOGIN_WINDOW_MS);
    fails.set(key, arr);
    return arr.length >= LOGIN_MAX_FAILS;
  }
  function noteFail(key) { (fails.get(key) || fails.set(key, []).get(key)).push(Date.now()); }

  function fakeKdf(email) {
    const salt = crypto.createHmac("sha256", secret).update("salt:" + email).digest().subarray(0, 16);
    return { salt: salt.toString("base64"), iterations: 600000 };
  }

  function newSession(userId) {
    const token = crypto.randomBytes(32).toString("base64url");
    q.purgeSessions.run(Date.now());
    q.insertSession.run(sha256hex(token), userId, Date.now() + SESSION_TTL_MS);
    return token;
  }

  function authenticate(req) {
    const h = req.headers.authorization || "";
    const m = /^Bearer ([A-Za-z0-9_-]{20,100})$/.exec(h);
    if (!m) throw new HttpError(401, "Not signed in");
    const row = q.sessionUser.get(sha256hex(m[1]));
    if (!row || row.expires_at < Date.now()) throw new HttpError(401, "Session expired");
    return { userId: row.user_id, tokenHash: sha256hex(m[1]) };
  }

  /* ----------------------------- Routes ---------------------------- */

  async function api(req, res, url) {
    const route = req.method + " " + url.pathname;

    if (route === "GET /api/prelogin") {
      const email = (url.searchParams.get("email") || "").trim().toLowerCase();
      if (!EMAIL_RE.test(email)) throw new HttpError(400, "Enter a valid email address");
      const u = q.userByEmail.get(email);
      const out = u ? { salt: u.kdf_salt, iterations: u.kdf_iters } : fakeKdf(email);
      return send(res, 200, out);
    }

    if (route === "POST /api/register") {
      const b = await readJson(req);
      const email = String(b.email || "").trim().toLowerCase();
      if (!EMAIL_RE.test(email)) throw new HttpError(400, "Enter a valid email address");
      if (!isB64(b.salt, 16, 64)) throw new HttpError(400, "Bad salt");
      if (!isB64(b.authKey, 40, 64)) throw new HttpError(400, "Bad auth key");
      const iters = Number(b.iterations);
      if (!Number.isInteger(iters) || iters < 100000 || iters > 5000000) throw new HttpError(400, "Bad iteration count");
      if (q.userByEmail.get(email)) throw new HttpError(409, "An account with that email already exists");

      const authSalt = crypto.randomBytes(16).toString("base64");
      const info = q.insertUser.run(email, b.salt, iters, authSalt, scryptHex(b.authKey, authSalt), Date.now());
      return send(res, 201, { token: newSession(Number(info.lastInsertRowid)) });
    }

    if (route === "POST /api/login") {
      const b = await readJson(req);
      const email = String(b.email || "").trim().toLowerCase();
      const key = email + "|" + (req.socket.remoteAddress || "");
      if (tooManyFails(key)) throw new HttpError(429, "Too many failed attempts. Try again in a few minutes.");
      if (!EMAIL_RE.test(email) || !isB64(b.authKey, 40, 64)) throw new HttpError(400, "Bad request");

      const u = q.userByEmail.get(email);
      // Hash even for unknown users so response time does not reveal them
      const candidate = scryptHex(b.authKey, u ? u.auth_salt : fakeKdf(email).salt);
      if (!u || !safeEqualHex(candidate, u.auth_hash)) {
        noteFail(key);
        throw new HttpError(401, "Incorrect email or master password");
      }
      fails.delete(key);
      return send(res, 200, { token: newSession(u.id) });
    }

    // Everything below needs a session
    const { userId, tokenHash } = authenticate(req);

    if (route === "POST /api/logout") {
      q.deleteSession.run(tokenHash);
      return send(res, 200, { ok: true });
    }

    if (route === "GET /api/items") {
      return send(res, 200, { items: q.listItems.all(userId) });
    }

    const m = /^\/api\/items\/([^/]+)$/.exec(url.pathname);
    if (m) {
      const id = m[1];
      if (!UUID_RE.test(id)) throw new HttpError(400, "Bad item id");

      if (req.method === "PUT") {
        const b = await readJson(req);
        if (!isB64(b.blob, 40, MAX_BLOB_CHARS)) throw new HttpError(400, "Bad item data");
        const now = Date.now();
        const owner = q.itemOwner.get(id);
        if (owner && owner.user_id !== userId) throw new HttpError(404, "Not found");
        if (owner) {
          q.updateItem.run(b.blob, now, id, userId);
        } else {
          if (q.countItems.get(userId).n >= MAX_ITEMS_PER_USER) throw new HttpError(403, "Vault is full");
          q.insertItem.run(id, userId, b.blob, now, now);
        }
        return send(res, 200, { id, updated_at: now });
      }

      if (req.method === "DELETE") {
        const r = q.deleteItem.run(id, userId);
        return send(res, r.changes ? 200 : 404, { ok: r.changes > 0 });
      }
    }

    throw new HttpError(404, "Not found");
  }

  /* --------------------------- Static files ------------------------ */

  const CSP = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  function serveStatic(req, res, url) {
    if (req.method !== "GET" && req.method !== "HEAD") throw new HttpError(405, "Method not allowed");
    let rel = decodeURIComponent(url.pathname);
    if (rel.endsWith("/")) rel += "index.html";
    const file = path.normalize(path.join(PUBLIC_DIR, rel));
    if (!file.startsWith(PUBLIC_DIR + path.sep)) throw new HttpError(403, "Forbidden");
    let data;
    try { data = fs.readFileSync(file); } catch { throw new HttpError(404, "Not found"); }
    res.writeHead(200, {
      "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
      "Cache-Control": "no-cache",
      "Content-Security-Policy": CSP,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
    });
    res.end(req.method === "HEAD" ? undefined : data);
  }

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://localhost");
      if (url.pathname.startsWith("/api/")) await api(req, res, url);
      else serveStatic(req, res, url);
    } catch (e) {
      if (e instanceof HttpError) return send(res, e.status, { error: e.message });
      if (e instanceof URIError) return send(res, 400, { error: "Bad request" });
      console.error(e);
      send(res, 500, { error: "Server error" });
    }
  });

  return { server, db };
}

module.exports = { createApp };

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || "127.0.0.1";
  const dbFile = process.env.VAULT_DB || path.join(__dirname, "vault.db");
  const { server } = createApp({ dbFile });
  server.listen(port, host, () => {
    console.log(`Vault running at http://${host === "127.0.0.1" ? "localhost" : host}:${port}`);
    console.log(`Database: ${dbFile}`);
  });
}
