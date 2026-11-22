"use strict";

const expect = require("expect.js");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createApp } = require("../vault/server");
const VC = require("../vault/public/vaultcrypto");

describe("Vault: crypto", function () {
  this.timeout(20000);
  const salt = VC.newSalt();

  it("derives different, stable keys for aes and auth", async () => {
    const a = await VC.deriveKeys("correct horse battery", "A@x.com", salt, 100000);
    const b = await VC.deriveKeys("correct horse battery", "a@x.com ", salt, 100000);
    const c = await VC.deriveKeys("a different password", "a@x.com", salt, 100000);
    expect(a.authKey).to.be(b.authKey);          // email is normalised
    expect(a.authKey).not.to.be(c.authKey);
  });

  it("round-trips an item and binds it to its id", async () => {
    const { aesKey } = await VC.deriveKeys("pw-for-test-12345", "a@x.com", salt, 100000);
    const id = VC.uuid(), other = VC.uuid();
    const blob = await VC.encryptItem(aesKey, id, { name: "Bank", password: "s3cret!" });
    expect(await VC.decryptItem(aesKey, id, blob)).to.eql({ name: "Bank", password: "s3cret!" });
    let failed = false;
    try { await VC.decryptItem(aesKey, other, blob); } catch { failed = true; }
    expect(failed).to.be(true);                   // moved under another id -> rejected
  });

  it("pads ciphertext so lengths fall into buckets", async () => {
    const { aesKey } = await VC.deriveKeys("pw-for-test-12345", "a@x.com", salt, 100000);
    const id = VC.uuid();
    const a = await VC.encryptItem(aesKey, id, { p: "a" });
    const b = await VC.encryptItem(aesKey, id, { p: "abcdefghij" });
    expect(a.length).to.be(b.length);
  });

  it("generates passwords with every selected character class", () => {
    for (let i = 0; i < 200; i++) {
      const p = VC.generatePassword({ length: 12 });
      expect(p).to.have.length(12);
      expect(/[a-z]/.test(p) && /[A-Z]/.test(p) && /[0-9]/.test(p) && /[^a-zA-Z0-9]/.test(p)).to.be(true);
    }
    expect(/^[0-9]+$/.test(VC.generatePassword({ length: 30, lower: false, upper: false, symbols: false }))).to.be(true);
  });

  it("rates strength sensibly", () => {
    expect(VC.passwordStrength("password123").score).to.be.lessThan(2);
    expect(VC.passwordStrength("aaaaaaaa").score).to.be.lessThan(2);
    expect(VC.passwordStrength(VC.generatePassword({ length: 24 })).score).to.be(4);
  });
});

describe("Vault: server + database", function () {
  this.timeout(30000);
  let app, base, dbFile;

  before(async () => {
    dbFile = path.join(os.tmpdir(), `vault-test-${process.pid}-${Date.now()}.db`);
    app = createApp({ dbFile });
    await new Promise((r) => app.server.listen(0, "127.0.0.1", r));
    base = "http://127.0.0.1:" + app.server.address().port;
  });
  after(async () => {
    await new Promise((r) => app.server.close(r));
    app.db.close();
    for (const s of ["", "-wal", "-shm"]) fs.rmSync(dbFile + s, { force: true });
  });

  async function call(method, url, body, token) {
    const res = await fetch(base + url, {
      method,
      headers: { ...(body ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: "Bearer " + token } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  }

  async function register(email, password) {
    const salt = VC.newSalt();
    const keys = await VC.deriveKeys(password, email, salt, 100000);
    const r = await call("POST", "/api/register", { email, salt, iterations: 100000, authKey: keys.authKey });
    return { r, keys, salt };
  }

  it("serves both frontends, and redirects /lockbox to /lockbox/", async () => {
    const main = await fetch(base + "/");
    expect(main.status).to.be(200);
    const lb = await fetch(base + "/lockbox/");
    expect(lb.status).to.be(200);
    expect(await lb.text()).to.contain("Lockbox");
    for (const f of ["/lockbox/lockbox.js", "/lockbox/lockbox.css", "/vaultcrypto.js"]) {
      expect((await fetch(base + f)).status).to.be(200);
    }
    const redirect = await fetch(base + "/lockbox", { redirect: "manual" });
    expect(redirect.status).to.be(301);
    expect(redirect.headers.get("location")).to.be("/lockbox/");
    expect((await fetch(base + "/lockbox/../server.js")).status).to.not.be(200);
  });

  it("registers, logs in and stores only ciphertext", async () => {
    const { r, keys } = await register("alice@example.com", "alice-master-password");
    expect(r.status).to.be(201);

    const pre = await call("GET", "/api/prelogin?email=alice@example.com");
    const k2 = await VC.deriveKeys("alice-master-password", "alice@example.com", pre.body.salt, pre.body.iterations);
    const login = await call("POST", "/api/login", { email: "alice@example.com", authKey: k2.authKey });
    expect(login.status).to.be(200);

    const id = VC.uuid();
    const blob = await VC.encryptItem(keys.aesKey, id, { type: "password", name: "Netflix", username: "alice", password: "hunter2-hunter2" });
    expect((await call("PUT", "/api/items/" + id, { blob }, login.body.token)).status).to.be(200);

    const list = await call("GET", "/api/items", null, login.body.token);
    expect(list.body.items).to.have.length(1);
    const plain = await VC.decryptItem(k2.aesKey, id, list.body.items[0].blob);
    expect(plain.name).to.be("Netflix");

    // Nothing readable at rest: scan the raw database file(s)
    app.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    const raw = Buffer.concat(["", "-wal"].map((s) => (fs.existsSync(dbFile + s) ? fs.readFileSync(dbFile + s) : Buffer.alloc(0)))).toString("latin1");
    for (const secret of ["Netflix", "hunter2-hunter2", "alice-master-password"]) expect(raw.includes(secret)).to.be(false);
  });

  it("rejects a wrong master password and unknown users with the same message", async () => {
    const pre = await call("GET", "/api/prelogin?email=alice@example.com");
    const bad = await VC.deriveKeys("wrong-password-123", "alice@example.com", pre.body.salt, pre.body.iterations);
    const a = await call("POST", "/api/login", { email: "alice@example.com", authKey: bad.authKey });
    const b = await call("POST", "/api/login", { email: "nobody@example.com", authKey: bad.authKey });
    expect(a.status).to.be(401);
    expect(b.status).to.be(401);
    expect(a.body.error).to.be(b.body.error);
  });

  it("gives unknown emails a stable fake salt", async () => {
    const x = await call("GET", "/api/prelogin?email=ghost@example.com");
    const y = await call("GET", "/api/prelogin?email=ghost@example.com");
    expect(x.body.salt).to.be(y.body.salt);
  });

  it("refuses duplicate accounts", async () => {
    const { r } = await register("alice@example.com", "another-password-1");
    expect(r.status).to.be(409);
  });

  it("requires a session and keeps users isolated", async () => {
    expect((await call("GET", "/api/items")).status).to.be(401);

    const bob = await register("bob@example.com", "bob-master-password-1");
    const token = bob.r.body.token;
    expect((await call("GET", "/api/items", null, token)).body.items).to.have.length(0);

    // Bob can't overwrite or delete Alice's item
    const alice = await call("POST", "/api/login", {
      email: "alice@example.com",
      authKey: (await VC.deriveKeys("alice-master-password", "alice@example.com", (await call("GET", "/api/prelogin?email=alice@example.com")).body.salt, 100000)).authKey,
    });
    const aliceItem = (await call("GET", "/api/items", null, alice.body.token)).body.items[0];
    const blob = await VC.encryptItem(bob.keys.aesKey, aliceItem.id, { name: "evil" });
    expect((await call("PUT", "/api/items/" + aliceItem.id, { blob }, token)).status).to.be(404);
    expect((await call("DELETE", "/api/items/" + aliceItem.id, null, token)).status).to.be(404);
    expect((await call("GET", "/api/items", null, alice.body.token)).body.items).to.have.length(1);
  });

  it("updates and deletes items, and logout kills the session", async () => {
    const { r, keys } = await register("carol@example.com", "carol-master-password");
    const token = r.body.token;
    const id = VC.uuid();
    await call("PUT", "/api/items/" + id, { blob: await VC.encryptItem(keys.aesKey, id, { name: "One" }) }, token);
    await call("PUT", "/api/items/" + id, { blob: await VC.encryptItem(keys.aesKey, id, { name: "Two" }) }, token);
    const list = (await call("GET", "/api/items", null, token)).body.items;
    expect(list).to.have.length(1);
    expect((await VC.decryptItem(keys.aesKey, id, list[0].blob)).name).to.be("Two");

    expect((await call("DELETE", "/api/items/" + id, null, token)).status).to.be(200);
    expect((await call("GET", "/api/items", null, token)).body.items).to.have.length(0);

    await call("POST", "/api/logout", {}, token);
    expect((await call("GET", "/api/items", null, token)).status).to.be(401);
  });

  it("validates input", async () => {
    const { r } = await register("dave@example.com", "dave-master-password-1");
    const t = r.body.token;
    expect((await call("PUT", "/api/items/not-a-uuid", { blob: "x".repeat(60) }, t)).status).to.be(400);
    expect((await call("PUT", "/api/items/" + VC.uuid(), { blob: "<script>" }, t)).status).to.be(400);
    expect((await call("POST", "/api/register", { email: "bad", salt: VC.newSalt(), iterations: 100000, authKey: "x" })).status).to.be(400);
  });

  it("locks out repeated failed logins", async () => {
    const pre = await call("GET", "/api/prelogin?email=erin@example.com");
    const k = await VC.deriveKeys("whatever-password-1", "erin@example.com", pre.body.salt, pre.body.iterations);
    let last;
    for (let i = 0; i < 9; i++) last = await call("POST", "/api/login", { email: "erin@example.com", authKey: k.authKey });
    expect(last.status).to.be(429);
  });

  it("serves the app with a strict CSP and blocks path traversal", async () => {
    const res = await fetch(base + "/");
    expect(res.status).to.be(200);
    expect(res.headers.get("content-security-policy")).to.contain("script-src 'self'");
    const t = await fetch(base + "/..%2Fserver.js");
    expect(t.status).not.to.be(200);
  });
});
