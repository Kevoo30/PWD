# PWD Vault

A LastPass-style web vault built on the same crypto design as `password-manager.js`,
with a real database behind it.

## Run it

Needs **Node 22.5 or newer** (it uses the built-in `node:sqlite`, so there is nothing extra to install).

```
npm start
```

Then open <http://localhost:3000>. Create an account, add items, lock, and log back in.

The vault opens at <http://localhost:3000>. It uses a linen-and-teal layout with a searchable
item list on the left and selected item details on the right. Select a saved login to view its
details, then use the eye control to reveal its password.

| Env var    | Default            | Meaning                                  |
|------------|--------------------|------------------------------------------|
| `PORT`     | `3000`             | Port to listen on                        |
| `HOST`     | `127.0.0.1`        | Interface to bind to                     |
| `VAULT_DB` | `vault/vault.db`   | SQLite file (created on first start)     |

The browser's crypto API only works on `localhost` or over HTTPS. If you deploy this
anywhere other than your own machine, put it behind HTTPS.

## How it works

```
master password --PBKDF2-SHA256 (600k)--> master key
master key --HMAC("vault-aes-gcm-key")--> AES-GCM key   stays in the browser, encrypts items
master key --HMAC("vault-auth-key")-----> auth key      sent to the server to log in
```

- Each item (name, URL, username, password, notes, folder) is one JSON object, padded to a
  256-byte bucket and encrypted with AES-GCM in the browser. The item's id is bound in as
  authenticated data, so a ciphertext copied under another id fails to decrypt.
- The server stores only that ciphertext. It never sees the master password, the AES key,
  or any plaintext. The auth key is hashed again with scrypt before it is stored.
- Folders, favorites and search all happen in the browser after decryption.

### Database (SQLite)

| Table      | Holds                                                                  |
|------------|------------------------------------------------------------------------|
| `users`    | email, public KDF salt and iteration count, scrypt hash of the auth key |
| `items`    | id, owner, opaque encrypted blob, timestamps                           |
| `sessions` | SHA-256 of each session token, expiry (12 hours)                       |

### Features

Login and signup, search (press `/`), filters for logins, notes and starred items, folders,
secure notes, add/edit/delete, password reveal, password generator, strength meter, security
challenge (weak and reused passwords), CSV export, clipboard auto-clear after 30 seconds,
auto-lock after 15 minutes idle, responsive layout.

## API

All bodies are JSON. Everything except `prelogin`, `register` and `login` needs
`Authorization: Bearer <token>`.

| Method | Path               | Purpose                                      |
|--------|--------------------|----------------------------------------------|
| GET    | `/api/prelogin?email=` | KDF salt and iterations for an email     |
| POST   | `/api/register`    | `{email, salt, iterations, authKey}`         |
| POST   | `/api/login`       | `{email, authKey}` returns `{token}`         |
| POST   | `/api/logout`      | Ends the session                             |
| GET    | `/api/items`       | All encrypted items for the user             |
| PUT    | `/api/items/:id`   | `{blob}` creates or replaces an item         |
| DELETE | `/api/items/:id`   | Deletes an item                              |

## Tests

```
npm test
```

`test/test-vault.js` covers the crypto, the API, user isolation, lockout, and checks that the
raw database file contains none of the plaintext.

## Limits to know about

- **No password recovery.** Lose the master password and the vault cannot be opened.
- **No master-password change yet.** It would mean re-encrypting every item under a new key.
- **No sharing, 2FA or browser extension.** This is a web vault only.
- Rate limiting is in memory and per email and address, and resets when the server restarts.
- This has not had an independent security review. Treat it as a solid learning and
  personal-use project, not a replacement for an audited password manager.

