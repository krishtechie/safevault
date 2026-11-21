# Vault

A self-hosted, zero-knowledge password manager. It generates strong passwords, stores them encrypted, syncs across devices, and checks them against known data breaches.

Runs on ordinary shared hosting (PHP 8.1+, no database). The front end is plain JavaScript with no build step.

## How it protects your data

| Area | Design |
|---|---|
| Master password | Never stored and never sent to the server |
| Key derivation | Argon2id (64 MiB, 3 passes), then HKDF-SHA256 splits the result into an encryption key and a separate sign-in key |
| Vault encryption | AES-256-GCM in the browser (Web Crypto), fresh random nonce on every save, username bound as associated data |
| Server knowledge | Only a bcrypt hash of the sign-in key and the encrypted vault blob. A full server breach exposes no passwords |
| Sync | Revision numbers with conflict detection. Devices merge per entry (newest edit wins, deletions sync) |
| Offline | An encrypted copy is kept on each device, so the vault opens without internet and syncs later |
| Leak check | Have I Been Pwned range API with k-anonymity: only the first 5 characters of a SHA-1 hash leave the device |
| Generator | `crypto.getRandomValues` with rejection sampling (no modulo bias). Random characters or EFF wordlist passphrases |
| Browser hardening | Strict Content Security Policy, no third-party scripts, no inline code, auto-lock, clipboard cleared after 30 seconds |
| API hardening | Invite-only sign-up, login throttling, HttpOnly SameSite=Strict session cookie, cross-site requests rejected, account enumeration blocked, data folder forced outside the web root |

## Deploy (cPanel)

1. Create a **dedicated subdomain** for it (for example `vault.yourdomain.com`) with HTTPS on. A separate subdomain keeps the vault isolated from every other site you host.
2. Deploy this repository into that subdomain's folder (cPanel Git, same as any other site).
3. In cPanel File Manager, copy `api/config.sample.php` to `api/config.php` and set:
   - `data_dir`: a folder outside the web root, for example `/home/YOUR_CPANEL_USER/vault-data`
   - `server_secret`: a long random string (32+ characters)
   - `invite_code`: a private code (12+ characters) needed to create an account
4. Open the site, choose "Create an account", and enter the invite code.
5. Set `allow_registration` to `false` in `config.php` once your accounts exist.
6. On your phone, open the site and use "Add to Home Screen" to install it as an app.

`config.php` is in `.gitignore`, so real settings never reach GitHub.

## Tests

```
node --test tests/core.test.mjs
```

Covers key derivation (cross-checked against libsodium), encryption round trips and tamper detection, merge rules, generator output, and the leak-check protocol.

## Limits to know about

- This project has not had an independent security audit. Keep an encrypted backup (Settings) and a second copy of critical passwords until you trust it.
- There is no password reset. A forgotten master password means the vault cannot be opened.
- Not in this version: changing the master password, two-factor sign-in, browser autofill, import from other password managers.
- Passwords are in memory while the vault is unlocked, so a compromised device or malicious browser extension can still read them. That is true of every password manager.

## Third-party code

- `vendor/argon2.umd.min.js`: hash-wasm (MIT)
- `vendor/wordlist.js`: EFF large wordlist (CC BY 3.0 US)
