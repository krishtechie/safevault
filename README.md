# Vault

A self-hosted, zero-knowledge password manager. It generates strong passwords, stores them encrypted, syncs across devices, and checks them against known data breaches.

Runs on ordinary shared hosting (PHP 8.1+, no database). The front end is plain JavaScript with no build step.

## How it protects your data

| Area | Design |
|---|---|
| Master password | Never stored and never sent to the server |
| Key derivation | Argon2id (64 MiB, 3 passes), then HKDF-SHA256 splits the result into a key-wrapping key and a separate sign-in key |
| Vault encryption | AES-256-GCM in the browser (Web Crypto) with a random vault key, fresh random nonce on every save, username bound as associated data |
| Key wrapping | The vault key is stored only in wrapped (encrypted) form. Changing the master password re-wraps the key and never rewrites the vault |
| Recovery | Optional recovery key (160 random bits, shown once). It wraps the same vault key, so a forgotten master password can be replaced without the server ever being able to open the vault |
| PIN unlock | Optional, per device. The key that opens the vault is split in two random halves: one on the device, one on the server. The server releases its half only for the right PIN and destroys it after three wrong tries, after which the master password is required. Needs a connection |
| Face ID / Touch ID | Optional, per device. Uses a passkey with the WebAuthn PRF extension: the device's secure hardware releases a secret only after a successful face or fingerprint check. Works offline |
| Access log | The server records each sign-in, failed attempt and security change with time, address and browser (latest 500 per account). Settings shows it in plain words with filters by type, period and search. It never contains keys or passwords. The server owner (the first account, or `owner` in config) also sees failed attempts on usernames that do not exist and on other accounts, with the name that was tried. A city and country are shown for each address through a lookup service, which can be switched off with `geo_url` in config |
| Import | CSV exports from Google or Chrome, Safari, Firefox, Edge, Bitwarden, 1Password and LastPass are read on the device, cleaned by the same field rules, de-duplicated against the vault, and encrypted before anything is sent |
| Two-factor sign-in | Optional. A new device needs the master password and a 6-digit authenticator code (TOTP, RFC 6238). Codes cannot be reused, five wrong codes block further tries, and the secret is stored encrypted on the server. Devices that passed once hold a random token and are not asked again. The recovery key is the way back in if the authenticator is lost |
| Rollback detection | Each device remembers the vault version and a fingerprint of the copy it last saw. If the server offers an older copy, a different copy under the same version, or no vault at all, syncing pauses with a warning and the device can restore its copy |
| Everyday use | Favourites first, then entries used recently on that device, then the rest. One tap copies a username or password from the list, and an entry can copy its password and open its site in one step. The recently used list holds entry ids only and never leaves the device |
| Recently deleted | Deleting moves an entry to Recently deleted with an Undo, on every device. It can be restored for 30 days, then it is removed for good and only an id and a time remain so the removal syncs |
| Health at a glance | The Health tab shows a count of entries that are reused, weak, older than a year or found in the last breach check. All of it is worked out on the device. The last breach result is remembered on the device as entry ids and counts only, and is wiped on sign out |
| Version safety | The encrypted vault records its format version. A device still running older code refuses to open or overwrite a newer vault and asks for a reload, so it cannot drop fields it does not know |
| Tags | Entries can carry up to 6 tags. Chips above the list filter by tag, search finds tags, and folder columns in Bitwarden or LastPass exports become tags on import. Tags live inside the encrypted vault, so the server never sees them |
| Devices | Settings lists every browser signed in, with a name you can change. Signing one out from another device ends its session at once, destroys its PIN record and two-factor trust, and makes it erase its vault copy the next time it connects. The server stores a hash of each device id, a name, the browser and two times |
| Safe updates | The page and the script carry a build number. If a browser holds one of them from before an update, the app fetches fresh copies and reloads once instead of failing |
| Authenticator codes | An entry can hold a site's two-factor key. The key is stored inside the encrypted vault and the 6-digit code is computed on the device (TOTP, RFC 6238) |
| Stay unlocked | Optional. The vault key is held as a non-extractable browser key until the auto-lock time passes, so a page reload does not ask for the password again. Closing and reopening the app always asks to unlock, with Face ID offered at once when it is on |
| Server knowledge | Only a bcrypt hash of the sign-in key and the encrypted vault blob. A full server breach exposes no passwords |
| Sync | Revision numbers with conflict detection. Devices merge per entry (newest edit wins, deletions sync) |
| Offline | An encrypted copy is kept on each device, so the vault opens without internet. An offline notice shows, and changes sync by themselves once the connection returns |
| Leak check | Have I Been Pwned range API with k-anonymity: only the first 5 characters of a SHA-1 hash leave the device |
| Generator | `crypto.getRandomValues` with rejection sampling (no modulo bias). Random characters or EFF wordlist passphrases |
| Field rules | Every entry field is validated (no hidden or control characters, usernames without spaces or markup, website addresses limited to http and https). Data read from the server or a backup is cleaned the same way before use |
| Script injection | All text is written to the page as plain text, never as HTML. Combined with the Content Security Policy, pasted or imported markup cannot run |
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

Covers key derivation (cross-checked against libsodium), encryption round trips and tamper detection, key wrapping, recovery keys, compatibility with vaults from the first release, merge rules, generator output, and the leak-check protocol.

## Limits to know about

- This project has not had an independent security audit. Keep an encrypted backup (Settings) and a second copy of critical passwords until you trust it.
- A forgotten master password can only be replaced with the recovery key. With neither, the vault cannot be opened by anyone.
- Not in this version: browser autofill.
- Rollback detection needs a device that has seen the newer copy. A brand new device has nothing to compare against.
- PIN unlock protects against someone who has the device but not the PIN. Someone holding both the device's storage and the server's files could try all PINs, so the master password remains the real key.
- Passwords are in memory while the vault is unlocked, so a compromised device or malicious browser extension can still read them. That is true of every password manager.

## Third-party code

- `vendor/argon2.umd.min.js`: hash-wasm (MIT)
- `vendor/wordlist.js`: EFF large wordlist (CC BY 3.0 US)
