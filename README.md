# Password Manager
Simple password and 2FA (one-time code) manager written in bash.
Inspired by https://github.com/drduh/pwd.sh, `pass`, tpm, pa and friends.
It keeps everything in one file, encrypted with GnuPG (AES-256, passphrase
stretched with S2K mode 3, SHA-512, maximum iterations), decrypts it on the
fly, and copies what you ask for to the clipboard for a few seconds.

## Dependencies
Required:
- `gpg`, `bash` 4+, coreutils (`base64`, `sha1sum`/`sha256sum`/`sha512sum`, ...)
- a clipboard tool: `xclip`, `xsel`, `wl-copy` or `pbcopy` (or use `--show`)

Optional:
- `fzf`: leave out the entry name and pick it from a list
- `zbarimg` (zbar): add a 2FA secret from a QR code screenshot
- `qrencode`: `--otp-export` shows a QR code, to move a secret to your phone
- `flock` (util-linux): no two pwdman runs write the database at once

- Ubuntu/Debian: `sudo apt install gpg xclip fzf zbar-tools qrencode`
- Arch: `pacman -S gnupg xclip fzf zbar qrencode`
- Nix: `nix run github:hydrastro/pwdman -- --help` (flake included)

## Installation
Clone or copy the script anywhere, then put it on your `PATH` or alias it:
```shell
git clone https://github.com/hydrastro/pwdman.git /opt/pwdman
alias pw='/opt/pwdman/pwdman.sh -i'
alias pwr='/opt/pwdman/pwdman.sh -r'
```
Settings are environment variables: `DEFAULT_DATABASE` (default
`~/pwdman.db`), `CLIPBOARD_TIMEOUT` (7 s), `DEFAULT_LENGTH` (128),
`DEFAULT_ALPHABET`, `PWDMAN_FZF` (1).

## Usage
```shell
pwdman.sh -c [database]              # create a database
pwdman.sh -w name [database]         # add a password (typed twice, or generated)
pwdman.sh -r [name] [database]       # copy it to the clipboard
pwdman.sh -u [name] [database]       # change it
pwdman.sh -d [name] [database]       # delete
pwdman.sh -l [database]              # list names and types
pwdman.sh -G [length]                # just generate a password
pwdman.sh --show -r name             # print to stdout instead (scripts, pipes)
```
Leave out the name and, with `fzf` installed, you pick it from a list.

### Two-factor codes (TOTP and HOTP)
```shell
pwdman.sh -t github                  # store the secret
pwdman.sh -g [github]                # copy the current code
pwdman.sh -e [github]                # show its otpauth:// URI and a QR code
```
`-t` takes the Base32 key the site shows, the full `otpauth://` link, or the
path of a screenshot of the QR code. Algorithms SHA1/SHA256/SHA512, 6 to 10
digits, any period, and counter-based HOTP (the counter is saved after each
code) are supported. Codes are computed in bash with `sha*sum`: the secret
never appears in a command line, where other users could see it.

Keep in mind: a 2FA secret stored next to the password turns two factors
into one for anyone who gets the database and its password. That's fine
against phishing and leaked site passwords (what 2FA mostly stops), but for
your most important accounts (email, bank) keep the 2FA on another device.

### Backups and moving
```shell
cp ~/pwdman.db somewhere/            # encrypted backup: just copy the file
pwdman.sh -x [database]              # change the database password
pwdman.sh -n other.db [database]     # merge another encrypted database in
pwdman.sh -b file [database]         # UNENCRYPTED export (Base64 is not encryption)
pwdman.sh -m file [database]         # import such an export
```

### Interactive mode
```shell
pwdman.sh -i
```
Then press a key: `r w u d l` passwords, `t g e` one-time codes, `G`
generate, `c x b m n` database, `h` help.

## Security notes
- The database password is everything: use a long passphrase (5+ random
  words). It's stretched with GnuPG's iterated S2K, which slows guessing
  down but is not memory-hard like scrypt/Argon2.
- Secrets travel only through pipes and bash builtins, never in program
  arguments; no temporary plaintext files; no core dumps; files are 0600.
- Every save is verified (the new file is decrypted and compared) before it
  replaces the old one, so a failed write can't destroy the database.
- The clipboard is cleared after the timeout, or at once on Ctrl-C, but only
  if it still holds the secret. Clipboard managers may keep a history:
  exclude your terminal from them or use `--show`.
- Changing the password (`-x`) doesn't re-encrypt old copies: backups and
  git history still open with the old one.

## Contributing
Feel free to contribute, pull requests are always welcome.
Please check your code with `shellcheck` before pushing it.

### Database Structure
The database is an encrypted CSV file with three columns, `Username`,
`Password` and `Type`, and a header line. The first two are Base64-encoded.
`Type` is `password`, `totp` or `hotp`; for the last two the second column
holds an `otpauth://` URI (older versions stored a bare Base32 key, which
still works). Databases from older versions open as they are.
