#!/usr/bin/env bash
# pwdman.sh — A GPG-encrypted password and TOTP manager
# Version 1.2
set -euo pipefail

umask 077

: "${DEFAULT_DATABASE:=${HOME}/pwdman.db}"
: "${CLIPBOARD_TIMEOUT:=7}"
: "${DEFAULT_LENGTH:=128}"
: "${DEFAULT_ALPHABET:=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#\$%^&*()_+=.,:;/-}"

SCRIPT_VERSION="1.2"
PWDMAN_LOCK_FD=""

# ---------------------------------------------------------------------------
# Core utilities
# ---------------------------------------------------------------------------

pwdman_exit() {
  local message="${1:-Error: undefined error.}"
  printf '%s\n' "$message" >&2
  exit 1
}

pwdman_require_command() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || \
    pwdman_exit "Error: required command not found: $cmd"
}

pwdman_base64_encode() {
  printf '%s' "$1" | base64 | tr -d '\n'
}

pwdman_base64_decode() {
  printf '%s' "$1" | base64 --decode
}

pwdman_prompt() {
  local prompt="${1:-Input: }"
  local value=""
  printf '%s' "$prompt" >&2
  IFS= read -r value || pwdman_exit "Error: failed to read input."
  printf '%s' "$value"
}

pwdman_prompt_secret() {
  local prompt="${1:-Password: }"
  local value=""
  printf '%s' "$prompt" >&2
  IFS= read -r -s value || pwdman_exit "Error: failed to read password."
  printf '\n' >&2
  printf '%s' "$value"
}

pwdman_ask_continue() {
  local default_yes="${1:-0}"
  local answer=""
  local prompt="Continue [y/N]? "
  [[ "$default_yes" == "1" ]] && prompt="Continue [Y/n]? "
  answer="$(pwdman_prompt "$prompt")"
  case "$answer" in
    [Yy]) return 0 ;;
    [Nn]) pwdman_exit "Aborting." ;;
    "")
      [[ "$default_yes" == "1" ]] && return 0
      pwdman_exit "Aborting."
      ;;
    *) pwdman_exit "Aborting." ;;
  esac
}

# ---------------------------------------------------------------------------
# File locking
# ---------------------------------------------------------------------------

pwdman_lock_database() {
  local database="$1"
  local mode="$2"
  local lock_file="${database}.lock"
  command -v flock >/dev/null 2>&1 || return 0
  mkdir -p -- "$(dirname -- "$database")"
  exec {PWDMAN_LOCK_FD}>"$lock_file" || \
    pwdman_exit "Error: could not open database lock."
  if [[ "$mode" == "shared" ]]; then
    flock -s "$PWDMAN_LOCK_FD" || pwdman_exit "Error: could not lock database."
  else
    flock -x "$PWDMAN_LOCK_FD" || pwdman_exit "Error: could not lock database."
  fi
}

pwdman_unlock_database() {
  if [[ -n "$PWDMAN_LOCK_FD" ]]; then
    command -v flock >/dev/null 2>&1 && { flock -u "$PWDMAN_LOCK_FD" || true; }
    exec {PWDMAN_LOCK_FD}>&-
    PWDMAN_LOCK_FD=""
  fi
}

# ---------------------------------------------------------------------------
# GPG encryption / decryption
# ---------------------------------------------------------------------------

# Common GPG options for symmetric encryption.
# --s2k-mode 3 + --s2k-count force iterated key derivation (max rounds),
# making brute-force attacks significantly more expensive than the v1.1 default.
_pwdman_gpg_enc_opts() {
  local database="$1"
  local passphrase_fd="$2"
  printf '%s\n' \
    --armor \
    --batch \
    --yes \
    --pinentry-mode loopback \
    --symmetric \
    --passphrase-fd "$passphrase_fd" \
    --no-symkey-cache \
    --cipher-algo AES256 \
    --s2k-mode 3 \
    --s2k-digest-algo SHA512 \
    --s2k-count 65011712 \
    --output "$database"
}

pwdman_encrypt_database() {
  local database="$1"
  local database_password="$2"
  local database_buffer="${3:-}"
  local database_dir tmp_file data
  local gpg_options=()

  database_dir="$(dirname -- "$database")"
  mkdir -p -- "$database_dir"

  data="Username,Password,Type"$'\n'
  [[ -n "$database_buffer" ]] && data+="$database_buffer"$'\n'

  tmp_file="$(mktemp "${database_dir}/.pwdman.XXXXXX")" || \
    pwdman_exit "Error: could not create temporary file."
  chmod 600 "$tmp_file"

  mapfile -t gpg_options < <(_pwdman_gpg_enc_opts "$tmp_file" 3)

  if printf '%s' "$data" | gpg "${gpg_options[@]}" 3< <(printf '%s' "$database_password"); then
    mv -f -- "$tmp_file" "$database"
    chmod 600 "$database"
  else
    rm -f -- "$tmp_file"
    pwdman_exit "Error: database encryption error."
  fi
}

pwdman_decrypt_database() {
  local database="$1"
  local database_password="$2"
  local result gpg_options=()

  [[ -f "$database" ]] || pwdman_exit "Error: database not found: $database"

  gpg_options=(
    --batch
    --yes
    --pinentry-mode loopback
    --passphrase-fd 3
    --no-symkey-cache
    --decrypt
  )

  if ! result="$(gpg "${gpg_options[@]}" -- "$database" \
      3< <(printf '%s' "$database_password") 2>/dev/null)"; then
    pwdman_exit "Error: database decryption error. Wrong password?"
  fi

  # Strip header line and blank lines; support both old (2-col) and new (3-col) format
  printf '%s' "$result" | tail -n +2 | sed '/^[[:space:]]*$/d'
}

# ---------------------------------------------------------------------------
# Buffer helpers  (format: base64(username),base64(secret),type)
# type = "password" | "totp"
# ---------------------------------------------------------------------------

pwdman_validate_username() {
  local username="$1"
  [[ -n "$username" ]]   || pwdman_exit "Error: username cannot be empty."
  [[ "$username" != *$'\n'* ]] || pwdman_exit "Error: username cannot contain newlines."
  [[ "$username" != *,* ]]     || pwdman_exit "Error: username cannot contain commas."
}

pwdman_count_entries() {
  local database_buffer="$1"
  local encoded_username="$2"
  local entry_type="${3:-}"   # optional: filter by type
  local line count=0

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local u t
    u="${line%%,*}"
    t="${line##*,}"
    [[ "$u" == "$encoded_username" ]] || continue
    [[ -z "$entry_type" || "$t" == "$entry_type" ]] || continue
    (( count++ ))
  done <<< "$database_buffer"

  printf '%s\n' "$count"
}

pwdman_username_exists() {
  local count
  count="$(pwdman_count_entries "$1" "$2" "${3:-}")"
  [[ "$count" -gt 0 ]]
}

pwdman_get_secret_by_username() {
  local database_buffer="$1"
  local encoded_username="$2"
  local entry_type="${3:-password}"
  local line

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local u s t
    u="${line%%,*}"
    rest="${line#*,}"
    s="${rest%%,*}"
    t="${rest##*,}"
    [[ "$u" == "$encoded_username" ]] || continue
    [[ "$t" == "$entry_type" ]] || continue
    pwdman_base64_decode "$s"
    return 0
  done <<< "$database_buffer"

  return 1
}

pwdman_remove_entry() {
  local database_buffer="$1"
  local encoded_username="$2"
  local entry_type="${3:-}"
  local line output=""

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local u t
    u="${line%%,*}"
    t="${line##*,}"
    if [[ "$u" == "$encoded_username" ]]; then
      [[ -z "$entry_type" || "$t" == "$entry_type" ]] && continue
    fi
    output+="$line"$'\n'
  done <<< "$database_buffer"

  printf '%s' "${output%$'\n'}"
}

pwdman_append_entry() {
  local database_buffer="$1"
  local entry="$2"
  if [[ -n "$database_buffer" ]]; then
    printf '%s\n%s' "$database_buffer" "$entry"
  else
    printf '%s' "$entry"
  fi
}

pwdman_merge_buffers() {
  local a="$1" b="$2"
  if [[ -n "$a" && -n "$b" ]]; then
    printf '%s\n%s' "$a" "$b"
  elif [[ -n "$a" ]]; then
    printf '%s' "$a"
  else
    printf '%s' "$b"
  fi
}

pwdman_check_merge_conflicts() {
  local first_buffer="$1"
  local second_buffer="$2"
  local line encoded_username

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    encoded_username="${line%%,*}"
    if pwdman_username_exists "$first_buffer" "$encoded_username"; then
      printf '%s\n' "Warning: imported data contains an entry already present in the current database." >&2
      pwdman_ask_continue 0
      return 0
    fi
  done <<< "$second_buffer"
}

# ---------------------------------------------------------------------------
# Random password
# ---------------------------------------------------------------------------

pwdman_random_password() {
  local length="${1:-$DEFAULT_LENGTH}"
  local alphabet="${2:-$DEFAULT_ALPHABET}"
  local alphabet_length max_usable password=""

  [[ "$length" =~ ^[1-9][0-9]*$ ]] || pwdman_exit "Error: invalid password length."
  alphabet_length="${#alphabet}"
  (( alphabet_length > 0 && alphabet_length <= 256 )) || \
    pwdman_exit "Error: alphabet length must be between 1 and 256."

  max_usable=$(( 256 / alphabet_length * alphabet_length ))

  while (( ${#password} < length )); do
    while IFS= read -r byte; do
      [[ -n "$byte" ]] || continue
      (( byte < max_usable )) || continue
      password+="${alphabet:byte % alphabet_length:1}"
      (( ${#password} >= length )) && break
    done < <(od -An -vtu1 -N 4096 /dev/urandom | tr -s ' ' '\n')
  done

  printf '%s' "$password"
}

# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------

pwdman_clipboard_set() {
  local value="$1"
  if   command -v wl-copy  >/dev/null 2>&1; then printf '%s' "$value" | wl-copy
  elif command -v xclip    >/dev/null 2>&1; then printf '%s' "$value" | xclip -selection clipboard
  elif command -v pbcopy   >/dev/null 2>&1; then printf '%s' "$value" | pbcopy
  else pwdman_exit "Error: no clipboard tool found (install wl-copy, xclip, or pbcopy)."
  fi
}

pwdman_copy_to_clipboard() {
  local secret="$1"
  local timeout="${2:-$CLIPBOARD_TIMEOUT}"
  [[ "$timeout" =~ ^[0-9]+$ ]] || pwdman_exit "Error: invalid clipboard timeout."
  pwdman_clipboard_set "$secret"
  while (( timeout > 0 )); do
    printf '\rCopied to clipboard. Clearing in %d s... ' "$timeout" >&2
    sleep 1
    (( timeout-- ))
  done
  printf '\nClipboard cleared.\n' >&2
  pwdman_clipboard_set ""
}

# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------

# Decode a Base32 string to hex (RFC 4648, case-insensitive, no padding required)
pwdman_base32_to_hex() {
  local input="${1^^}"          # uppercase
  input="${input//=}"           # strip padding
  local -A B32=(
    [A]=0  [B]=1  [C]=2  [D]=3  [E]=4  [F]=5  [G]=6  [H]=7
    [I]=8  [J]=9  [K]=10 [L]=11 [M]=12 [N]=13 [O]=14 [P]=15
    [Q]=16 [R]=17 [S]=18 [T]=19 [U]=20 [V]=21 [W]=22 [X]=23
    [Y]=24 [Z]=25 [2]=26 [3]=27 [4]=28 [5]=29 [6]=30 [7]=31
  )
  local bits="" hex="" i char val
  for (( i=0; i<${#input}; i++ )); do
    char="${input:i:1}"
    [[ -v B32[$char] ]] || pwdman_exit "Error: invalid Base32 character: $char"
    val="${B32[$char]}"
    bits+="$(printf '%05d' "$(bc <<< "obase=2; $val")")"
  done
  # pad bits to a multiple of 8
  while (( ${#bits} % 8 != 0 )); do bits+="0"; done
  for (( i=0; i<${#bits}; i+=8 )); do
    local byte="${bits:i:8}"
    hex+="$(printf '%02x' "$(( 2#$byte ))")"
  done
  printf '%s' "$hex"
}

# Compute a TOTP code from a Base32 secret.
# Uses openssl for HMAC-SHA1; no extra dependencies beyond what's typically installed.
pwdman_compute_totp() {
  local secret_b32="$1"
  local digits="${2:-6}"
  local period="${3:-30}"

  pwdman_require_command openssl
  pwdman_require_command bc

  local secret_hex
  secret_hex="$(pwdman_base32_to_hex "$secret_b32")"

  local timestamp counter counter_hex hmac offset code
  timestamp="$(date +%s)"
  counter=$(( timestamp / period ))

  # Counter as a 16-character zero-padded hex (big-endian 64-bit)
  counter_hex="$(printf '%016x' "$counter")"

  # HMAC-SHA1(secret, counter)
  hmac="$(printf '%s' "$counter_hex" | xxd -r -p 2>/dev/null | \
    openssl dgst -sha1 -mac HMAC \
      -macopt "hexkey:${secret_hex}" \
      -binary 2>/dev/null | \
    od -An -vtu1 | tr -s ' ' '\n' | grep -v '^$')"

  # Dynamic truncation: offset = last nibble of last byte
  local -a hmac_bytes
  mapfile -t hmac_bytes <<< "$hmac"
  local offset p modulo
  offset=$(( hmac_bytes[19] & 0x0f ))

  # Extract 4 bytes starting at offset, mask top bit
  p=$(( (hmac_bytes[offset] & 0x7f) << 24 | \
        hmac_bytes[offset+1]         << 16 | \
        hmac_bytes[offset+2]         << 8  | \
        hmac_bytes[offset+3] ))

  modulo=1
  for (( i=0; i<digits; i++ )); do modulo=$(( modulo * 10 )); done
  code=$(( p % modulo ))

  printf "%0${digits}d\n" "$code"
}

# ---------------------------------------------------------------------------
# otpauth:// URI parsing
# ---------------------------------------------------------------------------

# Decode percent-encoded characters in a URI component (e.g. %40 -> @)
pwdman_urldecode() {
  local encoded="$1"
  printf '%s' "$encoded" | python3 -c "
import sys, urllib.parse
print(urllib.parse.unquote(sys.stdin.read()), end='')
" 2>/dev/null || printf '%s' "$encoded" | sed 's/%/\\x/g' | xargs -0 printf '%b'
}

# Parse a raw TOTP secret OR an otpauth:// URI.
# Prints only the Base32 secret; also prints discovered metadata to stderr.
#
# otpauth URI format:
#   otpauth://totp/Issuer:user@example.com?secret=BASE32&issuer=X&digits=6&period=30
#
pwdman_parse_otpauth() {
  local input="$1"
  local secret="" issuer="" account="" digits="" period=""

  if [[ "$input" == otpauth://* ]]; then
    # Strip scheme
    local rest="${input#otpauth://}"

    # Extract type (totp/hotp) — we only support totp
    local otp_type="${rest%%/*}"
    [[ "$otp_type" == "totp" ]] || \
      pwdman_exit "Error: only otpauth://totp/ URIs are supported (got: $otp_type)."
    rest="${rest#totp/}"

    # Extract label (everything before the '?')
    local label="${rest%%\?*}"
    local query="${rest#*\?}"
    label="$(pwdman_urldecode "$label")"

    # Label may be "Issuer:account" or just "account"
    if [[ "$label" == *:* ]]; then
      issuer="${label%%:*}"
      account="${label#*:}"
    else
      account="$label"
    fi

    # Parse query parameters key=value&key=value...
    local param
    while IFS= read -r -d '&' param; do
      local key="${param%%=*}"
      local val="${param#*=}"
      val="$(pwdman_urldecode "$val")"
      case "$key" in
        secret) secret="${val^^}" ;;   # uppercase; Base32 is case-insensitive
        issuer) [[ -z "$issuer" ]] && issuer="$val" ;;
        digits) digits="$val" ;;
        period) period="$val" ;;
      esac
    done < <(printf '%s&' "$query")

    [[ -n "$secret" ]] || pwdman_exit "Error: no secret= found in otpauth URI."

    # Report what was parsed
    printf '%s\n' "Parsed otpauth URI:" >&2
    [[ -n "$issuer"  ]] && printf '  Issuer:  %s\n' "$issuer"  >&2
    [[ -n "$account" ]] && printf '  Account: %s\n' "$account" >&2
    [[ -n "$digits"  ]] && printf '  Digits:  %s\n' "$digits"  >&2
    [[ -n "$period"  ]] && printf '  Period:  %s s\n' "$period" >&2

    # Warn if non-default parameters that our compute function doesn't use yet
    if [[ -n "$digits" && "$digits" != "6" ]]; then
      printf '%s\n' "Warning: URI requests $digits digits; this script uses 6." >&2
    fi
    if [[ -n "$period" && "$period" != "30" ]]; then
      printf '%s\n' "Warning: URI requests ${period}s period; this script uses 30s." >&2
    fi

  else
    # Plain Base32 secret — uppercase and strip whitespace/dashes (common in manual entry)
    secret="${input^^}"
    secret="${secret//[[:space:]]/}"
    secret="${secret//-/}"
  fi

  [[ -n "$secret" ]] || pwdman_exit "Error: could not extract TOTP secret."
  printf '%s' "$secret"
}

pwdman_totp_add() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer encoded_username secret encoded_secret

  pwdman_require_command gpg
  pwdman_require_command base64

  [[ -z "$username" ]] && username="$(pwdman_prompt "Account (username/service): ")"
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  encoded_username="$(pwdman_base64_encode "$username")"
  if pwdman_username_exists "$database_buffer" "$encoded_username" "totp"; then
    printf '%s\n' "Warning: a TOTP entry for this account already exists." >&2
    pwdman_ask_continue 0
    database_buffer="$(pwdman_remove_entry "$database_buffer" "$encoded_username" "totp")"
  fi

  local raw_input
  raw_input="$(pwdman_prompt_secret "TOTP secret or otpauth:// URI: ")"
  [[ -n "$raw_input" ]] || pwdman_exit "Error: input cannot be empty."

  secret="$(pwdman_parse_otpauth "$raw_input")"
  # Validate it decodes and computes without error
  pwdman_compute_totp "$secret" >/dev/null

  encoded_secret="$(pwdman_base64_encode "$secret")"
  database_buffer="$(pwdman_append_entry "$database_buffer" \
    "${encoded_username},${encoded_secret},totp")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "TOTP secret stored for: $username"
}

pwdman_totp_get() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer encoded_username secret code

  pwdman_require_command gpg
  pwdman_require_command base64

  [[ -z "$username" ]] && username="$(pwdman_prompt "Account (username/service): ")"
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  encoded_username="$(pwdman_base64_encode "$username")"
  if ! pwdman_username_exists "$database_buffer" "$encoded_username" "totp"; then
    pwdman_exit "Error: no TOTP entry found for: $username"
  fi

  secret="$(pwdman_get_secret_by_username "$database_buffer" "$encoded_username" "totp")"
  code="$(pwdman_compute_totp "$secret")"

  printf 'TOTP code for %s: ' "$username" >&2
  printf '%s\n' "$code"

  # Also copy to clipboard with a shorter timeout (code expires in ≤30 s)
  pwdman_copy_to_clipboard "$code" "$(( CLIPBOARD_TIMEOUT < 25 ? CLIPBOARD_TIMEOUT : 25 ))"
}

# ---------------------------------------------------------------------------
# Password CRUD
# ---------------------------------------------------------------------------

pwdman_write_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer entry_password length encoded_username encoded_password

  pwdman_require_command gpg
  pwdman_require_command base64

  [[ -z "$username" ]] && username="$(pwdman_prompt "Username: ")"
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  encoded_username="$(pwdman_base64_encode "$username")"
  if pwdman_username_exists "$database_buffer" "$encoded_username" "password"; then
    printf '%s\n' "Warning: this username already exists in the database." >&2
    pwdman_ask_continue 0
  fi

  entry_password="$(pwdman_prompt_secret "Entry password [leave blank to generate]: ")"
  if [[ -z "$entry_password" ]]; then
    length="$(pwdman_prompt "Random password length [$DEFAULT_LENGTH]: ")"
    length="${length:-$DEFAULT_LENGTH}"
    entry_password="$(pwdman_random_password "$length")"
    printf '%s\n' "(Generated a $length-character random password.)" >&2
  fi

  encoded_password="$(pwdman_base64_encode "$entry_password")"
  database_buffer="$(pwdman_append_entry "$database_buffer" \
    "${encoded_username},${encoded_password},password")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  pwdman_copy_to_clipboard "$entry_password" "$CLIPBOARD_TIMEOUT"
  printf '%s\n' "Password successfully written."
}

pwdman_read_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer encoded_username password count

  pwdman_require_command gpg
  pwdman_require_command base64

  [[ -z "$username" ]] && username="$(pwdman_prompt "Username: ")"
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  encoded_username="$(pwdman_base64_encode "$username")"
  count="$(pwdman_count_entries "$database_buffer" "$encoded_username" "password")"

  [[ "$count" -eq 0 ]] && pwdman_exit "Error: username not found in the database."
  [[ "$count" -gt 1 ]] && printf '%s\n' "Warning: multiple exact entries found; using the first one." >&2

  password="$(pwdman_get_secret_by_username "$database_buffer" "$encoded_username" "password")"
  pwdman_copy_to_clipboard "$password" "$CLIPBOARD_TIMEOUT"
  printf '%s\n' "Password successfully read."
}

pwdman_update_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer entry_password length encoded_username encoded_password count

  pwdman_require_command gpg
  pwdman_require_command base64

  [[ -z "$username" ]] && username="$(pwdman_prompt "Username: ")"
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  encoded_username="$(pwdman_base64_encode "$username")"
  count="$(pwdman_count_entries "$database_buffer" "$encoded_username" "password")"

  [[ "$count" -eq 0 ]] && pwdman_exit "Error: username not found in the database."
  if [[ "$count" -gt 1 ]]; then
    printf '%s\n' "Warning: multiple exact entries found; replacing all with one." >&2
    pwdman_ask_continue 0
  fi

  entry_password="$(pwdman_prompt_secret "New password [leave blank to generate]: ")"
  if [[ -z "$entry_password" ]]; then
    length="$(pwdman_prompt "Random password length [$DEFAULT_LENGTH]: ")"
    length="${length:-$DEFAULT_LENGTH}"
    entry_password="$(pwdman_random_password "$length")"
    printf '%s\n' "(Generated a $length-character random password.)" >&2
  fi

  encoded_password="$(pwdman_base64_encode "$entry_password")"
  database_buffer="$(pwdman_remove_entry "$database_buffer" "$encoded_username" "password")"
  database_buffer="$(pwdman_append_entry "$database_buffer" \
    "${encoded_username},${encoded_password},password")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  pwdman_copy_to_clipboard "$entry_password" "$CLIPBOARD_TIMEOUT"
  printf '%s\n' "Entry successfully updated."
}

pwdman_delete_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer encoded_username count

  pwdman_require_command gpg
  pwdman_require_command base64

  [[ -z "$username" ]] && username="$(pwdman_prompt "Username: ")"
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  encoded_username="$(pwdman_base64_encode "$username")"
  count="$(pwdman_count_entries "$database_buffer" "$encoded_username" "password")"

  [[ "$count" -eq 0 ]] && pwdman_exit "Error: username not found in the database."
  if [[ "$count" -gt 1 ]]; then
    printf '%s\n' "Warning: multiple exact entries found; deleting all." >&2
    pwdman_ask_continue 0
  fi

  database_buffer="$(pwdman_remove_entry "$database_buffer" "$encoded_username" "password")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Entry successfully deleted."
}

# ---------------------------------------------------------------------------
# List / backup / import / reencrypt / create
# ---------------------------------------------------------------------------

pwdman_list() {
  local database="${1:-$DEFAULT_DATABASE}"
  local database_password database_buffer line username entry_type

  pwdman_require_command gpg
  pwdman_require_command base64

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  [[ -n "$database_buffer" ]] || pwdman_exit "Database is empty."

  printf '%s\n' "Database entries:"
  printf '  %-40s %s\n' "USERNAME" "TYPE"
  printf '  %-40s %s\n' "--------" "----"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    username="$(pwdman_base64_decode "${line%%,*}")"
    entry_type="${line##*,}"
    printf '  %-40s %s\n' "$username" "$entry_type"
  done <<< "$database_buffer"
}

pwdman_backup_database() {
  local database="${1:-$DEFAULT_DATABASE}"
  local backup_file="${2:-}"
  local database_password database_buffer

  pwdman_require_command gpg

  [[ -z "$backup_file" ]] && backup_file="$(pwdman_prompt "Backup filename: ")"
  [[ -n "$backup_file" ]] || pwdman_exit "Error: backup filename cannot be empty."

  # Warn BEFORE asking for password — avoids entering password then being told it exists
  if [[ -f "$backup_file" ]]; then
    printf '%s\n' "Warning: file already exists. Overwrite?" >&2
    pwdman_ask_continue 0
  fi

  printf '%s\n' "WARNING: the backup will NOT be encrypted. Store it securely." >&2
  pwdman_ask_continue 0

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  [[ -n "$database_buffer" ]] || pwdman_exit "Database is empty."

  {
    printf '%s\n' "Username,Password,Type"
    printf '%s\n' "$database_buffer"
  } > "$backup_file"
  chmod 600 "$backup_file"

  printf '%s\n' "Database successfully exported to: $backup_file"
}

pwdman_reencrypt_database() {
  local database="${1:-$DEFAULT_DATABASE}"
  local old_password new_password new_password_confirm database_buffer

  pwdman_require_command gpg

  old_password="$(pwdman_prompt_secret "Current database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$old_password")"

  new_password="$(pwdman_prompt_secret "New database password: ")"
  new_password_confirm="$(pwdman_prompt_secret "Confirm new database password: ")"
  [[ "$new_password" == "$new_password_confirm" ]] || \
    pwdman_exit "Error: passwords do not match."

  pwdman_encrypt_database "$database" "$new_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Database successfully reencrypted."
}

pwdman_create_database() {
  local database="${1:-}"
  local database_password database_password_confirm

  pwdman_require_command gpg

  if [[ -z "$database" ]]; then
    database="$(pwdman_prompt "Database path [$DEFAULT_DATABASE]: ")"
    database="${database:-$DEFAULT_DATABASE}"
  fi

  if [[ -f "$database" ]]; then
    printf '%s\n' "Warning: file already exists. Overwrite?" >&2
    pwdman_ask_continue 0
  fi

  database_password="$(pwdman_prompt_secret "New database password: ")"
  database_password_confirm="$(pwdman_prompt_secret "Confirm database password: ")"
  [[ "$database_password" == "$database_password_confirm" ]] || \
    pwdman_exit "Error: passwords do not match."

  pwdman_lock_database "$database" exclusive
  pwdman_encrypt_database "$database" "$database_password" ""
  pwdman_unlock_database

  printf '%s\n' "Database successfully created: $database"
}

pwdman_import_backup() {
  local database="${1:-$DEFAULT_DATABASE}"
  local backup_file="${2:-}"
  local database_password database_buffer import_buffer

  pwdman_require_command gpg

  [[ -z "$backup_file" ]] && backup_file="$(pwdman_prompt "Backup filename: ")"
  [[ -f "$backup_file" ]] || pwdman_exit "Error: backup file not found: $backup_file"

  local header
  header="$(head -n 1 "$backup_file")"
  # Accept both old (2-col) and new (3-col) backup headers
  [[ "$header" == "Username,Password" || "$header" == "Username,Password,Type" ]] || \
    pwdman_exit "Error: invalid backup file (unexpected header)."

  # For old-format backups, inject a default type column
  if [[ "$header" == "Username,Password" ]]; then
    import_buffer="$(tail -n +2 "$backup_file" | sed '/^[[:space:]]*$/d' | \
      awk -F',' '{print $1","$2",password"}')"
  else
    import_buffer="$(tail -n +2 "$backup_file" | sed '/^[[:space:]]*$/d')"
  fi

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_check_merge_conflicts "$database_buffer" "$import_buffer"
  database_buffer="$(pwdman_merge_buffers "$database_buffer" "$import_buffer")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Backup successfully imported."
}

pwdman_import_database() {
  local database="${1:-$DEFAULT_DATABASE}"
  local import_database="${2:-}"
  local database_password import_password database_buffer import_buffer

  pwdman_require_command gpg

  [[ -z "$import_database" ]] && import_database="$(pwdman_prompt "Import database path: ")"
  [[ -f "$import_database" ]] || pwdman_exit "Error: import database not found: $import_database"

  database_password="$(pwdman_prompt_secret "Current database password: ")"
  import_password="$(pwdman_prompt_secret "Import database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  import_buffer="$(pwdman_decrypt_database "$import_database" "$import_password")"
  pwdman_check_merge_conflicts "$database_buffer" "$import_buffer"
  database_buffer="$(pwdman_merge_buffers "$database_buffer" "$import_buffer")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Database successfully imported."
}

# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

pwdman_interactive() {
  local database="${1:-$DEFAULT_DATABASE}"
  local action

  printf '%s\n' "Interactive Mode — press h for help."
  IFS= read -r -n 1 -p "> " action || pwdman_exit "Error: failed to read action."
  printf '\n'

  case "$action" in
    h) pwdman_help ;;
    v) pwdman_version ;;
    r) pwdman_read_password "$database" ;;
    w) pwdman_write_password "$database" ;;
    u) pwdman_update_password "$database" ;;
    d) pwdman_delete_password "$database" ;;
    l) pwdman_list "$database" ;;
    b) pwdman_backup_database "$database" ;;
    x) pwdman_reencrypt_database "$database" ;;
    c) pwdman_create_database ;;
    m) pwdman_import_backup "$database" ;;
    n) pwdman_import_database "$database" ;;
    t) pwdman_totp_add "$database" ;;
    g) pwdman_totp_get "$database" ;;
    *) pwdman_exit "Error: invalid option. Press h for help." ;;
  esac
}

# ---------------------------------------------------------------------------
# Help / version
# ---------------------------------------------------------------------------

pwdman_version() {
  printf 'pwdman version %s\n' "$SCRIPT_VERSION"
}

pwdman_help() {
  pwdman_version
  cat <<'EOF'

Usage:
  pwdman.sh [command] [username] [database]

Password commands:
  -r, --read    <username> [db]   Copy a password to the clipboard.
  -w, --write   <username> [db]   Add a new password entry.
  -u, --update  <username> [db]   Update a password entry.
  -d, --delete  <username> [db]   Delete a password entry.
  -l, --list    [db]              List all entries (usernames + types).

TOTP commands:
  -t, --totp-add <username> [db]  Store a TOTP secret (Base32) for an account.
  -g, --totp-get <username> [db]  Compute and copy the current TOTP code.

Database commands:
  -c, --create  [db]              Create a new encrypted database.
  -x, --reencrypt [db]            Change the database master password.
  -b, --backup  <file> [db]       Export an unencrypted Base64 backup.
  -m, --import-plain <file> [db]  Import entries from a plain backup.
  -n, --import-enc <db2> [db]     Merge another encrypted database in.

Other:
  -i, --interactive [db]          Start interactive mode.
  -h, --help                      Show this help.
  -v, --version                   Show version.

Environment variables:
  DEFAULT_DATABASE    Path to the default database (default: ~/pwdman.db)
  CLIPBOARD_TIMEOUT   Seconds before clipboard is cleared (default: 7)
  DEFAULT_LENGTH      Default generated password length (default: 128)
  DEFAULT_ALPHABET    Characters used for generated passwords
EOF
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

pwdman_initialize() {
  pwdman_version
  printf '%s\n' "Welcome! No database found. Let's create one."
  pwdman_create_database "$DEFAULT_DATABASE"
}

pwdman_main() {
  local command="${1:-}"

  case "$command" in
    -h|--help|help)    pwdman_help;    return 0 ;;
    -v|--version|version) pwdman_version; return 0 ;;
  esac

  if [[ -z "$command" ]]; then
    if [[ ! -f "$DEFAULT_DATABASE" ]]; then
      pwdman_initialize
      return 0
    fi
    pwdman_exit "Please supply a command. Use --help for help."
  fi

  case "$command" in
    -i|--interactive|interactive) pwdman_interactive "${2:-}" ;;
    -r|--read|read)               pwdman_read_password    "${3:-}" "${2:-}" ;;
    -w|--write|write)             pwdman_write_password   "${3:-}" "${2:-}" ;;
    -u|--update|update)           pwdman_update_password  "${3:-}" "${2:-}" ;;
    -d|--delete|delete)           pwdman_delete_password  "${3:-}" "${2:-}" ;;
    -l|--list|list)               pwdman_list             "${2:-}" ;;
    -b|--backup|backup)           pwdman_backup_database  "${3:-}" "${2:-}" ;;
    -x|--reencrypt|reencrypt)     pwdman_reencrypt_database "${2:-}" ;;
    -c|--create|create)           pwdman_create_database  "${2:-}" ;;
    -m|--import-plain|import-plain) pwdman_import_backup  "${3:-}" "${2:-}" ;;
    -n|--import-enc|import-enc)   pwdman_import_database  "${3:-}" "${2:-}" ;;
    -t|--totp-add|totp-add)       pwdman_totp_add         "${3:-}" "${2:-}" ;;
    -g|--totp-get|totp-get)       pwdman_totp_get         "${3:-}" "${2:-}" ;;
    *) pwdman_exit "Unknown command: $command. Use --help for help." ;;
  esac
}

trap pwdman_unlock_database EXIT
pwdman_main "$@"
