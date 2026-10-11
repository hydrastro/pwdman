#!/usr/bin/env bash
# pwdman.sh — a GPG-encrypted password and one-time-code (TOTP/HOTP) manager
# Version 2.0
set -euo pipefail

umask 077
ulimit -c 0 2>/dev/null || true   # no core dumps: they would contain secrets

: "${DEFAULT_DATABASE:=${HOME}/pwdman.db}"
: "${CLIPBOARD_TIMEOUT:=7}"
: "${DEFAULT_LENGTH:=128}"
: "${DEFAULT_ALPHABET:=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#\$%^&*()_+=.,:;/-}"
# Pick entries with fzf when no name is given (1) or always ask (0).
: "${PWDMAN_FZF:=1}"
# For tests only: compute codes for this Unix time instead of now.
: "${PWDMAN_NOW:=}"

SCRIPT_VERSION="2.0"
PWDMAN_LOCK_FD=""
PWDMAN_CLIP_SECRET=""
HEADER="Username,Password,Type"

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

# Secrets only ever travel through pipes and bash builtins (printf, read),
# never as arguments of other programs: arguments are visible to every user
# in `ps` and /proc/*/cmdline.
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
    "") [[ "$default_yes" == "1" ]] && return 0; pwdman_exit "Aborting." ;;
    *) pwdman_exit "Aborting." ;;
  esac
}

# Lines of a buffer, through a pipe. (A here-string `<<<` can end up in a
# temporary file on disk when the buffer is large.)
pwdman_lines() {
  [[ -n "$1" ]] && printf '%s\n' "$1"
  return 0
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

# Symmetric AES-256; the passphrase goes through S2K mode 3 (iterated and
# salted SHA-512) with the maximum count, so every guess is expensive.
# The passphrase is given on file descriptor 3, never as an argument.
_pwdman_gpg() {
  gpg --batch --yes --quiet --no-greeting --pinentry-mode loopback \
    --no-symkey-cache --passphrase-fd 3 "$@"
}

_pwdman_gpg_decrypt_file() {
  local file="$1" password="$2"
  _pwdman_gpg --decrypt -- "$file" 3< <(printf '%s' "$password") 2>/dev/null
}

# The real file behind a link (e.g. ~/pwdman.db -> ~/private/pwdman.db), so
# saving replaces the file and not the link.
pwdman_real_path() {
  if command -v realpath >/dev/null 2>&1; then
    realpath -m -- "$1"
  else
    printf '%s' "$1"
  fi
}

pwdman_encrypt_database() {
  local database database_password="$2" database_buffer="${3:-}"
  local database_dir tmp_file data check

  database="$(pwdman_real_path "$1")"
  database_dir="$(dirname -- "$database")"
  mkdir -p -- "$database_dir"

  data="$HEADER"$'\n'
  [[ -n "$database_buffer" ]] && data+="$database_buffer"$'\n'

  tmp_file="$(mktemp "${database_dir}/.pwdman.XXXXXX")" || \
    pwdman_exit "Error: could not create temporary file."
  chmod 600 "$tmp_file"

  if ! printf '%s' "$data" | _pwdman_gpg --armor --symmetric \
      --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 \
      --s2k-count 65011712 --output "$tmp_file" \
      3< <(printf '%s' "$database_password"); then
    rm -f -- "$tmp_file"
    pwdman_exit "Error: database encryption error."
  fi

  # Read the new file back before it replaces the old one: a database that
  # can't be decrypted must never overwrite one that can.
  if ! check="$(_pwdman_gpg_decrypt_file "$tmp_file" "$database_password")" || \
     [[ "$check" != "${data%$'\n'}" ]]; then
    rm -f -- "$tmp_file"
    pwdman_exit "Error: the newly encrypted database did not verify; nothing was changed."
  fi

  sync -- "$tmp_file" 2>/dev/null || true
  mv -f -- "$tmp_file" "$database"
  chmod 600 "$database"
}

pwdman_decrypt_database() {
  local database="$1"
  local database_password="$2"
  local result line

  [[ -f "$database" ]] || pwdman_exit "Error: database not found: $database"

  if ! result="$(_pwdman_gpg_decrypt_file "$database" "$database_password")"; then
    pwdman_exit "Error: database decryption error. Wrong password?"
  fi

  # Skip the header line and blank lines; old 2-column rows get a type.
  local first=1
  while IFS= read -r line; do
    if (( first )); then first=0; continue; fi
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    [[ "$line" == *,*,* ]] || line+=",password"
    printf '%s\n' "$line"
  done < <(pwdman_lines "$result")
}

# ---------------------------------------------------------------------------
# Buffer helpers  (format: base64(name),base64(secret),type)
# type = password | totp | hotp
#   totp/hotp secrets are otpauth:// URIs (older entries: a bare Base32 key)
# ---------------------------------------------------------------------------

pwdman_validate_username() {
  local username="$1"
  [[ -n "$username" ]]         || pwdman_exit "Error: username cannot be empty."
  [[ "$username" != *$'\n'* ]] || pwdman_exit "Error: username cannot contain newlines."
}

pwdman_count_entries() {
  local database_buffer="$1"
  local encoded_username="$2"
  local entry_type="${3:-}"
  local line count=0 u t

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    u="${line%%,*}"
    t="${line##*,}"
    [[ "$u" == "$encoded_username" ]] || continue
    [[ -z "$entry_type" || "$t" == "$entry_type" ]] || continue
    count=$(( count + 1 ))
  done < <(pwdman_lines "$database_buffer")

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
  local line u s t rest

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    u="${line%%,*}"
    rest="${line#*,}"
    s="${rest%%,*}"
    t="${rest##*,}"
    [[ "$u" == "$encoded_username" ]] || continue
    [[ "$t" == "$entry_type" ]] || continue
    pwdman_base64_decode "$s"
    return 0
  done < <(pwdman_lines "$database_buffer")

  return 1
}

pwdman_remove_entry() {
  local database_buffer="$1"
  local encoded_username="$2"
  local entry_type="${3:-}"
  local line output="" u t

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    u="${line%%,*}"
    t="${line##*,}"
    if [[ "$u" == "$encoded_username" ]]; then
      [[ -z "$entry_type" || "$t" == "$entry_type" ]] && continue
    fi
    output+="$line"$'\n'
  done < <(pwdman_lines "$database_buffer")

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

# Every imported row must look like base64,base64,type.
pwdman_validate_buffer() {
  local buffer="$1" line n=0
  local b64='^[A-Za-z0-9+/]+={0,2}$'
  while IFS= read -r line; do
    n=$(( n + 1 ))
    [[ -n "$line" ]] || continue
    local u="${line%%,*}" rest="${line#*,}"
    local s="${rest%%,*}" t="${rest##*,}"
    [[ "$u" =~ $b64 && "$s" =~ $b64 ]] && [[ "$t" =~ ^(password|totp|hotp)$ ]] || \
      pwdman_exit "Error: line $n of the imported data is not a valid entry."
  done < <(pwdman_lines "$buffer")
}

pwdman_check_merge_conflicts() {
  local first_buffer="$1"
  local second_buffer="$2"
  local line

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    if pwdman_username_exists "$first_buffer" "${line%%,*}" "${line##*,}"; then
      printf '%s\n' "Warning: imported data contains an entry already present in the current database." >&2
      pwdman_ask_continue 0
      return 0
    fi
  done < <(pwdman_lines "$second_buffer")
}

# Names of the entries whose type matches TYPES (e.g. "password",
# "totp|hotp"; all if empty), decoded.
pwdman_entry_names() {
  local database_buffer="$1" types="${2:-}" line
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    [[ -z "$types" || "${line##*,}" =~ ^($types)$ ]] || continue
    pwdman_base64_decode "${line%%,*}"
    printf '\n'
  done < <(pwdman_lines "$database_buffer")
}

# ---------------------------------------------------------------------------
# Choosing an entry
# ---------------------------------------------------------------------------

# Can we show a fuzzy picker? (fzf installed, enabled, and on a terminal)
pwdman_can_pick() {
  [[ "$PWDMAN_FZF" == "1" ]] && command -v fzf >/dev/null 2>&1 && [[ -t 0 && -t 2 ]]
}

# Before decrypting: ask for the name, unless it was given or fzf will pick
# it from the decrypted list afterwards.
pwdman_username_first() {
  local username="$1" prompt="$2"
  if [[ -z "$username" ]] && ! pwdman_can_pick; then
    username="$(pwdman_prompt "$prompt")"
  fi
  [[ -z "$username" ]] || pwdman_validate_username "$username"
  printf '%s' "$username"
}

# After decrypting: the name, picked with fzf if still empty.
pwdman_username_pick() {
  local username="$1" database_buffer="$2" entry_type="$3" names
  if [[ -z "$username" ]]; then
    names="$(pwdman_entry_names "$database_buffer" "$entry_type" | sort -u)"
    [[ -n "$names" ]] || pwdman_exit "Error: no matching entries in the database."
    username="$(printf '%s\n' "$names" | fzf --height=40% --reverse --prompt='entry> ')" || \
      pwdman_exit "Aborting."
  fi
  pwdman_validate_username "$username"
  printf '%s' "$username"
}

# ---------------------------------------------------------------------------
# Random password
# ---------------------------------------------------------------------------

pwdman_random_password() {
  local length="${1:-$DEFAULT_LENGTH}"
  local alphabet="${2:-$DEFAULT_ALPHABET}"
  local alphabet_length max_usable password="" byte

  [[ "$length" =~ ^[1-9][0-9]*$ ]] || pwdman_exit "Error: invalid password length."
  alphabet_length="${#alphabet}"
  (( alphabet_length > 1 && alphabet_length <= 256 )) || \
    pwdman_exit "Error: alphabet length must be between 2 and 256."

  # Rejection sampling: bytes >= max_usable are thrown away, so every
  # character of the alphabet is exactly equally likely.
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

# Bits of entropy of a random password: length * log2(alphabet size)
pwdman_entropy_bits() {
  local length="$1" size="${2:-${#DEFAULT_ALPHABET}}" bits=0 n
  # integer log2 * 100, good enough for a hint
  n=$(( size * 100 ))
  while (( n >= 200 )); do n=$(( n / 2 )); bits=$(( bits + 100 )); done
  # linear interpolation for the fraction
  bits=$(( bits + (n - 100) ))
  printf '%d' $(( length * bits / 100 ))
}

# A new entry password: typed twice, or generated when left blank.
pwdman_new_entry_password() {
  local prompt="$1" entry_password confirm length
  entry_password="$(pwdman_prompt_secret "$prompt")"
  if [[ -z "$entry_password" ]]; then
    length="$(pwdman_prompt "Random password length [$DEFAULT_LENGTH]: ")"
    length="${length:-$DEFAULT_LENGTH}"
    entry_password="$(pwdman_random_password "$length")"
    printf '(Generated %d random characters, about %d bits.)\n' \
      "$length" "$(pwdman_entropy_bits "$length")" >&2
  else
    confirm="$(pwdman_prompt_secret "Repeat it: ")"
    [[ "$entry_password" == "$confirm" ]] || pwdman_exit "Error: passwords do not match."
  fi
  printf '%s' "$entry_password"
}

# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------

pwdman_clipboard_tool() {
  if [[ -n "${WAYLAND_DISPLAY:-}" ]] && command -v wl-copy >/dev/null 2>&1; then echo wl
  elif [[ -n "${DISPLAY:-}" ]] && command -v xclip >/dev/null 2>&1; then echo xclip
  elif [[ -n "${DISPLAY:-}" ]] && command -v xsel >/dev/null 2>&1; then echo xsel
  elif command -v pbcopy >/dev/null 2>&1; then echo pb
  else echo none
  fi
}

pwdman_clipboard_set() {
  case "$(pwdman_clipboard_tool)" in
    wl)    printf '%s' "$1" | wl-copy ;;
    xclip) printf '%s' "$1" | xclip -selection clipboard ;;
    xsel)  printf '%s' "$1" | xsel --clipboard --input ;;
    pb)    printf '%s' "$1" | pbcopy ;;
    *) pwdman_exit "Error: no clipboard (install xclip, xsel or wl-clipboard), or use --show." ;;
  esac
}

pwdman_clipboard_get() {
  case "$(pwdman_clipboard_tool)" in
    wl)    wl-paste --no-newline 2>/dev/null ;;
    xclip) xclip -o -selection clipboard 2>/dev/null ;;
    xsel)  xsel --clipboard --output 2>/dev/null ;;
    pb)    pbpaste 2>/dev/null ;;
  esac
  return 0
}

# Empty the clipboard, but only if it still holds our secret: whatever you
# copied in the meantime stays.
pwdman_clipboard_clear() {
  [[ -n "$PWDMAN_CLIP_SECRET" ]] || return 0
  if [[ "$(pwdman_clipboard_get)" == "$PWDMAN_CLIP_SECRET" ]]; then
    pwdman_clipboard_set ""
    printf '\nClipboard cleared.\n' >&2
  else
    printf '\nClipboard changed meanwhile; left as it is.\n' >&2
  fi
  PWDMAN_CLIP_SECRET=""
}

pwdman_copy_to_clipboard() {
  local secret="$1"
  local timeout="${2:-$CLIPBOARD_TIMEOUT}"
  [[ "$timeout" =~ ^[0-9]+$ ]] || pwdman_exit "Error: invalid clipboard timeout."
  pwdman_clipboard_set "$secret"
  PWDMAN_CLIP_SECRET="$secret"
  # Ctrl-C clears right away instead of leaving the secret behind.
  trap 'pwdman_clipboard_clear; exit 130' INT TERM
  while (( timeout > 0 )); do
    printf '\rCopied to clipboard. Clearing in %d s... ' "$timeout" >&2
    sleep 1
    timeout=$(( timeout - 1 ))
  done
  pwdman_clipboard_clear
  trap - INT TERM
}

# Fail early, before any prompt, if the secret couldn't be delivered.
pwdman_check_output() {
  [[ "${PWDMAN_SHOW:-0}" == "1" ]] && return 0
  [[ "$(pwdman_clipboard_tool)" != none ]] || \
    pwdman_exit "Error: no clipboard (install xclip, xsel or wl-clipboard), or use --show."
}

# --show prints to standard output instead (for pipes and scripts).
pwdman_output_secret() {
  local secret="$1" timeout="${2:-$CLIPBOARD_TIMEOUT}"
  if [[ "${PWDMAN_SHOW:-0}" == "1" ]]; then
    printf '%s\n' "$secret"
  else
    pwdman_copy_to_clipboard "$secret" "$timeout"
  fi
}

# ---------------------------------------------------------------------------
# One-time codes: HMAC, TOTP (RFC 6238), HOTP (RFC 4226)
# Pure bash and coreutils (sha1sum/sha256sum/sha512sum): the key never
# appears in a command line.
# ---------------------------------------------------------------------------

# hex string -> bytes on stdout
_pwdman_hex_to_bin() {
  local hex="$1" out="" i
  for (( i = 0; i < ${#hex}; i += 2 )); do out+="\\x${hex:i:2}"; done
  printf '%b' "$out"
}

# Base32 (RFC 4648, any case, padding and spaces ignored) -> hex
pwdman_base32_to_hex() {
  local input="${1^^}" alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  local buffer=0 bits=0 hex="" i char val rest
  input="${input//=/}"; input="${input//[[:space:]]/}"; input="${input//-/}"
  [[ -n "$input" ]] || return 1
  for (( i = 0; i < ${#input}; i++ )); do
    char="${input:i:1}"
    rest="${alphabet%%"$char"*}"
    [[ "$rest" != "$alphabet" ]] || return 1          # not a Base32 character
    val=${#rest}
    buffer=$(( (buffer << 5) | val )); bits=$(( bits + 5 ))
    if (( bits >= 8 )); then
      bits=$(( bits - 8 ))
      hex+="$(printf '%02x' $(( (buffer >> bits) & 0xff )))"
      buffer=$(( buffer & ((1 << bits) - 1) ))
    fi
  done
  [[ -n "$hex" ]] || return 1
  printf '%s' "$hex"
}

# HMAC(key, message) with SHA1 | SHA256 | SHA512; key, message, result in hex
pwdman_hmac() {
  local algo="$1" key="$2" msg="$3"
  local sum block i b ipad="" opad="" inner
  case "$algo" in
    SHA1)   sum=sha1sum;   block=64 ;;
    SHA256) sum=sha256sum; block=64 ;;
    SHA512) sum=sha512sum; block=128 ;;
    *) pwdman_exit "Error: unsupported algorithm: $algo" ;;
  esac
  pwdman_require_command "$sum"
  if (( ${#key} / 2 > block )); then
    key="$(_pwdman_hex_to_bin "$key" | "$sum")"; key="${key%% *}"
  fi
  while (( ${#key} < block * 2 )); do key+="00"; done
  for (( i = 0; i < block * 2; i += 2 )); do
    b=$(( 16#${key:i:2} ))
    ipad+="$(printf '%02x' $(( b ^ 0x36 )))"
    opad+="$(printf '%02x' $(( b ^ 0x5c )))"
  done
  inner="$({ _pwdman_hex_to_bin "$ipad"; _pwdman_hex_to_bin "$msg"; } | "$sum")"
  inner="${inner%% *}"
  { _pwdman_hex_to_bin "$opad"; _pwdman_hex_to_bin "$inner"; } | "$sum" | { read -r h _; printf '%s' "$h"; }
}

# HOTP value: key (hex), counter, digits, algorithm
pwdman_hotp() {
  local key="$1" counter="$2" digits="$3" algo="$4" mac offset code modulo=1 i
  mac="$(pwdman_hmac "$algo" "$key" "$(printf '%016x' "$counter")")"
  offset=$(( 16#${mac: -1} ))
  code=$(( 16#${mac:offset*2:8} & 0x7fffffff ))
  for (( i = 0; i < digits; i++ )); do modulo=$(( modulo * 10 )); done
  printf "%0${digits}d" $(( code % modulo ))
}

# ---------------------------------------------------------------------------
# otpauth:// URIs
#   otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer
#             &algorithm=SHA1&digits=6&period=30
#   otpauth://hotp/...?secret=BASE32&counter=0
# Parsed into the OTP_* variables.
# ---------------------------------------------------------------------------

pwdman_urldecode() {
  local s="${1//+/ }"
  printf '%b' "${s//%/\\x}"
}

pwdman_urlencode() {
  local LC_ALL=C                      # walk bytes, so UTF-8 is encoded right
  local s="$1" out="" c i
  for (( i = 0; i < ${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [A-Za-z0-9._~-]) out+="$c" ;;
      *) out+="$(printf '%%%02X' "'$c")" ;;
    esac
  done
  printf '%s' "$out"
}

pwdman_parse_otp() {
  local input="$1" rest label query param key val
  OTP_TYPE=totp OTP_SECRET="" OTP_ISSUER="" OTP_ACCOUNT=""
  OTP_ALGORITHM=SHA1 OTP_DIGITS=6 OTP_PERIOD=30 OTP_COUNTER=0

  if [[ "$input" == otpauth://* ]]; then
    rest="${input#otpauth://}"
    OTP_TYPE="${rest%%/*}"
    OTP_TYPE="${OTP_TYPE,,}"
    [[ "$OTP_TYPE" == totp || "$OTP_TYPE" == hotp ]] || \
      pwdman_exit "Error: unsupported otpauth type: $OTP_TYPE"
    rest="${rest#*/}"
    label="$(pwdman_urldecode "${rest%%\?*}")"
    query=""; [[ "$rest" == *\?* ]] && query="${rest#*\?}"
    if [[ "$label" == *:* ]]; then
      OTP_ISSUER="${label%%:*}"; OTP_ACCOUNT="${label#*:}"
      OTP_ACCOUNT="${OTP_ACCOUNT# }"
    else
      OTP_ACCOUNT="$label"
    fi
    while IFS= read -r -d '&' param; do
      [[ -n "$param" ]] || continue
      key="${param%%=*}"; val="$(pwdman_urldecode "${param#*=}")"
      case "${key,,}" in
        secret)    OTP_SECRET="$val" ;;
        issuer)    OTP_ISSUER="$val" ;;
        algorithm) OTP_ALGORITHM="${val^^}" ;;
        digits)    OTP_DIGITS="$val" ;;
        period)    OTP_PERIOD="$val" ;;
        counter)   OTP_COUNTER="$val" ;;
      esac
    done < <(printf '%s&' "$query")
  else
    OTP_SECRET="$input"                         # a bare Base32 key
  fi

  OTP_SECRET="${OTP_SECRET^^}"
  OTP_SECRET="${OTP_SECRET//[[:space:]=-]/}"
  pwdman_base32_to_hex "$OTP_SECRET" >/dev/null || \
    pwdman_exit "Error: the secret is not valid Base32."
  [[ "$OTP_ALGORITHM" =~ ^SHA(1|256|512)$ ]] || \
    pwdman_exit "Error: unsupported algorithm: $OTP_ALGORITHM"
  [[ "$OTP_DIGITS" =~ ^(6|7|8|9|10)$ ]] || pwdman_exit "Error: digits must be 6 to 10."
  [[ "$OTP_PERIOD" =~ ^[1-9][0-9]*$ ]] || pwdman_exit "Error: invalid period."
  [[ "$OTP_COUNTER" =~ ^[0-9]+$ ]] || pwdman_exit "Error: invalid counter."
}

pwdman_build_otp_uri() {
  local label="$OTP_ACCOUNT" uri
  [[ -n "$OTP_ISSUER" ]] && label="$OTP_ISSUER:$OTP_ACCOUNT"
  uri="otpauth://$OTP_TYPE/$(pwdman_urlencode "$label")?secret=$OTP_SECRET"
  [[ -n "$OTP_ISSUER" ]] && uri+="&issuer=$(pwdman_urlencode "$OTP_ISSUER")"
  uri+="&algorithm=$OTP_ALGORITHM&digits=$OTP_DIGITS"
  if [[ "$OTP_TYPE" == hotp ]]; then
    uri+="&counter=$OTP_COUNTER"
  else
    uri+="&period=$OTP_PERIOD"
  fi
  printf '%s' "$uri"
}

# The current code for the parsed OTP_* entry
pwdman_otp_code() {
  local key now
  key="$(pwdman_base32_to_hex "$OTP_SECRET")"
  if [[ "$OTP_TYPE" == hotp ]]; then
    pwdman_hotp "$key" "$OTP_COUNTER" "$OTP_DIGITS" "$OTP_ALGORITHM"
  else
    now="${PWDMAN_NOW:-$(date +%s)}"
    pwdman_hotp "$key" $(( now / OTP_PERIOD )) "$OTP_DIGITS" "$OTP_ALGORITHM"
  fi
}

# Read a QR code image (zbarimg) and print the otpauth:// URI in it.
pwdman_read_qr() {
  local image="$1" text
  pwdman_require_command zbarimg
  text="$(zbarimg --quiet --raw -- "$image" 2>/dev/null)" || \
    pwdman_exit "Error: no QR code found in $image"
  [[ "$text" == otpauth://* ]] || \
    pwdman_exit "Error: the QR code is not an otpauth:// URI (Google Authenticator exports are not supported)."
  printf '%s' "$text"
}

# ---------------------------------------------------------------------------
# One-time code commands
# ---------------------------------------------------------------------------

pwdman_otp_add() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer encoded_username raw_input uri

  pwdman_require_command gpg
  pwdman_require_command base64

  [[ -z "$username" ]] && username="$(pwdman_prompt "Account (name of the entry): ")"
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  encoded_username="$(pwdman_base64_encode "$username")"
  if pwdman_username_exists "$database_buffer" "$encoded_username" totp || \
     pwdman_username_exists "$database_buffer" "$encoded_username" hotp; then
    printf '%s\n' "Warning: a one-time-code entry for this account already exists; it will be replaced." >&2
    pwdman_ask_continue 0
    database_buffer="$(pwdman_remove_entry "$database_buffer" "$encoded_username" totp)"
    database_buffer="$(pwdman_remove_entry "$database_buffer" "$encoded_username" hotp)"
  fi

  raw_input="$(pwdman_prompt_secret "Secret (Base32), otpauth:// URI, or QR code image file: ")"
  [[ -n "$raw_input" ]] || pwdman_exit "Error: input cannot be empty."
  if [[ "$raw_input" != otpauth://* && -f "$raw_input" ]]; then
    raw_input="$(pwdman_read_qr "$raw_input")"
  fi

  pwdman_parse_otp "$raw_input"
  [[ -n "$OTP_ACCOUNT" ]] || OTP_ACCOUNT="$username"
  uri="$(pwdman_build_otp_uri)"

  printf 'Type %s, %s, %s digits' "${OTP_TYPE^^}" "$OTP_ALGORITHM" "$OTP_DIGITS" >&2
  if [[ "$OTP_TYPE" == hotp ]]; then printf ', counter %s' "$OTP_COUNTER" >&2
  else printf ', every %s s' "$OTP_PERIOD" >&2; fi
  [[ -n "$OTP_ISSUER" ]] && printf ' (%s)' "$OTP_ISSUER" >&2
  printf '\n' >&2

  database_buffer="$(pwdman_append_entry "$database_buffer" \
    "${encoded_username},$(pwdman_base64_encode "$uri"),$OTP_TYPE")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "One-time-code secret stored for: $username"
}

pwdman_otp_get() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer encoded_username secret code
  local entry_type="" remaining timeout

  pwdman_require_command gpg
  pwdman_require_command base64
  pwdman_check_output

  username="$(pwdman_username_first "$username" "Account: ")"
  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  username="$(pwdman_username_pick "$username" "$database_buffer" "totp|hotp")"
  encoded_username="$(pwdman_base64_encode "$username")"
  for entry_type in totp hotp; do
    pwdman_username_exists "$database_buffer" "$encoded_username" "$entry_type" && break
    entry_type=""
  done
  [[ -n "$entry_type" ]] || pwdman_exit "Error: no one-time-code entry found for: $username"

  secret="$(pwdman_get_secret_by_username "$database_buffer" "$encoded_username" "$entry_type")"
  pwdman_parse_otp "$secret"

  if [[ "$OTP_TYPE" == hotp ]]; then
    # Counter-based: use the next value and save the counter.
    code="$(pwdman_otp_code)"
    OTP_COUNTER=$(( OTP_COUNTER + 1 ))
    pwdman_lock_database "$database" exclusive
    database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
    database_buffer="$(pwdman_remove_entry "$database_buffer" "$encoded_username" hotp)"
    database_buffer="$(pwdman_append_entry "$database_buffer" \
      "${encoded_username},$(pwdman_base64_encode "$(pwdman_build_otp_uri)"),hotp")"
    pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
    pwdman_unlock_database
    timeout="$CLIPBOARD_TIMEOUT"
    printf 'HOTP code for %s (counter now %s): ' "$username" "$OTP_COUNTER" >&2
  else
    remaining=$(( OTP_PERIOD - ${PWDMAN_NOW:-$(date +%s)} % OTP_PERIOD ))
    if (( remaining < 5 )); then          # about to expire: wait for the next one
      printf 'Next code in %d s...\n' "$remaining" >&2
      sleep "$remaining"
      remaining="$OTP_PERIOD"
    fi
    code="$(pwdman_otp_code)"
    timeout=$(( CLIPBOARD_TIMEOUT > remaining ? remaining : CLIPBOARD_TIMEOUT ))
    (( timeout > 0 )) || timeout=1
    printf 'TOTP code for %s (valid %d s more): ' "$username" "$remaining" >&2
  fi

  if [[ "${PWDMAN_SHOW:-0}" == "1" ]]; then
    printf '%s\n' "$code"
  else
    printf '%s\n' "$code" >&2
    pwdman_copy_to_clipboard "$code" "$timeout"
  fi
}

# Show an entry's otpauth:// URI (and a QR code if qrencode is there), to
# move it to a phone or another app.
pwdman_otp_export() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer encoded_username secret entry_type uri

  username="$(pwdman_username_first "$username" "Account: ")"
  database_password="$(pwdman_prompt_secret "Database password: ")"
  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database
  username="$(pwdman_username_pick "$username" "$database_buffer" "totp|hotp")"

  encoded_username="$(pwdman_base64_encode "$username")"
  for entry_type in totp hotp; do
    secret="$(pwdman_get_secret_by_username "$database_buffer" "$encoded_username" "$entry_type")" && break
    secret=""
  done
  [[ -n "$secret" ]] || pwdman_exit "Error: no one-time-code entry found for: $username"
  pwdman_parse_otp "$secret"
  [[ -n "$OTP_ACCOUNT" ]] || OTP_ACCOUNT="$username"
  uri="$(pwdman_build_otp_uri)"

  printf '%s\n' "This shows the secret on screen." >&2
  pwdman_ask_continue 0
  printf '%s\n' "$uri"
  if command -v qrencode >/dev/null 2>&1 && [[ -t 1 ]]; then
    printf '%s' "$uri" | qrencode -t ansiutf8
  fi
}

# ---------------------------------------------------------------------------
# Password commands
# ---------------------------------------------------------------------------

pwdman_write_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer entry_password encoded_username

  pwdman_require_command gpg
  pwdman_require_command base64
  pwdman_check_output

  [[ -z "$username" ]] && username="$(pwdman_prompt "Username: ")"
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  encoded_username="$(pwdman_base64_encode "$username")"
  if pwdman_username_exists "$database_buffer" "$encoded_username" password; then
    printf '%s\n' "Warning: this username already exists; its password will be replaced." >&2
    pwdman_ask_continue 0
    database_buffer="$(pwdman_remove_entry "$database_buffer" "$encoded_username" password)"
  fi

  entry_password="$(pwdman_new_entry_password "Entry password [leave blank to generate]: ")"

  database_buffer="$(pwdman_append_entry "$database_buffer" \
    "${encoded_username},$(pwdman_base64_encode "$entry_password"),password")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Password successfully written." >&2
  pwdman_output_secret "$entry_password"
}

pwdman_read_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer encoded_username password count

  pwdman_require_command gpg
  pwdman_require_command base64
  pwdman_check_output

  username="$(pwdman_username_first "$username" "Username: ")"
  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  username="$(pwdman_username_pick "$username" "$database_buffer" password)"
  encoded_username="$(pwdman_base64_encode "$username")"
  count="$(pwdman_count_entries "$database_buffer" "$encoded_username" password)"

  [[ "$count" -eq 0 ]] && pwdman_exit "Error: username not found in the database."
  [[ "$count" -gt 1 ]] && printf '%s\n' "Warning: multiple entries found; using the first one." >&2

  password="$(pwdman_get_secret_by_username "$database_buffer" "$encoded_username" password)"
  pwdman_output_secret "$password"
}

pwdman_update_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer entry_password encoded_username count

  pwdman_require_command gpg
  pwdman_require_command base64
  pwdman_check_output

  username="$(pwdman_username_first "$username" "Username: ")"
  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  username="$(pwdman_username_pick "$username" "$database_buffer" password)"
  encoded_username="$(pwdman_base64_encode "$username")"
  count="$(pwdman_count_entries "$database_buffer" "$encoded_username" password)"

  [[ "$count" -eq 0 ]] && pwdman_exit "Error: username not found in the database."
  if [[ "$count" -gt 1 ]]; then
    printf '%s\n' "Warning: multiple entries found; replacing all with one." >&2
    pwdman_ask_continue 0
  fi

  entry_password="$(pwdman_new_entry_password "New password [leave blank to generate]: ")"

  database_buffer="$(pwdman_remove_entry "$database_buffer" "$encoded_username" password)"
  database_buffer="$(pwdman_append_entry "$database_buffer" \
    "${encoded_username},$(pwdman_base64_encode "$entry_password"),password")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Entry successfully updated." >&2
  pwdman_output_secret "$entry_password"
}

pwdman_delete_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password database_buffer encoded_username count types=""

  pwdman_require_command gpg
  pwdman_require_command base64

  username="$(pwdman_username_first "$username" "Username: ")"
  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  username="$(pwdman_username_pick "$username" "$database_buffer" "")"
  encoded_username="$(pwdman_base64_encode "$username")"
  count="$(pwdman_count_entries "$database_buffer" "$encoded_username")"
  [[ "$count" -eq 0 ]] && pwdman_exit "Error: username not found in the database."

  # A name can have a password and a one-time code: ask which to delete.
  local t choice
  for t in password totp hotp; do
    pwdman_username_exists "$database_buffer" "$encoded_username" "$t" && types+=" $t"
  done
  types="${types# }"
  if [[ "$types" == *" "* ]]; then
    choice="$(pwdman_prompt "\"$username\" has: $types. Delete [p]assword, [o]ne-time code or [b]oth? ")"
    case "$choice" in
      p) types=password ;;
      o) types="totp hotp" ;;
      b) ;;
      *) pwdman_exit "Aborting." ;;
    esac
  fi
  printf 'Delete "%s" (%s)?\n' "$username" "$types" >&2
  pwdman_ask_continue 0

  for t in $types; do
    database_buffer="$(pwdman_remove_entry "$database_buffer" "$encoded_username" "$t")"
  done
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Entry successfully deleted."
}

# ---------------------------------------------------------------------------
# List / backup / import / reencrypt / create / generate
# ---------------------------------------------------------------------------

pwdman_list() {
  local database="${1:-$DEFAULT_DATABASE}"
  local database_password database_buffer line

  pwdman_require_command gpg
  pwdman_require_command base64

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  [[ -n "$database_buffer" ]] || pwdman_exit "Database is empty."

  printf '  %-40s %s\n' "NAME" "TYPE"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    printf '  %-40s %s\n' "$(pwdman_base64_decode "${line%%,*}")" "${line##*,}"
  done < <(pwdman_lines "$database_buffer") | sort
}

pwdman_backup_database() {
  local database="${1:-$DEFAULT_DATABASE}"
  local backup_file="${2:-}"
  local database_password database_buffer

  pwdman_require_command gpg

  [[ -z "$backup_file" ]] && backup_file="$(pwdman_prompt "Backup filename: ")"
  [[ -n "$backup_file" ]] || pwdman_exit "Error: backup filename cannot be empty."

  if [[ -e "$backup_file" ]]; then
    printf '%s\n' "Warning: file already exists. Overwrite?" >&2
    pwdman_ask_continue 0
  fi

  printf '%s\n' "WARNING: the backup will NOT be encrypted (Base64 is not encryption)." >&2
  printf '%s\n' "For an encrypted backup, just copy the database file itself." >&2
  pwdman_ask_continue 0

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  [[ -n "$database_buffer" ]] || pwdman_exit "Database is empty."

  ( umask 077; { printf '%s\n' "$HEADER"; printf '%s\n' "$database_buffer"; } > "$backup_file" )
  chmod 600 "$backup_file"

  printf '%s\n' "Database successfully exported to: $backup_file"
}

pwdman_check_master_password() {
  local password="$1"
  (( ${#password} >= 12 )) && return 0
  printf '%s\n' "Warning: this database password is short (${#password} characters)." >&2
  printf '%s\n' "Everything in the database is only as safe as this password; 5+ random words is good." >&2
  pwdman_ask_continue 0
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
  pwdman_check_master_password "$new_password"

  pwdman_encrypt_database "$database" "$new_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Database successfully reencrypted."
  printf '%s\n' "Note: old copies (backups, git history) still open with the old password." >&2
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
  pwdman_check_master_password "$database_password"

  pwdman_lock_database "$database" exclusive
  pwdman_encrypt_database "$database" "$database_password" ""
  pwdman_unlock_database

  printf '%s\n' "Database successfully created: $database"
}

pwdman_import_backup() {
  local database="${1:-$DEFAULT_DATABASE}"
  local backup_file="${2:-}"
  local database_password database_buffer import_buffer header

  pwdman_require_command gpg

  [[ -z "$backup_file" ]] && backup_file="$(pwdman_prompt "Backup filename: ")"
  [[ -f "$backup_file" ]] || pwdman_exit "Error: backup file not found: $backup_file"

  header="$(head -n 1 -- "$backup_file")"
  [[ "$header" == "Username,Password" || "$header" == "$HEADER" ]] || \
    pwdman_exit "Error: invalid backup file (unexpected header)."

  import_buffer="$(tail -n +2 -- "$backup_file" | while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    [[ "$line" == *,*,* ]] || line+=",password"     # old 2-column backups
    printf '%s\n' "$line"
  done)"
  pwdman_validate_buffer "$import_buffer"

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
  pwdman_validate_buffer "$import_buffer"
  pwdman_check_merge_conflicts "$database_buffer" "$import_buffer"
  database_buffer="$(pwdman_merge_buffers "$database_buffer" "$import_buffer")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Database successfully imported."
}

pwdman_generate() {
  local length="${1:-$DEFAULT_LENGTH}" password
  pwdman_check_output
  password="$(pwdman_random_password "$length")"
  printf '(%d random characters, about %d bits.)\n' \
    "$length" "$(pwdman_entropy_bits "$length")" >&2
  pwdman_output_secret "$password"
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
    t) pwdman_otp_add "$database" ;;
    g) pwdman_otp_get "$database" ;;
    e) pwdman_otp_export "$database" ;;
    G) pwdman_generate ;;
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
  pwdman.sh [--show] command [name] [database]

Leave out the name to pick the entry from a list (needs fzf).

Passwords:
  -r, --read     [name] [db]      Copy a password to the clipboard.
  -w, --write    [name] [db]      Add a password (typed twice, or generated).
  -u, --update   [name] [db]      Change a password.
  -d, --delete   [name] [db]      Delete an entry (password and one-time code).
  -l, --list     [db]             List all entries and their types.
  -G, --generate [length]         Just make a random password.

One-time codes (2FA):
  -t, --otp-add    <name> [db]    Store a TOTP/HOTP secret: Base32 key,
                                  otpauth:// URI, or QR code image (zbarimg).
  -g, --otp-get    [name] [db]    Copy the current code (HOTP: the next one).
  -e, --otp-export [name] [db]    Show the otpauth:// URI and a QR code
                                  (qrencode), to move it to another app.

Database:
  -c, --create   [db]             Create a new encrypted database.
  -x, --reencrypt [db]            Change the database password.
  -b, --backup   <file> [db]      Export an UNENCRYPTED Base64 backup.
  -m, --import-plain <file> [db]  Import entries from a plain backup.
  -n, --import-enc <db2> [db]     Merge another encrypted database in.

Other:
  -s, --show                      Print secrets to standard output instead
                                  of the clipboard (put it first).
  -i, --interactive [db]          Start interactive mode.
  -h, --help                      Show this help.
  -v, --version                   Show version.

Environment variables:
  DEFAULT_DATABASE    Path to the default database (default: ~/pwdman.db)
  CLIPBOARD_TIMEOUT   Seconds before the clipboard is cleared (default: 7)
  DEFAULT_LENGTH      Default generated password length (default: 128)
  DEFAULT_ALPHABET    Characters used for generated passwords
  PWDMAN_FZF          1: pick entries with fzf when no name is given (default)
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
  if [[ "${1:-}" == -s || "${1:-}" == --show ]]; then
    PWDMAN_SHOW=1
    shift
  fi
  local command="${1:-}"

  case "$command" in
    -h|--help|help)       pwdman_help;    return 0 ;;
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
    -i|--interactive|interactive)   pwdman_interactive "${2:-}" ;;
    -r|--read|read)                 pwdman_read_password    "${3:-}" "${2:-}" ;;
    -w|--write|write)               pwdman_write_password   "${3:-}" "${2:-}" ;;
    -u|--update|update)             pwdman_update_password  "${3:-}" "${2:-}" ;;
    -d|--delete|delete)             pwdman_delete_password  "${3:-}" "${2:-}" ;;
    -l|--list|list)                 pwdman_list             "${2:-}" ;;
    -G|--generate|generate)         pwdman_generate         "${2:-}" ;;
    -b|--backup|backup)             pwdman_backup_database  "${3:-}" "${2:-}" ;;
    -x|--reencrypt|reencrypt)       pwdman_reencrypt_database "${2:-}" ;;
    -c|--create|create)             pwdman_create_database  "${2:-}" ;;
    -m|--import-plain|import-plain) pwdman_import_backup    "${3:-}" "${2:-}" ;;
    -n|--import-enc|import-enc)     pwdman_import_database  "${3:-}" "${2:-}" ;;
    -t|--otp-add|otp-add|--totp-add|totp-add) pwdman_otp_add "${3:-}" "${2:-}" ;;
    -g|--otp-get|otp-get|--totp-get|totp-get) pwdman_otp_get "${3:-}" "${2:-}" ;;
    -e|--otp-export|otp-export)     pwdman_otp_export       "${3:-}" "${2:-}" ;;
    *) pwdman_exit "Unknown command: $command. Use --help for help." ;;
  esac
}

trap pwdman_unlock_database EXIT
pwdman_main "$@"
