#!/usr/bin/env bash
set -euo pipefail

umask 077

: "${DEFAULT_DATABASE:=${HOME}/pwdman.db}"
: "${CLIPBOARD_TIMEOUT:=7}"
: "${DEFAULT_LENGTH:=128}"
: "${DEFAULT_ALPHABET:=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+=.,:;/-}"

SCRIPT_VERSION="1.1"
PWDMAN_LOCK_FD=""

pwdman_exit() {
  local message="${1:-Error: undefined error.}"
  printf '%s\n' "$message" >&2
  exit 1
}

pwdman_require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 || \
    pwdman_exit "Error: required command not found: $command_name"
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

  if [[ "$default_yes" == "1" ]]; then
    prompt="Continue [Y/n]? "
  fi

  answer="$(pwdman_prompt "$prompt")"

  case "$answer" in
    [Yy]) return 0 ;;
    [Nn]) pwdman_exit "Aborting." ;;
    "")
      if [[ "$default_yes" == "1" ]]; then
        return 0
      fi
      pwdman_exit "Aborting."
      ;;
    *) pwdman_exit "Aborting." ;;
  esac
}

pwdman_lock_database() {
  local database="$1"
  local mode="$2"
  local lock_file="${database}.lock"
  local database_dir=""

  command -v flock >/dev/null 2>&1 || return 0

  database_dir="$(dirname -- "$database")"
  mkdir -p -- "$database_dir"

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
    if command -v flock >/dev/null 2>&1; then
      flock -u "$PWDMAN_LOCK_FD" || true
    fi
    exec {PWDMAN_LOCK_FD}>&-
    PWDMAN_LOCK_FD=""
  fi
}

pwdman_encrypt_database() {
  local database="$1"
  local database_password="$2"
  local database_buffer="${3:-}"
  local database_dir=""
  local tmp_file=""
  local data="Username,Password"
  local gpg_options=()

  database_dir="$(dirname -- "$database")"
  mkdir -p -- "$database_dir"

  if [[ -n "$database_buffer" ]]; then
    data+=$'\n'"$database_buffer"
  fi
  data+=$'\n'

  tmp_file="$(mktemp "${database_dir}/.pwdman.XXXXXX")" || \
    pwdman_exit "Error: could not create temporary database file."
  chmod 600 "$tmp_file"

  gpg_options=(
    --armor
    --batch
    --yes
    --pinentry-mode loopback
    --symmetric
    --passphrase-fd 3
    --no-symkey-cache
    --cipher-algo AES256
    --output "$tmp_file"
  )

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
  local result=""
  local gpg_options=()

  [[ -f "$database" ]] || pwdman_exit "Error: database not found: $database"

  gpg_options=(
    --batch
    --yes
    --pinentry-mode loopback
    --passphrase-fd 3
    --no-symkey-cache
    --decrypt
  )

  if ! result="$(gpg "${gpg_options[@]}" -- "$database" 3< <(printf '%s' "$database_password") 2>/dev/null)"; then
    pwdman_exit "Error: database decryption error."
  fi

  printf '%s' "$result" | tail -n +2 | sed '/^$/d'
}

pwdman_validate_username() {
  local username="$1"

  [[ -n "$username" ]] || pwdman_exit "Error: username cannot be empty."
  [[ "$username" != *$'\n'* ]] || pwdman_exit "Error: username cannot contain newlines."
}

pwdman_count_username() {
  local database_buffer="$1"
  local encoded_username="$2"
  local line=""
  local count=0

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    if [[ "${line%%,*}" == "$encoded_username" ]]; then
      ((count += 1))
    fi
  done <<< "$database_buffer"

  printf '%s\n' "$count"
}

pwdman_username_exists() {
  local database_buffer="$1"
  local encoded_username="$2"
  local count=""

  count="$(pwdman_count_username "$database_buffer" "$encoded_username")"
  [[ "$count" -gt 0 ]]
}

pwdman_get_password_by_username() {
  local database_buffer="$1"
  local encoded_username="$2"
  local line=""
  local encoded_password=""

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    if [[ "${line%%,*}" == "$encoded_username" ]]; then
      encoded_password="${line#*,}"
      pwdman_base64_decode "$encoded_password"
      return 0
    fi
  done <<< "$database_buffer"

  return 1
}

pwdman_remove_username() {
  local database_buffer="$1"
  local encoded_username="$2"
  local line=""
  local output=""

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    [[ "${line%%,*}" == "$encoded_username" ]] && continue
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
  local first_buffer="$1"
  local second_buffer="$2"

  if [[ -n "$first_buffer" && -n "$second_buffer" ]]; then
    printf '%s\n%s' "$first_buffer" "$second_buffer"
  elif [[ -n "$first_buffer" ]]; then
    printf '%s' "$first_buffer"
  else
    printf '%s' "$second_buffer"
  fi
}

pwdman_check_merge_conflicts() {
  local first_buffer="$1"
  local second_buffer="$2"
  local line=""
  local encoded_username=""

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

pwdman_random_password() {
  local length="${1:-$DEFAULT_LENGTH}"
  local alphabet="${2:-$DEFAULT_ALPHABET}"
  local alphabet_length=0
  local max_usable=0
  local byte=""
  local password=""

  [[ "$length" =~ ^[1-9][0-9]*$ ]] || pwdman_exit "Error: invalid password length."

  alphabet_length="${#alphabet}"
  ((alphabet_length > 0 && alphabet_length <= 256)) || \
    pwdman_exit "Error: alphabet length must be between 1 and 256 characters."

  max_usable=$((256 / alphabet_length * alphabet_length))

  while ((${#password} < length)); do
    while IFS= read -r byte; do
      [[ -n "$byte" ]] || continue
      ((byte < max_usable)) || continue
      password+="${alphabet:byte % alphabet_length:1}"
      ((${#password} >= length)) && break
    done < <(od -An -vtu1 -N 4096 /dev/urandom | tr -s ' ' '\n')
  done

  printf '%s' "$password"
}

pwdman_clipboard_set() {
  local value="$1"

  if command -v wl-copy >/dev/null 2>&1; then
    printf '%s' "$value" | wl-copy
  elif command -v xclip >/dev/null 2>&1; then
    printf '%s' "$value" | xclip -selection clipboard
  elif command -v pbcopy >/dev/null 2>&1; then
    printf '%s' "$value" | pbcopy
  else
    pwdman_exit "Error: no supported clipboard command found. Install xclip, wl-copy, or pbcopy."
  fi
}

pwdman_copy_to_clipboard() {
  local secret="$1"
  local timeout="${2:-$CLIPBOARD_TIMEOUT}"

  [[ "$timeout" =~ ^[0-9]+$ ]] || pwdman_exit "Error: invalid clipboard timeout."

  pwdman_clipboard_set "$secret"

  while ((timeout > 0)); do
    printf '\rPassword on clipboard! Clearing clipboard in %d ' "$timeout" >&2
    sleep 1
    ((timeout -= 1))
  done

  printf '\nClipboard cleared.\n' >&2
  pwdman_clipboard_set ""
}

pwdman_write_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password=""
  local database_buffer=""
  local entry_password=""
  local length=""
  local encoded_username=""
  local encoded_password=""

  pwdman_require_command gpg
  pwdman_require_command base64

  if [[ -z "$username" ]]; then
    username="$(pwdman_prompt "Username: ")"
  fi
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  encoded_username="$(pwdman_base64_encode "$username")"
  if pwdman_username_exists "$database_buffer" "$encoded_username"; then
    printf '%s\n' "Warning: this username already exists in the database." >&2
    pwdman_ask_continue 0
  fi

  entry_password="$(pwdman_prompt_secret "Entry password [random]: ")"
  if [[ -z "$entry_password" ]]; then
    length="$(pwdman_prompt "Random password length [$DEFAULT_LENGTH]: ")"
    length="${length:-$DEFAULT_LENGTH}"
    entry_password="$(pwdman_random_password "$length")"
  fi

  encoded_password="$(pwdman_base64_encode "$entry_password")"
  database_buffer="$(pwdman_append_entry "$database_buffer" "$encoded_username,$encoded_password")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  pwdman_copy_to_clipboard "$entry_password" "$CLIPBOARD_TIMEOUT"
  printf '%s\n' "Password successfully written."
}

pwdman_read_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password=""
  local database_buffer=""
  local encoded_username=""
  local password=""
  local count=""

  pwdman_require_command gpg
  pwdman_require_command base64

  if [[ -z "$username" ]]; then
    username="$(pwdman_prompt "Username: ")"
  fi
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  encoded_username="$(pwdman_base64_encode "$username")"
  count="$(pwdman_count_username "$database_buffer" "$encoded_username")"

  if [[ "$count" -eq 0 ]]; then
    pwdman_exit "Error: username not found in the database."
  elif [[ "$count" -gt 1 ]]; then
    printf '%s\n' "Warning: multiple exact entries found; using the first one." >&2
  fi

  password="$(pwdman_get_password_by_username "$database_buffer" "$encoded_username")"
  pwdman_copy_to_clipboard "$password" "$CLIPBOARD_TIMEOUT"
  printf '%s\n' "Password successfully read."
}

pwdman_update_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password=""
  local database_buffer=""
  local entry_password=""
  local length=""
  local encoded_username=""
  local encoded_password=""
  local count=""

  pwdman_require_command gpg
  pwdman_require_command base64

  if [[ -z "$username" ]]; then
    username="$(pwdman_prompt "Username: ")"
  fi
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  encoded_username="$(pwdman_base64_encode "$username")"
  count="$(pwdman_count_username "$database_buffer" "$encoded_username")"

  if [[ "$count" -eq 0 ]]; then
    pwdman_exit "Error: username not found in the database."
  elif [[ "$count" -gt 1 ]]; then
    printf '%s\n' "Warning: multiple exact entries found; replacing all of them with one entry." >&2
    pwdman_ask_continue 0
  fi

  entry_password="$(pwdman_prompt_secret "New password [random]: ")"
  if [[ -z "$entry_password" ]]; then
    length="$(pwdman_prompt "Random password length [$DEFAULT_LENGTH]: ")"
    length="${length:-$DEFAULT_LENGTH}"
    entry_password="$(pwdman_random_password "$length")"
  fi

  encoded_password="$(pwdman_base64_encode "$entry_password")"
  database_buffer="$(pwdman_remove_username "$database_buffer" "$encoded_username")"
  database_buffer="$(pwdman_append_entry "$database_buffer" "$encoded_username,$encoded_password")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  pwdman_copy_to_clipboard "$entry_password" "$CLIPBOARD_TIMEOUT"
  printf '%s\n' "Entry successfully updated."
}

pwdman_delete_password() {
  local database="${1:-$DEFAULT_DATABASE}"
  local username="${2:-}"
  local database_password=""
  local database_buffer=""
  local encoded_username=""
  local count=""

  pwdman_require_command gpg
  pwdman_require_command base64

  if [[ -z "$username" ]]; then
    username="$(pwdman_prompt "Username: ")"
  fi
  pwdman_validate_username "$username"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"

  encoded_username="$(pwdman_base64_encode "$username")"
  count="$(pwdman_count_username "$database_buffer" "$encoded_username")"

  if [[ "$count" -eq 0 ]]; then
    pwdman_exit "Error: username not found in the database."
  elif [[ "$count" -gt 1 ]]; then
    printf '%s\n' "Warning: multiple exact entries found; deleting all of them." >&2
    pwdman_ask_continue 0
  fi

  database_buffer="$(pwdman_remove_username "$database_buffer" "$encoded_username")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Entry successfully deleted."
}

pwdman_list() {
  local database="${1:-$DEFAULT_DATABASE}"
  local database_password=""
  local database_buffer=""
  local line=""
  local username=""

  pwdman_require_command gpg
  pwdman_require_command base64

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  [[ -n "$database_buffer" ]] || pwdman_exit "Database is empty."

  printf '%s\n' "Database entries:"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    username="$(pwdman_base64_decode "${line%%,*}")"
    printf '  %s\n' "$username"
  done <<< "$database_buffer"
}

pwdman_backup_database() {
  local database="${1:-$DEFAULT_DATABASE}"
  local backup_file="${2:-}"
  local database_password=""
  local database_buffer=""

  pwdman_require_command gpg

  if [[ -z "$backup_file" ]]; then
    backup_file="$(pwdman_prompt "Backup filename: ")"
  fi
  [[ -n "$backup_file" ]] || pwdman_exit "Error: backup filename cannot be empty."

  if [[ -f "$backup_file" ]]; then
    printf '%s\n' "Warning: file already exists. Overwrite it?" >&2
    pwdman_ask_continue 0
  fi

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" shared
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_unlock_database

  [[ -n "$database_buffer" ]] || pwdman_exit "Database is empty."

  {
    printf '%s\n' "Username,Password"
    printf '%s\n' "$database_buffer"
  } > "$backup_file"
  chmod 600 "$backup_file"

  printf '%s\n' "Database successfully exported."
  printf '%s\n' "Note: the export is base64-encoded, but it is NOT encrypted." >&2
}

pwdman_reencrypt_database() {
  local database="${1:-$DEFAULT_DATABASE}"
  local old_password=""
  local new_password=""
  local database_buffer=""

  pwdman_require_command gpg

  old_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$old_password")"
  new_password="$(pwdman_prompt_secret "New database password: ")"
  pwdman_encrypt_database "$database" "$new_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Database successfully reencrypted."
}

pwdman_create_database() {
  local database="${1:-}"
  local database_password=""

  pwdman_require_command gpg

  if [[ -z "$database" ]]; then
    database="$(pwdman_prompt "Database name [$DEFAULT_DATABASE]: ")"
    database="${database:-$DEFAULT_DATABASE}"
  fi

  if [[ -f "$database" ]]; then
    printf '%s\n' "Warning: file already exists. Overwrite it?" >&2
    pwdman_ask_continue 0
  fi

  database_password="$(pwdman_prompt_secret "New database password: ")"

  pwdman_lock_database "$database" exclusive
  pwdman_encrypt_database "$database" "$database_password" ""
  pwdman_unlock_database

  printf '%s\n' "Database successfully created."
}

pwdman_import_backup() {
  local database="${1:-$DEFAULT_DATABASE}"
  local backup_file="${2:-}"
  local database_password=""
  local database_buffer=""
  local import_buffer=""

  pwdman_require_command gpg

  if [[ -z "$backup_file" ]]; then
    backup_file="$(pwdman_prompt "Backup filename: ")"
  fi

  [[ -f "$backup_file" ]] || pwdman_exit "Error: backup file not found."
  [[ "$(head -n 1 "$backup_file")" == "Username,Password" ]] || \
    pwdman_exit "Error: invalid backup file."

  import_buffer="$(tail -n +2 "$backup_file" | sed '/^$/d')"

  database_password="$(pwdman_prompt_secret "Database password: ")"

  pwdman_lock_database "$database" exclusive
  database_buffer="$(pwdman_decrypt_database "$database" "$database_password")"
  pwdman_check_merge_conflicts "$database_buffer" "$import_buffer"
  database_buffer="$(pwdman_merge_buffers "$database_buffer" "$import_buffer")"
  pwdman_encrypt_database "$database" "$database_password" "$database_buffer"
  pwdman_unlock_database

  printf '%s\n' "Database successfully imported."
}

pwdman_import_database() {
  local database="${1:-$DEFAULT_DATABASE}"
  local import_database="${2:-}"
  local database_password=""
  local import_password=""
  local database_buffer=""
  local import_buffer=""

  pwdman_require_command gpg

  if [[ -z "$import_database" ]]; then
    import_database="$(pwdman_prompt "Import database filename: ")"
  fi

  [[ -f "$import_database" ]] || pwdman_exit "Error: import database not found."

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

pwdman_interactive() {
  local database="${1:-$DEFAULT_DATABASE}"
  local action=""

  printf '%s\n' "Interactive Mode"
  printf '%s\n' "Press h for help."
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
    *) pwdman_exit "Error: invalid option. Press h for help." ;;
  esac
}

pwdman_version() {
  printf 'Password Manager version %s\n' "$SCRIPT_VERSION"
}

pwdman_help() {
  pwdman_version
  cat <<'EOF_HELP'

Usage:
  pwdman.sh -i [database]
  pwdman.sh -r username [database]
  pwdman.sh -w username [database]
  pwdman.sh -u username [database]
  pwdman.sh -d username [database]
  pwdman.sh -l [database]
  pwdman.sh -b backup_file [database]
  pwdman.sh -x [database]
  pwdman.sh -c [database]
  pwdman.sh -m backup_file [database]
  pwdman.sh -n import_database [database]

Commands:
  -h, --help, help          Show this help message.
  -v, --version, version    Show version information.
  -i, --interactive         Start interactive mode.
  -r, --read                Copy an entry password to the clipboard.
  -w, --write               Add a new password entry.
  -u, --update              Update a password entry.
  -d, --delete              Delete a password entry.
  -l, --list                List usernames saved in a database.
  -b, --backup              Export a base64-encoded, unencrypted database backup.
  -x, --reencrypt           Change the database password.
  -c, --create              Create a new database.
  -m, --import-plain        Import from a base64-encoded backup.
  -n, --import-enc          Import from another encrypted database.
EOF_HELP
}

pwdman_initialize() {
  pwdman_version
  printf '%s\n' "Welcome! Set up pwdman."
  pwdman_create_database "$DEFAULT_DATABASE"
}

pwdman_main() {
  local command="${1:-}"

  case "$command" in
    -h|--help|help)
      pwdman_help
      return 0
      ;;
    -v|--version|version)
      pwdman_version
      return 0
      ;;
  esac

  if [[ -z "$command" ]]; then
    if [[ ! -f "$DEFAULT_DATABASE" ]]; then
      pwdman_initialize
      return 0
    fi
    pwdman_exit "Please supply at least one argument. Type --help for help."
  fi

  case "$command" in
    -i|--interactive|interactive) pwdman_interactive "${2:-}" ;;
    -r|--read|read) pwdman_read_password "${3:-}" "${2:-}" ;;
    -w|--write|write) pwdman_write_password "${3:-}" "${2:-}" ;;
    -u|--update|update) pwdman_update_password "${3:-}" "${2:-}" ;;
    -d|--delete|delete) pwdman_delete_password "${3:-}" "${2:-}" ;;
    -l|--list|list) pwdman_list "${2:-}" ;;
    -b|--backup|backup) pwdman_backup_database "${3:-}" "${2:-}" ;;
    -x|--reencrypt|reencrypt) pwdman_reencrypt_database "${2:-}" ;;
    -c|--create|create) pwdman_create_database "${2:-}" ;;
    -m|--import-plain|--import-back|import-plain|import-back) pwdman_import_backup "${3:-}" "${2:-}" ;;
    -n|--import-enc|import-enc) pwdman_import_database "${3:-}" "${2:-}" ;;
    *) pwdman_exit "Invalid argument(s). Type --help for help." ;;
  esac
}

trap pwdman_unlock_database EXIT
pwdman_main "$@"
