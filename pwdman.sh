#!/bin/bash

: "${DEFAULT_DATABASE:=pwdman.db}"
: "${CLIPBOARD_TIMEOUT:=30}"
: "${DEFAULT_LENGTH:=128}"
: "${DEFAULT_ALPHABET:=abcdefghijklmonpqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123\
456789!@#$%^&*()-=_+\`~[]{\}|;\':\",./<>?}"

SCRIPT_VERSION="0.4"
BUFFER=""

#
# Encrypt Database
#
# $1 Database
# $2 Password
# $3 [ Data ]
#
# $BUFFER
#
function pwdman_encrypt_database() {
    local data gpg_options
    if [[ $# -lt 2 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    data="Username,Password"$'\n'"$3"
    gpg_options=(
        --armor
        --batch
        --symmetric
        --yes
        --passphrase-fd 3
        --no-symkey-cache
        --output
    )
    if ! printf "%s" "$data" | gpg "${gpg_options[@]}" "$1" 3<                 \
    <(printf "%s" "$2"); then
        pwdman_exit "Error: database encryption error."
    fi
}

#
# Decrypt Database
#
# $1 Database
# $2 Password
#
# $BUFFER
#
function pwdman_decrypt_database() {
    local gpg_options result
    if [[ $# -lt 2 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    if [[ ! -f "$1" ]]; then
        pwdman_exit "Error: database not found."
    fi
    gpg_options=(
        --armor
        --batch
        --no-symkey-cache
        --decrypt
        --passphrase-fd 0
    )
    if ! result=$(printf "%s\\n" "$2" | gpg "${gpg_options[@]}"                \
    "$1" 2>/dev/null); then
        pwdman_exit "Error: database decryption error."
    fi
    BUFFER=$(printf "%s" "$result" | tail -n +2)
}

#
# Write Password
#
# $1 Username
# $2 [ Database ]
#
#
function pwdman_write_password() {
    local database database_password username
    if [[ $# -lt 1 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    if [[ $# -gt 1 ]]; then
        database="$2"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password: "
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    if ! pwdman_check_reverse_entries "$1" "$BUFFER" ||                        \
    [[ $(pwdman_count_entries "$1" "$BUFFER") -gt 0 ]]; then
        echo "Warning: there's already a matching entry in the database."
        pwdman_ask_continue 0
    fi
    pwdman_get_input_password "Entry password [random]: "
    if [[ "$PASSWORD" == "" ]]; then
        pwdman_get_input "Random password length [$DEFAULT_LENGTH]: "
        if [[ -z "$INPUT" ]]; then
            length="$DEFAULT_LENGTH"
        else
            length="$INPUT"
        fi
        pwdman_get_random_password "$length"
    fi
    PASSWORD=$(printf "%s" "$PASSWORD" | base64 -w 0)
    if [[ "$BUFFER" != "" ]]; then
        BUFFER+=$'\n'
    fi
    username=$(printf "%s" "$1" | base64 -w 0)
    BUFFER+="$username,$PASSWORD"
    pwdman_encrypt_database "$database" "$database_password" "$BUFFER"
    echo "Password successfully written."
}

#
# Check DB Reverse Matching Entries
#
# $1 Username
# $2 Database Buffer
#
function pwdman_check_reverse_entries() {
    local database_buffer decoded_line line
    if [[ $# -lt 2 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    database_buffer=$(printf "%s" "$2" | cut -d "," -f1)
    if [[ "$database_buffer" == "" ]]; then
        return 0
    fi
    while IFS= read -r line; do
        decoded_line=$(printf "%s" "$line" | base64 --decode)
        if printf "%s" "$1" | grep -q "$decoded_line"; then
            return 1
        fi
    done <<< "$database_buffer"
    return 0
}

#
# Count DB Entries
#
# $1 Username
# $2 Database Buffer
#
function pwdman_count_entries() {
    local database_buffer decoded_database line
    if [[ $# -lt 2 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    database_buffer=$(printf "%s" "$2" | cut -d "," -f1)
    decoded_database=""
    while IFS= read -r line; do
        decoded_database=$(printf "%s" "$line" | base64 --decode)$'\n'
    done <<< "$database_buffer"
    printf "%s" "$decoded_database" | grep -c "$1"
}

#
# Read Password
#
# $1 Username
# $2 [ Database ]
#
function pwdman_read_password() {
    local database_password count timeout
    if [[ $# -lt 1 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    if [[ $# -gt 1 ]]; then
        database="$2"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password: "
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    encoded_usernames=$(printf "%s" "$BUFFER" | cut -d "," -f1)
    decoded_usernames=""
    while IFS= read -r line; do
        decoded_usernames+=$(printf "%s" "$line" | base64 --decode)$'\n'
    done <<< "$encoded_usernames"
    count=$(printf "%s" "$decoded_usernames" | grep -c "$1")
    if [[ $count -eq 0 ]]; then
        pwdman_exit "Error: username not found in the database."
    elif [[ $count -gt 1 ]]; then
        echo "Warning: multiple entries matching in the database."
    fi
    password=$(printf "%s" "$BUFFER" | cut -d "," -f2 |                        \
    sed -n "$(printf "%s" "$(printf "%s" "$decoded_usernames" |                \
    grep -n "$1")" | cut -d ":" -f1 | sed -n 1p)"p | base64 --decode)
    printf "%s" "$password" | xclip
    timeout="$CLIPBOARD_TIMEOUT"
    shift
    while [[ $timeout -gt 0 ]]; do
        printf "\\rPassword on clipboard! Clearing clipboard in %.d"           \
        $((timeout--))
        sleep 1
    done
    printf "%s" "" | xclip
    echo "Done."
}

#
# Update Password
#
# $1 Username
# $2 [ Database ]
#
function pwdman_update_password() {
    local username database database_password count length line_number
    if [[ $# -lt 1 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    username=$(printf "%s" "$1" | base64 -w 0)
    if [[ $# -gt 1 ]]; then
        database="$2"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password: "
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    count=$(pwdman_count_entries "$username" "$BUFFER")
    if [[ $count -eq 0 ]]; then
        pwdman_exit "Error: username not found in the database."
    elif [[ $count -gt 1 ]]; then
        echo "Warning: multiple entries matching in the database."
        pwdman_ask_continue 0
    fi
    while :
    do
        line_number=$(printf "%s" "$BUFFER" | cut -d "," -f1 |                 \
        grep -n "$username" | cut -d ":" -f1 | head -n 1)
        if [[ "$line_number" == "" ]]; then
            break;
        fi
        BUFFER=$(printf "%s" "$BUFFER" | sed "${line_number}d")
    done
    pwdman_get_input_password "New password [random]: "
    if [[ "$PASSWORD" == "" ]]; then
        pwdman_get_input "Random password length [128]: "
        if [[ -z "$INPUT" ]]; then
            length="$DEFAULT_LENGTH"
        else
            length="$INPUT"
        fi
        pwdman_get_random_password "$length"
    fi
    PASSWORD=$(printf "%s" "$PASSWORD" | base64 -w 0)
    if [[ "$BUFFER" != "" ]]; then
        BUFFER+=$'\n'
    fi
    BUFFER+="$username,$PASSWORD"
    pwdman_encrypt_database "$database" "$database_password" "$BUFFER"
    echo "Entry successfully updated."
}

#
# Delete Password
#
# $1 Username
# $2 [ Database ]
#
function pwdman_delete_password() {
    local username database count line_number
    if [[ $# -lt 1 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    username=$(printf "%s" "$1" | base64 -w 0)
    if [[ $# -gt 1 ]]; then
        database="$2"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password: "
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    count=$(pwdman_count_entries "$username" "$BUFFER")
    if [[ $count -eq 0 ]]; then
        pwdman_exit "Error: username not found in the database."
    elif [[ $count -gt 1 ]]; then
        echo "Warning: multiple entries matching in the database."
        pwdman_ask_continue 0
    fi
    while :
    do
        line_number=$(printf "%s" "$BUFFER" | cut -d "," -f1 |                 \
        grep -n "$username" | cut -d ":" -f1 | head -n 1)
        if [[ "$line_number" == "" ]]; then
            break;
        fi
        BUFFER=$(printf "%s" "$BUFFER" | sed "${line_number}d")
    done
    pwdman_encrypt_database "$database" "$database_password" "$BUFFER"
    echo "Entry successfully deleted."
}

#
# List Entries
#
# $1 [ Database ]
#
function pwdman_list() {
    local database  database_password username password decoded_data
    if [[ $# -gt 0 ]]; then
        database="$1"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password: "
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    if [[ "$BUFFER" == "" ]]; then
        pwdman_exit "Database is empty."
    fi
    decoded_data="Username Password"$'\n'
    printf "Database entries:\\n"
    while IFS= read -r line; do
        username=$(printf "%s" "$line" | cut -d "," -f1 | base64 --decode)
        password=$(printf "%s" "$line" | cut -d "," -f2 | base64 --decode)
        decoded_data+="$username $password"$'\n'
    done <<< "$BUFFER"
    printf "%s" "$decoded_data" | column -t -s " "
}


#
# Backup Database
#
# $1 File Name
# $2 [ Database ]
#
function pwdman_backup_database() {
    local database database_password username password decoded_data
    if [[ $# -lt 1 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    if [[ $# -gt 1 ]]; then
        database="$2"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password: "
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    if [[ "$BUFFER" == "" ]]; then
        pwdman_exit "Database is empty."
    fi
    decoded_data="Username,Password"$'\n'
    while IFS= read -r line; do
        username=$(printf "%s" "$line" | cut -d "," -f1 | base64 --decode)
        password=$(printf "%s" "$line" | cut -d "," -f2 | base64 --decode)
        decoded_data+="$username,$password"$'\n'
    done <<< "$BUFFER"
    printf "%s" "$decoded_data" > "$1"
    echo "Database successfully exported."
    echo "Note: be aware that the export is in plaintext!"
}

#
# Reencrypt Database
#
# $1 [ Database ]
#
function pwdman_reencrypt_database() {
    local database
    if [[ $# -gt 0 ]]; then
        database="$1"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password: "
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    pwdman_get_input_password "New database password: "
    pwdman_encrypt_database "$database" "$PASSWORD" "$BUFFER"
    echo "Database successfully reencrypted."
}

#
# Continue Prompt
#
# $1 [ Default Yes ]
#
function pwdman_ask_continue() {
    local yesno prompt
    if [[ $# -gt 1 ]]; then
        yesno="$1"
    else
        yesno=0
    fi
    if [[ $yesno -eq 0 ]]; then
        prompt="Continue [y/N]? "
    elif [[ $yesno -eq 1 ]]; then
        prompt="Continue [Y/n]? "
    else
        prompt="Continue [y/n]? "
    fi
    pwdman_get_input "$prompt"
    case "$INPUT" in
        [Yy])
            ;;
        [Nn])
            pwdman_exit "Aborting."
            ;;
        *)
            if [[ $1 -eq 0 ]]; then
                pwdman_exit "Aborting."
            fi
            ;;
    esac
}

#
# Get Random Password
#
# $1 [ Length ]
# $2 [ Alphabet ]
#
function pwdman_get_random_password() {
    local length alphabet char
    if [[ $# -gt 0 ]]; then
        length="$1"
    else
        length="$DEFAULT_LENGTH"
    fi
    if [[ $# -gt 1 ]]; then
        alphabet="$2"
    else
        alphabet="$DEFAULT_ALPHABET"
    fi
    PASSWORD=""
    for _ in $(seq 1 "$length"); do
        char=${alphabet:$RANDOM % ${#alphabet}:1}
        PASSWORD+=$char
    done
}

#
# Get Input Password
#
# $1 [ Prompt ]
#
function pwdman_get_input_password() {
    pwdman_get_input "$1" "*"
    PASSWORD="$INPUT"
}

#
# Get Input
#
# $1 [ Prompt ]
# $2 [ Hide character ]
#
function pwdman_get_input() {
    local prompt
    INPUT=""
    prompt="${1:-Input: }"
    while IFS= read -p "${prompt}" -r -s -n 1 char ; do
        if [[ ${char} == $'\0' ]] ; then
            break
        elif [[ ${char} == $'\177' ]] ; then
            if [[ -z "${INPUT}" ]] ; then
                prompt=""
            else
                prompt=$'\b \b'
                INPUT="${INPUT%?}"
            fi
        else
            if [[ $# -gt 1 ]]; then
                prompt="$2"
            else
                prompt="${char}"
            fi
            INPUT+="${char}"
        fi
    done
    printf "%s" $'\n'
}

#
# Interactive Mode
#
# $1 [ Database ]
#
function pwdman_interactive() {
    local database
    if [[ $# -gt 0 ]]; then
        database="$1"
    else
        database="$DEFAULT_DATABASE"
    fi
    while [[ -z "${action}" ]] ; do
        # pwdman_version
        # echo "Interactive Mode"
        read -r -n 1 -p "> " action
        printf "\\n"
    done
    case "$action" in
        "h")
            pwdman_help
            ;;
        "v")
            pwdman_version
            ;;
        "r")
            pwdman_get_input "Username: "
            pwdman_read_password "$INPUT" "$database"
            ;;
        "w")
            pwdman_get_input "Username: "
            pwdman_write_password "$INPUT" "$database"
            ;;
        "u")
            pwdman_get_input "Username: "
            pwdman_update_password "$INPUT" "$database"
            ;;
        "d")
            pwdman_get_input "Username: "
            pwdman_delete_password "$INPUT" "$database"
            ;;
        "l")
            pwdman_list "$database"
            ;;
        "b")
            pwdman_get_input "Backup filename: "
            pwdman_backup_database "$INPUT" "$database"
            ;;
        "x")
            pwdman_reencrypt_database "$database"
            ;;
        *)
            pwdman_exit "Error: invalid option. Press h for help."
    esac
    exit 0
}

#
# Password Manager Version
#
function pwdman_version() {
    echo "Password Manager version $SCRIPT_VERSION"
}

#
# Password Manager Help
#
function pwdman_help(){
    pwdman_version
    cat <<EOF
usage: ./pwdman [options]

Options:
  -h | (--)help             Displays this information.
  -v | (--)version          Displays the script version.
  -i | (--)interactive      Runs the script in interactive mode.
  -r | (--)read <arg>       Reads a password from a database.
  -w | (--)write <arg>      Writes a new password in a database.
  -u | (--)update <arg>     Updates a password in a database.
  -d | (--)delete <arg>     Deletes a password from a database.
  -l | (--)list <arg>       Lists all passwords saved in a database.
  -b | (--)backup <arg>     Makes a backup dump of a database.
  -x | (--)reencrypt <arg>  Changes the password of a database.
EOF
}

#
# Exit Password Manager
#
# $1 Error Message
#
function pwdman_exit() {
    if [[ $# -eq 0 ]]; then
        echo "Error: undefined error."
    else
        echo "$1"
    fi
    exit 1
}

#
# Initialize Password Manager
#
function pwdman_initialize() {
    pwdman_version
    echo "Welcome! Set up pwdman."
    pwdman_get_input "Database name [$DEFAULT_DATABASE]: "
    if [[ -z "$INPUT" ]]; then
        database="$DEFAULT_DATABASE"
    else
        database="$INPUT"
    fi
    pwdman_get_input_password "Database password: "
    pwdman_encrypt_database "$database" "$PASSWORD"
    echo "Database set up successful."
    exit 0
}

#
# Password Manager Main
#
# $@ Arguments
#
function pwdman_main() {
    if [[ ! -f "$DEFAULT_DATABASE" ]]; then
        pwdman_initialize
    fi
    if [[ $# -eq 0 ]]; then
        pwdman_exit "Please supply at least one argument. Type --help for help."
    fi
    case "$1" in
        "-h" | "--help" | "help")
            pwdman_help
            ;;
        "-v" | "--version" | "version")
            pwdman_version
            ;;
        "-i" | "--interactive" | "interactive")
            pwdman_interactive "${@:2}"
            ;;
        "-r" | "--read" | "read")
            pwdman_read_password "${@:2}"
            ;;
        "-w" | "--write" | "write")
            pwdman_write_password "${@:2}"
            ;;
        "-u" | "--update" | "update")
            pwdman_update_password "${@:2}"
            ;;
        "-d" | "--delete" | "delete")
            pwdman_delete_password "${@:2}"
            ;;
        "-l" | "--list" | "list")
            pwdman_list "${@:2}"
            ;;
        "-b" | "--backup" | "backup")
            pwdman_backup_database "${@:2}"
            ;;
        "-x" | "--reencrypt" | "reencrypt")
            pwdman_reencrypt_database "${@:2}"
            ;;
        *)
            echo "Invalid argument(s). Type --help for help."
            exit 1
            ;;
    esac
    exit 0
}

pwdman_main "$@"
