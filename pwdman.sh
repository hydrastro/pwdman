#!/bin/bash

: "${DEFAULT_DATABASE:=pwdman.db}"
: "${CLIPBOARD_TIMEOUT:=30}"

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
    if [[ $# -lt 2 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    database="$1"
    if [[ ! -f "$database" ]]; then
        pwdman_exit "Error: database not found."
    fi
    password="$2"
    data="$3"
    data=$(printf "%s,%s" "Username" "Password")$'\n'$(printf "%s" "$data")
    if ! result=$(printf "%s" "$data" | gpg --armor --batch --symmetric --yes --passphrase-fd 3 --no-symkey-cache --output "$database" 3< <(printf "%s" "$password")); then
        pwdman_exit "Database encryption error."
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
    if [[ $# -lt 2 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    database="$1"
    if [[ ! -f "$database" ]]; then
        pwdman_exit "Error: database not found."
    fi
    password="$2"
    if ! result=$(printf "%s\\n" "$password" | gpg --armor --batch --no-symkey-cache --decrypt --passphrase-fd 0 "$database" 2>/dev/null); then
        pwdman_exit "Database decryption error."
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
    if [[ $# -lt 1 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    username="$1"
    if [[ $# -gt 1 ]]; then
        database="$2"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password:"
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    data=$(printf "%s" "$BUFFER")
    if ! pwdman_check_reverse_entries "$username" "$BUFFER"; then
        echo "Warning: there's already a matching entry in the database."
        pwdman_ask_continue
    fi
    pwdman_get_input_password "Entry password [random]:"
    if [[ "$PASSWORD" == "" ]]; then
        pwdman_get_input "Random password length [128]:"
        if [[ -z "$INPUT" ]]; then
            length=128
        else
            length="$INPUT"
        fi
        pwdman_get_random_password "$length"
    fi
    PASSWORD=$(printf "%s" "$PASSWORD" | base64 -w 0)
    if [[ "$data" != "" ]]; then
        data+=$'\n'
    fi
    username=$(printf "%s" "$username" | base64 -w 0)
    data+=$(printf "%s,%s" "$username" "$PASSWORD")
    pwdman_encrypt_database "$database" "$database_password" "$data"
}

#
# Check DB Reverse Matching Entries
#
# $1 Username
# $2 Database Buffer
#
function pwdman_check_reverse_entries() {
    if [[ $# -lt 2 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    username="$1"
    database_buffer=$(printf "%s" "$2" | cut -d "," -f1)
    if [[ "$database_buffer" == "" ]]; then
        return 0
    fi
    while IFS= read -r line; do
        decoded_line=$(printf "%s" "$line" | base64 --decode)
        if printf "%s" "$username" | grep "$decoded_line"; then
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
    if [[ $# -lt 2 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    username_encoded="$1"
    database_buffer="$2"
    printf "%s" "$database_buffer" | grep -c "$username_encoded"
}

#
# Read Password
#
# $1 Username
# $2 [ Database ]
#
function pwdman_read_password() {
    if [[ $# -lt 1 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    username="$1"
    username=$(printf "%s" "$username" | base64 -w 0)
    if [[ $# -gt 1 ]]; then
        database="$2"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password:"
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    data=$(printf "%s" "$BUFFER")
    count=$(pwdman_count_entries "$username" "$BUFFER")
    if [[ $count -eq 0 ]]; then
        pwdman_exit "Error: username not found in the database."
    fi
    if [[ $count -gt 1 ]]; then
        echo "Warning: multiple entries matching in the database."
    fi
    password=$(printf "%s" "$data" | grep "$username" |  cut -d "," -f2 | base64 --decode)
    printf "%s" "$password" | xclip
    timeout="$CLIPBOARD_TIMEOUT"
    shift
    while [[ $timeout -gt 0 ]]; do
        printf "\rPassword on clipboard! Clearing clipboard in %.d" $((timeout--))
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
    if [[ $# -lt 1 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    username="$1"
    username=$(printf "%s" "$username" | base64 -w 0)
    if [[ $# -gt 1 ]]; then
        database="$2"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password:"
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    data=$(printf "%s" "$BUFFER")
    count=$(pwdman_count_entries "$username" "$BUFFER")
    if [[ $count -eq 0 ]]; then
        pwdman_exit "Error: username not found in the database."
    fi
    if [[ $count -gt 1 ]]; then
        echo "Warning: multiple entries matching in the database."
        pwdman_ask_continue
    fi
    while :
    do
        line_number=$(printf "%s" "$data" | cut -d "," -f1 | grep -n "$username" | cut -d ":" -f1 | head -n 1)
        if [[ "$line_number" == "" ]]; then
            break;
        fi
        data=$(printf "%s" "$data" | sed "${line_number}d")
    done
    pwdman_get_input_password "New password [random]:"
    if [[ "$PASSWORD" == "" ]]; then
        pwdman_get_input "Random password length [128]:"
        if [[ -z "$INPUT" ]]; then
            length=128
        else
            length="$INPUT"
        fi
        pwdman_get_random_password "$length"
    fi
    PASSWORD=$(printf "%s" "$PASSWORD" | base64 -w 0)
    if [[ "$data" != "" ]]; then
        data+=$'\n'
    fi
    data+=$(printf "%s,%s" "$username" "$PASSWORD")
    pwdman_encrypt_database "$database" "$database_password" "$data"
    echo "Entry successfully updated."
}

#
# Delete Password
#
# $1 Username
# $2 [ Database ]
#
function pwdman_delete_password() {
    if [[ $# -lt 1 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    username="$1"
    username=$(printf "%s" "$username" | base64 -w 0)
    if [[ $# -gt 1 ]]; then
        database="$2"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password:"
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    data=$(printf "%s" "$BUFFER")
    count=$(pwdman_count_entries "$username" "$BUFFER")
    if [[ $count -eq 0 ]]; then
        pwdman_exit "Error: username not found in the database."
    fi
    if [[ $count -gt 1 ]]; then
        echo "Warning: multiple entries matching in the database."
        pwdman_ask_continue
    fi
    while :
    do
        line_number=$(printf "%s" "$data" | cut -d "," -f1 | grep -n "$username" | cut -d ":" -f1 | head -n 1)
        if [[ "$line_number" == "" ]]; then
            break;
        fi
        data=$(printf "%s" "$data" | sed "${line_number}d")
    done
    pwdman_encrypt_database "$database" "$database_password" "$data"
    echo "Entry successfully deleted."
}

#
# List Entries
#
# $1 [ Database ]
#
function pwdman_list() {
    if [[ $# -gt 0 ]]; then
        database="$1"
    else
        database="$DEFAULT_DATABASE"
    fi
    pwdman_get_input_password "Database password:"
    database_password="$PASSWORD"
    pwdman_decrypt_database "$database" "$database_password"
    data=$(printf "%s" "$BUFFER")
    if [[ "$data" == "" ]]; then
        pwdman_exit "Database is empty."
    fi
    decoded_data="Username,Password"$'\n'
    printf "Database entries:\\n"
    while IFS= read -r line; do
        username=$(printf "%s" "$line" | cut -d "," -f1 | base64 --decode)
        password=$(printf "%s" "$line" | cut -d "," -f2 | base64 --decode)
        decoded_data+=$(printf "%s,%s" "$username" "$password")
        decoded_data+=$'\n'
    done <<< "$data"
    printf "%s" "$decoded_data" | column -t -s ","
}

#
# Continue Prompt
#
function pwdman_ask_continue() {
    # TODO: default Y/N
    pwdman_get_input "Continue [y/N]?"
    case "$INPUT" in
        [Yy])
            ;;
        [Nn] | *)
            pwdman_exit "Aborting."
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
    length="${1:-128}"
    if [[ $# -gt 1 ]]; then
        alphabet="$2"
    else
        # Removed comma
        alphabet='abcdefghijklmonpqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+`~[]\{}|;'\'':"./<>?'
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
    INPUT=""
    prompt="${1:-Input:}"
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
    while [[ -z "${action}" ]] ; do
        read -r -n 1 -p "pwdman-interactive>" action
        printf "\\n"
    done
    # Switch for action
    # Get stuff
    # Call functions
    pwdman_exit "Invalid option. Press h for help."
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
  -h | (--)help           Displays this information.
  -v | (--)version        Displays the script version.
  -i | (--)interactive    Runs the script in interactive mode.
  -r | (--)read <arg>     Reads a password from the database.
  -w | (--)write <arg>    Writes a new password in the database.
  -u | (--)update <arg>   Updates a password in the database.
  -d | (--)delete <arg>   Deletes a password from the database.
  -l | (--)list <arg>     Lists all passwords saved in the database.
  -b | (--)backup <arg>   Makes a backup dump of the database.
  -e | (--)encrypt <arg>  Encrypts a database file.
  -x | (--)decrypt <arg>  Decrypts a database file.
EOF
}

#
# Exit Password Manager
#
# $1 Error Message
#
function pwdman_exit() {
    if [[ $# -eq 0 ]]; then
        echo "An error occured."
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
    pwdman_get_input "Database name [$DEFAULT_DATABASE]:"
    if [[ -z "$INPUT" ]]; then
        database="$DEFAULT_DATABASE"
    else
        database="$INPUT"
    fi
    pwdman_get_input_password "Database password:"
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
            pwdman_interactive
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
        *)
            echo "Invalid argument(s). Type --help for help."
            exit 1
            ;;
    esac
    exit 0
}

pwdman_main "$@"
