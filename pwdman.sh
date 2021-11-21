#!/bin/bash

: "${DEFAULT_DATABASE:=pwdman.db}"

SCRIPT_VERSION="0.3"
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
    password="$2"
    data="$3"
    data=$(printf "%s,%s" "Username" "Password")$'\n'$(printf "%s" "$data")
    result=$(printf "%s" "$data" | gpg --armor --batch --symmetric --yes --passphrase-fd 3 --no-symkey-cache --output "$database" 3< <(printf "%s" "$password"))
    if [[ $? -ne 0 ]]; then
        pwdman_exit "Database encryption error."
    fi
}

function pwdman_check_database_existance() {
    if [[ $# -lt 1 ]]; then
        pwdman_exit "Error: missing argument(s) for ${FUNCNAME[0]}"
    fi
    # TODO
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
    password="$2"
    result=$(printf "%s\n" "$password" | gpg --armor --batch --no-symkey-cache --decrypt --passphrase-fd 0 "$database" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
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
    # TODO: better checking
    count=$(pwdman_count_entries "$username" "$BUFFER")
    if [[ $count -ge 1 ]]; then
        echo "Warning: there's already a matching entry in the database."
        pwdman_ask_continue
    fi
    pwdman_get_input_password "Entry password (press enter for generating a random one):"
    if [[ "$PASSWORD" == "" ]]; then
        pwdman_get_random_password
    fi
    PASSWORD=$(printf "%s" "$PASSWORD" | base64 -w 0)
    if [[ "$data" != "" ]]; then
        data+=$'\n'
    fi
    data+=$(printf "%s,%s" "$username" "$PASSWORD")
    pwdman_encrypt_database "$database" "$database_password" "$data"
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
    username="$1"
    database_buffer="$2"
    printf "$database_buffer" | grep "$username" | wc -l
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
    printf "%s" "$data" | grep "$username" |  cut -d "," -f2 | base64 --decode
    # TODO: copy to clipboard
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
    pwdman_get_input_password "New password (press enter for generating a new one):"
    if [[ "$PASSWORD" == "" ]]; then
        pwdman_get_random_password
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
    printf "Database entries:\nUsername\tPassword\n"
    while IFS= read -r line; do
        username=$(printf "%s" "$line" | cut -d "," -f1 | base64 --decode)
        password=$(printf "%s" "$line" | cut -d "," -f2 | base64 --decode)
        printf "%s\t%s\n" "$username" "$password"
    done <<< "$data"
}

#
# Continue Prompt
#
function pwdman_ask_continue() {
    # TODO: default Y/N
    pwdman_get_input "Continue? [y/N]"
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
        alphabet='abcdefghijklmonpqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+`~[]\{}|;'\'':",./<>?'
    fi
    PASSWORD=""
    for i in $(seq 1 $length); do
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
    pwdman_get_input "Database name (press enter for default database $DEFAULT_DATABASE):"
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
