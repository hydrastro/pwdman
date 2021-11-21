# Password Manager
Simple password manager written in bash.  
Inspired by https://github.com/drduh/pwd.sh
It uses `gpg` for encrypting a csv single database on the fly.  
And copies retrieved passwords to the clipboard with `xclip`.

## Dependencies
This cripts has the following dependencies:
- `gpg`
- `xclip`

Which can be easily installed with these commands:
- Ubuntu/Debian: `sudo apt install gpg xclip`
- Arch: `pacman -S gpg xclip`

## Installation
Script installation is trivial, just clone or copy this script in some
directory.
```shell
cd /opt
git clone https://github.com/hydrastro/pwdman.git
```
And then either add it to your `PATH` or set up a bash alias for
the script.  
A bash alias is conveniente because you can directly invoke the script in
interactive mode:
```shell
alias pw=/opt/password_manager/pwdman.sh -i
```

There are some configs hardcoded in the code you might want to change: the
default database location and the clipboard clearing timeout or the alphabet
user for random password generation.


## Usage
The script usage is pretty straightforward, as explained in
the help section:
```
Password Manager version 0.4
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
```
Further examples
For running script normally:
```shell
./pwdman.sh -r username [database]
./pwdman.sh -w username [database]
./pwdman.sh -u username [database]
./pwdman.sh -d username [database]
./pwdman.sh -l list [database]
./pwdman.sh -b backup file_name [database]
```
For running the script interactively:
```shell
./pwdman.sh -i
```

## Contributing
Feel free to contribute, pull requests are always welcome.  
Please reveiw and clean your code with `shellcheck` before pushing it.  
If you want to help, Here below is a todo list.

### Database Structure
The database is just an encrpyted csv file with two columns: `Username` and
`Password`.  
It has a header with the column names and also its values are encoded in base64.

## TODO
- [ ] Optimization (there are a lot of unnecessary assignments)
- [ ] Allow "," in passwords
- [X] Proper README.md
- [X] ask_continue function feature
- [X] Interactive mode
- [X] Backup function(s)
- [X] Clipboard copy
- [X] Better list output
- [X] Better check for usernames on function password write
- [X] Code cleanup with shellcheck
- [X] Setup CI workflow
- [X] Check update function
- [X] Random functions
- [X] LICENSE file
