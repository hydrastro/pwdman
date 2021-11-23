# Password Manager
Simple password manager written in bash.  
Inspired by https://github.com/drduh/pwd.sh  
It uses GnuPG for symmetrically encrypting a csv database on the fly and copies
retrieved passwords to the clipboard with `xclip`.

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
There are some hardcoded configs you might want to change: the default database
location, the clipboard clearing timeout and the alphabet user for random
password generation.

## Usage
The script usage is pretty straightforward: you can either run the script
normally, specifying your parameters (usually the username on and optionally
the database you're working on) in the command call:
```shell
./pwdman.sh -r username [database]
./pwdman.sh -w username [database]
./pwdman.sh -u username [database]
./pwdman.sh -d username [database]
./pwdman.sh -l list [database]
./pwdman.sh -b backup file_name [database]
```
Or you can run the script interactively with the `i` flag:
```shell
./pwdman.sh -i
```
Now you have to press a flag key to perform an action and the script will
guide and eventually ask for inputs.

## Contributing
Feel free to contribute, pull requests are always welcome.  
Please reveiw and clean your code with `shellcheck` before pushing it.  

### Database Structure
The database is just an encrpyted csv file with two columns: `Username` and
`Password`.  
It has a header with the column names and also its values are encoded in base64.
