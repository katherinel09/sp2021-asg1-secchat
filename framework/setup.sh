#!/bin/bash
# fields.sh
# This script will generate the serverkeys, clientkeys, and/or ttpkeys directories

set -e # shell will exit if a command fails (exit non-zero)

#! bin/bash
#! Katherine Lasonde
#! Test the crawler module

# Directories

mkdir serverkeys
mkdir clientkeys
mkdir ttpkeys

# Open SSL commands to generate cryptographic keys and certificates 

CERT="cert.crt"
CSR="users.csr"
CRT="users.crt"
KEY="userskey"
DER="users.der"
PEM="users.pem"
PFX="users.pfx"

# Generate server key 

### Testing memory leaks ###
valgrind --leak-check=full --show-leak-kinds=all ./crawler $seedURL0 seedURL0test0/ 1

