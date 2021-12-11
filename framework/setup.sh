#!/bin/bash
# setup.sh
# This script will generate the serverkeys, clientkeys, and/or ttpkeys directories

set -e # shell will exit if a command fails (exit non-zero)

# Directories
mkdir serverkeys
mkdir clientkeys
mkdir ttpkeys

# Create variables
CERT="cert.crt"
CSR="users.csr"
CRT="users.crt"
KEY="userskey"
DER="users.der"
PEM="users.pem"
PFX="users.pfx"

# Create client keys
if [ "$1" = "client" ]; 
	if ["$2" = "public" ]; 
		# Get public key 
		dir = ../clientkey/public/$3
		cd dir
		# Create public key for user and share
		openssl genrsa -out "public_key.pem" >/dev/null 2>&1
 		openssl rsa -pubout  "$3_public_key.pem" >/dev/null 2>&1
  	exit
	fi
	if [ "$2" = "private" ]; 
		// Get private key 
		dir = ../clientkey/private/$3
		cd dir
		// Create key for user

		# Generate private key for the user
		openssl genrsa -out "priv_key.pem" >/dev/null 2>&1
 		openssl rsa -in "$3_priv_key.pem"  >/dev/null 2>&1
  	exit
	fi
fi
# Generate server keys
if [ "$1" = "server" ]; 
	dir = ../serverkey/
	cd dir

	openssl genrsa -out "server_key.pem"  >/dev/null 2>&1
fi

# Create signatures and verify
if [ "$1" = "signature" ]; 
	./rsa-sign keypriv.pem "$2" | ./rsa-verify keypub.pem "$2"	
fi
if [ "$1" = "verify" ]; 
	./rsa-sign keypriv.pem "$2" | ./rsa-verify keypub.pem "$2"
fi


