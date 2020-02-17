#!/bin/bash
# this script generates a CA cert and CA key and combines those into a pkcs12 format file for importing into
# osx keychain

# generates the key and cert
openssl req -x509 -newkey rsa:2048 -out cacert.pem -days 3650 -outform PEM -config self-sign-root.cnf

# combine into a pk12 file
openssl pkcs12 \
	-name "BlackwellApps CA" \
	-export \
	-out ca.p12 \
	-inkey cakey.pem \
	-in cacert.pem \
	-passin pass:blackwellapps \
	-passout pass:blackwellapps