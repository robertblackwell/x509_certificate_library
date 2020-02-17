#!/bin/bash
# openssl s_client -showcerts -connect paypal.com:443 </dev/null | openssl -x509 -outform PEM
CAFILE="/usr/local/ssl/cert.pem"
PWD=`pwd`
BIN=`realpath ${PWD}/bin`
ALLROOTS=`realpath ${PWD}/allroots`
MOZ=`realpath ${ALLROOTS}/mozilla-cacert.pem`
CAFILE=
openssl s_client -showcerts -CAfile ${MOZ} -connect  $1:443 </dev/null \
	| openssl x509 -outform PEM  \
	| sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' \
	