#!/bin/bash

openssl x509 -req \
	-in testreq.pem \
	-inform PEM \
	-CA ./private/cacert.pem \
	-CAkey ./private/cakey.pem \
	-CAcreateserial \
	-out testcert.pem \
	-extfile request.cnf \
	-extensions v3_req \
	-outform PEM \
	-days 500

# openssl ca -cert ./private/cacert.pem -keyfile ./private/cakey.pem -in $1 -config ./ca_config.conf