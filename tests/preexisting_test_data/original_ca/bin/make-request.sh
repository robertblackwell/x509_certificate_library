#!/bin/bash

# openssl genrsa -out key.pem 1024
# openssl req -new -key key.pem -out req.pem -config `pwd`/request.cnf

openssl req -newkey rsa:2048 \
-keyout testkey.pem \
-keyform PEM \
-out testreq.pem \
-outform PEM \
-config request.conf