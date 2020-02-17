#!/bin/bash

openssl pkcs12 -export -out {$p12} -inkey {$key} -in {$cert} -passin pass:blackwellapps -passout pass:blackwellapps