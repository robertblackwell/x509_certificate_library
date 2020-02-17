
#
# verify a server certificate against a file of root certificates
# 
# verify-cert.sh file-of-root-certs server-cert
#

# openssl verify -verbose -x509_strict -CAfile allcerts.pem -CApath nosuchdir ssltest.crt.pem
PWD=`pwd`
CAFILE=${PWD}/allroots/combined-cacert.pem
CAFILE=/usr/local/ssl/cert.pem
SRVCERT=${PWD}/certs/$1/real_certificate.pem
openssl verify -verbose -x509_strict -CAfile ${CAFILE} -CApath nosuchdir ${SRVCERT}