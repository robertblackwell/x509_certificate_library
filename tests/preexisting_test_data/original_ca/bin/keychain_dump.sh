#
# dump all root certificates from the OSX key chain
#
PWD=`pwd`
security find-certificate -a -p > ${PWD}/allroots/osx-cacerts.pem


cat ./allroots/osx-cacert.pem ./private/cacert.pem > ./allroots/osx-combined-cacert.pem