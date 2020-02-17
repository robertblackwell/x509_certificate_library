#
# dump all root certificates from the OSX key chain
#
PWD=`pwd`
security find-certificate -a -p > ./allroots/osx-cacerts.pem


cat ./allroots/osx-cacerts.pem ./private/cacert.pem > ./allroots/osx-combined-cacert.pem