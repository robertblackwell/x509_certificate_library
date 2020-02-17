#
# download mozilla's file of root certs from the curl website
# store in ./allroots/mozilla-cacert.pem
# 
# This is a preliminary step required to build a cert store containing our 
# CA cert 
#
wget -O allroots/mozilla-cacert.pem https://curl.haxx.se/ca/cacert.pem

cat ./allroots/mozilla-cacert.pem ./private/cacert.pem > ./allroots/moz-combined-cacert.pem