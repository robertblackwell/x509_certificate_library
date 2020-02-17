# 
# 
# makefile to build sites and allroots subfolders
# 
GETALL= php ./bin/cert-util.php getall 
PWD=$(shell pwd)
BIN=$(PWD)/bin
HOSTS=$(shell cat server_list.txt)
ALLROOTS=$(PWD)/allroots
CACERT=$(PWD)/private/cacert.pem
HOSTS=bankofamerica.com mozilla.org paypal.com ssltest www.google.com www.httpsnow.org yahoo.com ssllabs.com

all:
	echo hello	


clean:
	rm -rvf certs/*

# make a certificate authority
mkca:
	$(BIN)/make-root.sh

# add ca to osx keychain
addca:
	sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "/private/tmp/certs/certname.cer"



# pull down mozilla's store of root certificates into ALLROOTS/mozilla-cacerts.pem
# pull osx store of root certificates from keychain
# add out CA certificate to the mozilla store under the name of combined-cacert.pem
mozgetroots:
	wget -O $(ALLROOTS)/mozilla.pem https://curl.haxx.se/ca/cacert.pem
	# $(BIN)/get-mozilla-certs.sh

mozaddca:
	cat $(ALLROOTS)/mozilla.pem $(CACERT) > $(ALLROOTS)/moz-combined.pem

# pull osx store of root certificates from keychain
osxroots:
	security find-certificate -a -p > $(ALLROOTS)/osx.pem	
	# $(BIN)/osx-extract-roots.sh

osxaddca:
	cat $(ALLROOTS)/osx.pem $(CACERT) > $(ALLROOTS)/osx-combined.pem

# pull down the current certificates for a group of hosts
# and build intercepting certificates for each of them
mkcerts:
	rm -rvf certs/*
	$(GETALL) $(HOSTS)
	# $(GETALL) mozilla.org

