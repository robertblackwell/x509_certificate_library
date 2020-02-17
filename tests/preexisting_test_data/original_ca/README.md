#Certificate Management
## Overview
This folder contains the data, information and tools necessary to manage a process that includes:

-	creating a dedicated private __Certificate Signing Authority__, called __*Our CA*__.

-	soliciting any https server on the internet for its real certificate, checking that the certificate verifies against the osx keychain, and then storing that certificate

-	using the data in a servers real certificate to make a new certificate signing request for that server, signing that request with __*Our (private) CA*__ and storing that signed certificate. These new certificates we call the server's __*Intercepting Certificate*__ .

##Purpose##

The motivation for all of this is so that a proxy app can use a servers __*Intercepting Certificate*__ to pretend to be that server.

As a secondary goal we can use the tools described below to generate and sign certificates for use by https websites or other apps that use TLS to secure communications.

##Structure##

We have the following folders:

-	__private__. This contains the files necessary to have a CA
	-	```config.cf```, is an openssl configuration file used to generate the rest of the files in this folder. This is file is generated from ```template-config.cnf``` as an absolute file path needs to be included in the config file.
	-	```cakey.pem``` is the CA's public and private key stored in PEM format.
	-	```cacert.pem``` is the CA's self-signed certificate also in PEM format
	-	```ca.p12``` is the CA's key and self-signed certificate combined into a PKCS#12 format. This is what is required by OS X keychain utilities in order to import the CA into the keychain and make it a __*trusted root*__
	-	```ca_combined.pem``` is the CA's key and certificate combined into a single PEM file. But it is not used. Was part of an experiment.
	-	```certificate.p12``` is the CA's entry in the OS X keychain exported to check that it is the same as ```ca.p12```. Also not used.

-	__certs__. This folder contains a sub folder for each host on the internet for which we have solicited a real certificate and created an Intercepting Certificate.
	
	The contents of a typical sub folder is:
	
	-	```real_certificate.pem```, this is (obviously) the hosts real certificate that we solicited over the internet, [see - apple tech note https://developer.apple.com/library/mac/technotes/tn2232/\_index.html](https://developer.apple.com/library/mac/technotes/tn2232/_index.html).

	-	```config.cnf```, is an openssl config file that is created from the information in the real certificate and info about our CA.
	-	```pass_protected_key.pem```, is a new key we generate to be the basis of the intercepting certificate. This is pass word protected.
	-	```key.pem```, is the same key but with the pass work pass phrase stripped.
	-	```request.em```, is a certificate signing request generated from the config file, key file and destined for signing by our CA.
	-	```interceptor_cert.pem```, is finally a certificate for this host/server signed by our CA ready for use by any app that wants to act like the server of this host. 

-	__sites__. Contains a sub folder for each website or app for which we have generated a certificate signed by our CA. These are created from scratch, meaning we __did not__ have to solicit a real certificate to start with. The contents of such a folder are:
	-	```config.cf```, this is the openssl config file that will be used to generate a certificate signing request for this site. You should anticipate editing this file if you want to create a certificate for a site.
	-	```<site-name>.pass_protected_key.pem```, is the new private/public key pair generated for the site. ```<site_name>.key.pem``` is the same key with the pass word/phrase stripped.
	-	```request.em```, is the certificate signing request required to get our CA to sign a certificate.
	-	```<site-name>.crt.pem```, is the signed certificate.
	-	```key.em, crt.pem```, are copies of the certificate and key files.

-	__bin__, contains tools for doing all of the above. Explained below.

##Tools - the bin folder##

Most of the files in the __bin__ folder are shell scripts built while working out how to do each of the required steps. I have left these as a historical record of the work.

However a couple are the core of the process, these are:

-	```make-root.sh```, this creates __*Our CA*__ and the contents of the ```private``` folder. This is usually a *once off* and does not need to be fast. You can change the details of the CA thus created by editing the ```self-sign-rio.cnf``` file in the ```private``` folder.
-	```cert-util.php```, this is a utility written in `php` that can either:
	-	get the certificate from a server (host) and then make an interceptor certificate for that host
	-	create an server certificate signed by the this CA for a host from the `cnf` file in that hosts `sites/` directory. Note the directory and the `cnf` file must already exist. The only use so far for this function is to make a certificate for the local site `ssltest`.	

