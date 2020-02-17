# x509 Certificate LIbrary (libcert)

__Libcert__ is a library in C++ intended to make handling x509 certificates (and related data structures) a little easier, and also to teach me how such things work.

This project was motivated by another project I have been working on simply for my own amusement. Specifically the building of a __Charles__ like `man-in-the-middle` (MITM) proxy in C++ using the `boost::asio` library as the event manager. 

In order that a proxy can intercept and view HTTPS traffic the proxy must impersonate the upstream host/server when communicating HTTPS requests/responses with the client system. 

That requires: 

-	a custom X509 certificate be added to the requesting system's store of trusted root certificates (this is in fact a new Certificate Authority), and 
-	the proxy must create a new X509 certificate, signed by the custom root certificate mention in the previous sentence, which identifies the proxy as the upstream server. Thus the client system will think that it is exchanging requests/responses directly with the upstream server. Whereas it is actually in conversation with the proxy.

This project is all about how these custom certificates are made, in code, using the openssl `libcrypto` and `libssl` libraries rather than openssl command line utilities.

Specifically I am seeking a function with the following signature (somewhat stylized):

```
	[EVP_PKEY* pkey, X509* cert] buildMitmCertificate(X509* original_cert, X509* ca_certificate, EVP_PKEY* ca_private_key)
	
	where:
	
		original_cert	-	is the certificate send by the original upstream host
		ca_certificate	-	is the Certificate for the custom local Certificate Authority
		ca_private_key	-	is the private key for the custom local Certificate Authority
		
		cert			-	is a new certificate for the original host BUT now signed by the local Certificate Authority
		pkey			-	is a new public key for the original host that corresponds to 'cert'
		
		NOTE: the pair [pkey, cert] is often called an 'Identity'
```
The result of this calculation is that provided that local CA certificate has been added to the local root certificate store our browser/client system will accept an https response containing `cert` rather than `original_cert`; there by allowing us to successfully place our proxy between the browser and the original host.

The actual function that achieves my desired outcome is:

```
	Cert::Identity Cert::Builder::buildMitmIdentity()
```
and you can find it in file `${project_dir}/src/cert_builder.cpp`.

This function is not the end of the story, at least so far as my learning is concerned, for I had to test that the function worked as hoped. To do that I needed to learn how to make an __https__ connection to a host, get the certificate from the host, and verify it against a possibly non-standard bundle of root certificates.

All of this `learning` is encapsulated in the library and the test code.

To get to this end point I spent considerable time scouring the internet with google, not to mention many hours reading the code for openssl's crypto library.

So I have tried to make this project a distillation of what I learned. Between the library functions and the test suites a lot of information has been captured on the subject of how to use openssl and TLS in a boost::asio environment.

## Dependencies

libcert depends on 

-	boost version 1.72
-	openssl version 1.1.1d
-	catch2 version 2.11.1
-	nlohmann/json 3.7.3

The build process, and the xcode project file, expects to find the headers files from these libraries in

	-	${project_dir}/vendor/include/boost
	-	${project_dir}/vendor/include/openssl
	-	${project_dir}/vendor/include/catch
	-	${project_dir}/vendor/include/json/json.hpp

and the libraries (as static archives) in

	-	${project_dir}/vendor/lib


The project does no use a formal dependency manager. Dependencies are installed within the project using custom shell scripts. This process so far has only been tested on OSX Catalina.

Dependencies are installed with the commands:

```
cd {project_dir}
./scripts/install_dependencies.sh install
``` 

The libraries installed will include DEBUG  information and hence be suitable for development.

Providing for a __Release__ install of the dependencies is a __TODO__.

## Building

The project build uses `cmake`. The following commands:
```
	mkdir build && cd build
	cmake ..
	make 
	ctest
```
Will build the library, the tests and run all tests.

The command (in the build directory)

```make install```

will install libcert.a in `{project_dir}/vendor/lib`
and header files in `{project_dir}/include/cert`

## IDE

The project comes with an xcode project file (x509.xcodeproj) __THAT IS NOT BUILT BY CMAKE__. 

Another Xcode project file can be generated from the cmake files with the following commands:

```
cd {project_dir}
mkdir xcode-build
cd xcode-build
cmake -G Xcode ..
```
then from Xcode open the file `{project_dir}/xcode-build/CertificateLibrary.xcodeproj.

The project can be directly loaded with __Clion__.


## The Cert:: namespace, and a road map

__Cert::__ is the top level namespace for the project and everything (except the tests) are under this namespace.

### Namespace Cert::x509 

Provides a set of functions for getting and setting the properties of a certificate (X509*), certificate chains, certificate bundles and other esoteric data structures such a X509_EXTENSION, X509_NAME, STACK_OF(X509). 

If you want to understand how to pull apart a certificate and its properties this is the place to look, in addition to `tests/test_x509` which contains the unit tests for these functions.

### Namespace Cert::Builder

Provides a class with two functions for building X509 certificates from scratch in code without any use of openssl command line tools. 

The tests for these functions are in `tests/test_builder` and these tests demonstrate how to create and sign a certificate.

### Namespace Cert::Handshaker

Provides a couple of classes and functions for performing a SSL/TLS handshake with a host and collecting the hosts certificate and certificate chain. After all if I want to create a certificate so that I can pretend to be some particular host I had better know how to harvest that hosts certificate in the first place.

The tests for these classes and functions are in `tests/handshake`, which also contains experiment with different ways of specifying the bundle of root certificates used to verify a hosts certificate chain. In particular I was looking to find a way of specifying the root bundle for many different handshake operations while only reading the certificates from disk once. 

It is worth noting that while the handshake functions provide an interface that looks synchronous under the covers the `connect` and `handshake` are asynchronous using boost::asio.

### Namespace Cert::Authority

Creating certificates requires a Certificate Authority (a self signed certificate and the corresponding private key). This namespace provides a class that encapsulates  the self signed certificate and private key as well as some static functions for creating those things in the first place. 

__Note:__ Creation of a Certificate Authority is performed using `boost::process::system()` to execute openssl command and hence is not suitable for execution frequently on a `boost::asio` run loop.  

### Namespace Cert::Store - Currently not packaged with the library

The word `Store` is used here in the sense of storage or database.

Currently an instance of Cert::Store manages access to a file based storage mechanism that holds:

	-	the custom local CA's certificate and private key, 
	-	a bundle of root certificates for use in verifying host certificates.
	-	and original certificates and original certificate chains for a number of real work host or servers.

An instance of Cert::Store loads this data from files at startup and is used by Cert::Builder and Cert::Authority once loaded.

I envisage at some point Cert::Store will become a special purpose server that provides an asynchronous certificate creation service.

# TODO
-	make a skeleton server that demonstrates Mitm process.
-	build an test on Linux
-	adapt dependency install and library build process to make a Release version.



## References

While working on this project I found a lot useful information on the internet. Here are some of the references I used.

[https://gist.github.com/1stvamp/2158128](https://gist.github.com/1stvamp/2158128)

[https://docs.giantswarm.io/guides/importing-certificates/](https://docs.giantswarm.io/guides/importing-certificates/)

[http://www.iet.unipi.it/p.perazzo/teaching/openssl/]
(http://www.iet.unipi.it/p.perazzo/teaching/openssl/)

[https://stackoverflow.com/questions/32472337/osx-export-system-certificates-from-keychain-in-pem-format-programmatically]
(https://stackoverflow.com/questions/32472337/osx-export-system-certificates-from-keychain-in-pem-format-programmatically)

[https://derflounder.wordpress.com/2011/03/13/adding-new-trusted-root-certificates-to-system-keychain/]
(https://derflounder.wordpress.com/2011/03/13/adding-new-trusted-root-certificates-to-system-keychain/)

[http://wiki.cacert.org/FAQ/ImportRootCert?action=show&redirect=ImportRootCert](http://wiki.cacert.org/FAQ/ImportRootCert?action=show&redirect=ImportRootCert)

[http://gagravarr.org/writing/openssl-certs/others.shtml](http://gagravarr.org/writing/openssl-certs/others.shtml)

[https://www.ed.ac.uk/information-services/computing/computing-infrastructure/network/certificates/install/installmacos](https://www.ed.ac.uk/information-services/computing/computing-infrastructure/network/certificates/install/installmacos)

[https://www.sslsupportdesk.com/how-to-import-a-certificate-into-mac-os/](https://www.sslsupportdesk.com/how-to-import-a-certificate-into-mac-os/)


## including googletest in project

[mattrajca - http://www.mattrajca.com/2016/03/11/using-google-test-with-xcode-7.html](http://www.mattrajca.com/2016/03/11/using-google-test-with-xcode-7.html)

[mattstevens - https://github.com/mattstevens/xcode-googletest](https://github.com/mattstevens/xcode-googletest)

