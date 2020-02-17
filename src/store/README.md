# cert_store
A service that includes a custom __certificate authority__ (CA) and services for creating host certificates so that a __man in the middle__ proxy can impersonate any host. These __impersonating__ certificates are signed by the custom CA.

More specifically the follwing services are required.

	-	create the key and certificate for the custom CA
	-	provide a database mechanism for storing the custom CA, and storing, accessing and creating impersonating certificates for hosts.
	- 	building a custom root certificate store that includes the custom CA, using the root certificates either, in the OSX keychain or downloaded from Mozilla.
	-  add the custom CA as an authorized root certificatr to the OSX keychain. 
	-  add the custom CA as an authorized root certificate to MOzilla's root store.

# modules, classes

`cert_auth.cpp/hpp` - create the custom CA from details stored in the code.

`cert_store.cpp/hpp` - the primary interface to the database of host impersonating certificates. Provides `get` and `create` functions for a host name(+port). Operates asynchronously uwing Boost Asio.

`cert_location.hpp/cpp` - a helper class that knows the layout of the database of impersonating certificates.

`host.hpp/cpp` - implements the details for creating and retrieving impoersonating certificates/