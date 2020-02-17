#ifndef certlib_cert_store_mozilla_include_hpp
#define certlib_cert_store_mozilla_include_hpp

namespace Cert {

/**
* \brief provides a namespace for functions that import a root certificate bundle from Mozilla via the curl website
*/
class Mozilla
{
    public:
	/**
	* downloads the moziila store of root certificates
	* and appends the CA root certificate from the subject cert store. Saves
    * the resulting PEM file in the subject store.
    *
	* @param store - the certificate store in question
	* @throws if something goes wrong
	*/
	static void importRootCerts(Store::Store& store);

};
} // namespace CertStore
#endif
