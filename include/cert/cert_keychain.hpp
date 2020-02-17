#ifndef certlib_cert_store_keychain_include_hpp
#define certlib_cert_store_keychain_include_hpp
namespace Cert{

/**
 * \brief Provides a namespace for functions that work with the OSX keychain to import the root certificate bundle
 */
class Keychain
{
    public:

	/// https://stackoverflow.com/questions/35031149/set-imported-certificate-to-always-be-trusted-in-mac-os-x
	/// sudo security add-trusted-cert -d -r trustRoot -p [option] -k /Library/Keychains/System.keychain <certificate>
	/// -p options are ssl, smime, codeSign, IPSec, iChat, basic, swUpdate, pkgSign, pkinitClient, pkinitServer, timestamping, eap
	
	/**
	* importCAIdentity - adds the CA certificate from the subject store
	* to the OSX keychain
	* @param store - the certificate store in question
	* @param keychain - not used
	* @throws if something goes wrong
	*/
	static void importCAIdentity(::Cert::Store::Store& store, std::string keyChain);

	/**
	* getRooCerts - exports the store of root certificates
	* from the OSX keychain and appends the CA root certificate from the subject cert store
	* @param store - the certificate store in question
	* @throws if something goes wrong
	*/
	static void importRootCerts(::Cert::Store::Store& store, std::string keyChain);

};
} //namespace Cert
#endif
