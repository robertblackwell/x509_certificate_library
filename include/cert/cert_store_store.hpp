
#ifndef certlib_cert_store_store_hpp
#define certlib_cert_store_store_hpp

#include <cstdlib>
#include <iostream>
#include <memory>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/thread.hpp>

#include <cert/x509.hpp>
#include <cert/cert_identity.hpp>
#include <cert/cert_authority.hpp>
#include <cert/cert_store_locator.hpp>


using namespace Cert;

namespace Cert {
/**
* @brief Cert::Store namespace wraps classes and functions that implement a certificate store and provides
* the public interface for the process of building imitation certificates for a host
*/
namespace Store {


class Store;

typedef std::shared_ptr<Store> StoreSPtr;
typedef boost::filesystem::path Path;

/**
* \brief A Certificate Store Cert::Store::Store class provide the interface to a file based certificate storage
* mechanism the includes a certificate authority and certificates for individual hosts
*/
class Store : public std::enable_shared_from_this<Store>
{
    public:

        /**
        * create a new empty certificate store. If the path already has a store
        * it will be emptied and all files deleted
        *
        * This should only be required once as part of an install as the resulting store
        * is not ready for use.
        *
        * @param storeDirPath Store::Path - path to the top directory for the store
        * @return StoreSPtr
        */
        static StoreSPtr makeEmpty(Path storeDirPath);
        /**
        * create a new empty certificate store with a newly created CA certificate and key inside that store,
        * and then primes with out data required for test suite..
        * Details for the CA are from the the json specification file.
        *
        * This result is ready for use.
        *
        * This should only be required once as part of an install
        *
        * @param storeDirPath Store::Path - path to the top directory for the store
        * @param jsonSpecificationFile Path - path to a json file holding specs for the CA
        * @return StoreSPtr
        */
        static StoreSPtr makeWithCA(Path storeDirPath, Path jsonSpecificationFile);

        /**
        * Loads an already initialized store with a CA and makes it ready for use
        *
        * @param storeDirPath Path - path to a certificate store top directory - must exist and
        *                       already have neeb initialized.
        * @throws if path  is not a valid directory with a CA already constructed
        */
        static StoreSPtr load(Path storeDirPath);

        /**
        * Adds the stores CA certificate to the osx keychain so that web browsers and other
        * apps will correctly validate certificates signed by this store's CA.
        *
        * This method should be called once following every call to makeWithCA.
        */
        void addCACertToKeychain();
    
        /**
        * Load the set of root certificate from the OSX keychain, and place them (as a single file)
        * in this CertStore instance.
        * Also makes a second copy of the OSX root certificates, adds the certificate for this stores CA,
        * and adds that file to this stores instance.
        *
        * When complete there are two files derived from the keychain root certificate store:
        *
        *   -   one with only the osx root store
        *   -   one with the OSX root store + the certificate from the stores CA
        *
        * These will be used by custom apps (like Marvin) to validate connections with https servicers.
        *
        * This method should be called periodically to ensure the store local OSX root certificate file is currentt.
        */
        void rootCertsFromKeychain();
        /**
        * Makes the OSX + stores CA file the active file for use as a root certificate bundle
        */
        void rootCertsKeychainActive();

        /**
        * load the set of root certificate from the Mozilla website (or Curl website) and place them, as a single file, in this CertStore
        * instance.
        * Also makes a second copy of the Mozilla root certificate file, adds the certificate for this stores CA,
        * and adds that file to this stores instance.
        *
        * When complete there are two files derived from the Mozilla root certificate store:
        *
        *   -   one with only the Mozilla root store
        *   -   one with the Mozzila root store + the certificate from the stores CA
        *
        *
        These will be used by custom apps (like Marvin) to validate connections with https servicers.
        *
        * This method should be called periodically to ensure the store local Mozilla root certificate file is currentt.
        */
        void rootCertsFromMozilla();
        /**
        * Makes the Mozilla + stores CA file the active file for use as a root certificate bundle
        */
        void rootCertsMozillaActive();

        LocatorSPtr getLocator();
        AuthoritySPtr getAuthority();

        /** Turn off Store - not using it to get and maintain cache of Mitm certificates
         * at least not yet*/
        #ifdef USE_STORE
        /**
        * Gets an imitating Identity(certificate + private key) for a server/host by soliciting that
        * hosts certificate and then making a "forgery" signed by this stores CA.
        *
        * @NOTE this method synchronously connects and handshakes with the speified host
        * and so should probably not be called from code running on a boost:asio::io_context
        * as the io_contextx will be blocked for the duration of the connect and handshake
        *
        * @param host HostId - the id of the host/server
        * @return a host identity certificate + private key
        */
    
        Cert::Identity forgeHostIdentity(HostId host);
    
        /**
        * Make an imitating Identity(certificate + private key) for a server/host
        * from the details in the provided original certificate
        *
        * @NOTE - this method does not perform any I/O and hence is ok to be called in a
        * boost::asio::io_context environment.
        *
        * @param host HostId - the id of the host/server
        * @return a host identity certificate + private key
        */
        Cert::Identity forgeHostIdentity(X509* original_certificate);
        #endif

        /**
        * constructor
        * @param dirPath Path - path to a certificate store top directory - must exist and
        *                       already have neeb initialized.
        * @throws if path  is not a valid directory with a CA already constructed
        */
        Store(Path dirPath);
        /**
        * clean - empties a certificate store, create folders if necessary.
        * Do NOT create the CA
        *
        */
        void makeClean();
    
        /** makes a certificate authority inside the store using the details provided in the
        * CA config file.
        * @param jsonSpecificationFile - a json file path the gives details of the CA
        */
        void makeCA(Path jsonSpecificationFile);

        void post(std::function<void()> request);
        void loadConfig();
        void loadCertAuth();
        void saveConfig(std::string caSpecificationFilePath);

        LocatorSPtr             m_locator_sptr;
        ::Cert::AuthoritySPtr   m_cert_auth_sptr;
    protected:
    
};
} // namespace Store
} // namespace Cert
#endif /* marvin_cert_store_hpp */
