
#ifndef certlib_cert_store_locator_hpp
#define certlib_cert_store_locator_hpp

#include <cstdlib>
#include <iostream>
#include <boost/filesystem/path.hpp>
#include "cert_store_types.hpp"

namespace Cert {
namespace Store {

class Locator;
typedef std::shared_ptr<Locator> LocatorSPtr;

void create_host_folder(Locator& locator, std::string host);
void get_real_host_certificate(Locator& locator, std::string host);
void create_host_config_file(Locator& locator, std::string host);

void make_signing_request(Locator& locator, std::string host);
void sign_request(Locator& locator, std::string host);
void verifyInterceptorCert(Locator& locator, std::string host);

void remove_passphrase(Locator& locator, std::string host);
void make_p12_file(Locator& locator, std::string host);

/**
* \brief Cert::Store::Locator class encapsulates the folder layout of a certificate store and the
* names of files held within that store. It is a utility used by a number of other units to
* locate specific resources inside a certificate store.
*
* NOTE::WARNING Current implementation DOES NOT support the hosts folder and implied contents
*
* The layout is:
*       top-level-dir
*           hosts/
*               <host.com> one-dir-for-each-host-already-acquired-cerrtificate/
*                   real_certificate.pem
*                   real_certificate_chain.pem
*                   ... imitating certificate and private key
*           private/
*               -this dir holds the details of CertificateAuthority.
*               -Certificate, private key, password for, the key. ca.p12 holds all of that inp12 format
*               ca.p12
*               cacert.pem
*               cakey.pem
*               caroot.cnf
*               password.txt
*           root_certs/
*               active_roots.pem  The currently active bundle of root certificates
*               mozilla.pem       A bundle of root certificates downloaded from mozilla
*               mozilla_ext.pem   The mozilla bundle augmented with the CA's certificate as a root certificate
*               osx.pem           Bundle of root certificates taken from OSX Keychain
*               osx_ext.pem       OSX root certificates augmented by the custom/local CA
*           sites/
*               deprecated .. I think
*           config.json           A copy of the config file from which the CA certificate and keys was built
*/
class Locator
{
    public:
    /// removes the contents of all directories that exists - makes the store empty
    static void clean(Cert::Store::LocatorSPtr locator);
    /// verifies that all store directories exist
    static bool verify(Cert::Store::LocatorSPtr locator);
    /// creates an empty store structure ensuring that all directories exist
    static void create(Cert::Store::LocatorSPtr locator);

    Locator(Path dirPath);
        void initPaths(Path dirPath);
        void loadConfig();

        /**
        * @var ca_name the name of the certificate authority
        */
        std::string ca_name;

        /**
        * @var ca_name the name of the certificate authority
        */
        std::string ca_state;
    
        /**
        * @var ca_state the name of the state of the certificate authority
        */
        std::string ca_country;
    
        /**
        * @var ca_country the country of the certificate authority
        */
        std::string ca_email;
    
        /**
        * @var ca_organzation the org name of the certificate authority
        */
        std::string ca_organization;


        /**
        * @var the in passphrase for the CA private key
        */
        std::string passin;

        /**
        * @var the out passphrase for the CA private key
        */
        std::string passout;

        /**
        * @var the top directory path for of the certificate store
        */
        Path cert_store_root_dir_path;

        /**
        * @var path to the sub folder (of $cert_store_root_path) in which the Certificate Authority certificate and key is stored
        */
        Path ca_dir_path;

        /**
        * @var ca_cert_pem_file_path - path to CA certificate file in PEM format
        */
        Path ca_cert_pem_file_path;

        /**
        * @var ca_key_pem_path - path to CA private key file in PEM format
        */
//        Path ca_private_key_path;
        Path ca_key_pem_path;
    
        Path ca_password_file_path;
        Path ca_serial_number_file_path;
        Path ca_cnf_file_path;

        /**
        * @var ca_pk12 - path to CA identity (certificate and private key) pk12 file  
        */
        Path ca_pk12_file_path;

        /**
        * @var $ca_self_sign_root_cnf_path - path to openssl config file that creates a CA certificate and key
        */
        Path ca_self_sign_root_cnf_path;

        /**
        * @var full path to a subfolder (of $cert_store_root_path) in which files in pem format containing
        * the root certificates from Mozill and OSX, plus both of these extended to contain "our" CA's
        * root certificate  are stored.
        */
        Path root_certs_dir_path;

        /**
        * @var root_certs - path to a PEM file containing currently active root certificates
        */
        Path root_certs_bundle_file_path;

        /**
        * @var mozilla_root_certs - path to a PEM file containg the latest root certificates from Mozilla
        */
        Path mozilla_root_certs;
        /**
        * @var extended_mozilla_root_certs - path to a PEM file containg the latest root certificates from Mozilla
        * plus the certificate for THE customCA
        */
        Path extended_mozilla_root_certs;

        /**
        * @var osx_root_certs - path to a PEM file containg the latest root certificates from the ox keychain
        */
        Path osx_root_certs;
        /**
        * @var extended_osx_root_certs - path to a PEM file containg the latest root certificates from the osx kychain
        * plus the certificate for THE customCA
        */
        Path extended_osx_root_certs;

//         see root_certs Path active_root_certs;
    
        /**
        * @var sites_dir_path - path of a subfolder (of $cert_store_root_path) in which we store a certificates and
        * and keys for sites/holts resident on the local machine - only for development
        * site or host or server known to the certificate store
        */
        Path sites_dir_path;
        /**
        * @var hosts_dir_path - path of a subfolder (of $cert_store_root_path) in which we store a folder for each
        * host or server known to the certificate store for which we have or will create an intercepting certificate
        */
        Path hosts_dir_path;
        
        Path config_file_path;
        /**
        * return the path to the folder holding certificates and associated files for this host
        */
        Path hostFolder(std::string host);
        Path hostConfigPath(std::string host);
        Path hostKeyPath(std::string host);
        Path hostUnprotectedKeyPath(std::string host);
        Path hostRequestPath(std::string host);
        Path hostP12Path(std::string host);
        /**
        * Returns true of the store holds an original certificate and an intercepting certificate for
        * the specified host
        * @param host - a string name for the host
        * @return Path or boost::filesystem::path, the same thing
        */
        bool certificateExists(std::string host);
    
        /**
        * Returns the path to the original certificate for the named host
        * @param host - string name of the host
        * @return Path or boost::filesystem::path
        */

        Path hostRealCertificatePath(std::string host);
        Path hostRealCertificateChainPath(std::string host);
        /**
        * Returns the path to the intercepting certificate for the named host
        * @param host - string name of the host
        * @return Path or boost::filesystem::path
        */
        Path hostInterceptingCertificatePath(std::string host);

        /**
        * Creates a folder to hold certificates and working files for a specified host
        * @param host - string name of the host
        */
        void createHostFolder(std::string host);
    
        void create(std::string host);
        /**
        * If true the utility operates in debug mode
        */
        bool debug;

    
    private:
};

} //namespace Store
} //namespace Cert
#endif /* marvin_cert_store_hpp */
