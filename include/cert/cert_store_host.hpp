#ifndef certlib_cert_store_host_hpp
#define certlib_cert_store_host_hpp

#include <boost/filesystem.hpp>
#include <boost/asio.hpp>

#include "cert_store_locator.hpp"
#include "cert_store_host.hpp"
#include "cert_store_store.hpp"
#include "cert_keychain.hpp"
#include "cert_mozilla.hpp"

namespace Cert {
namespace Store {
/**
* \brief Provides an interface to the details of a hosts held within a Cert::Store
*/
class Host
{
public:

	static const bool debug = false;
    
    Host(::Cert::Store::Store& store, HostId host);
    
    /**
    *   returns true if a certificate has alredy been created for this host
    *
    * @param host HostId - the identifier for the host in question
    * @param store Store& - a ref to the subject certificate store
    */
	static bool certExists(Store& store, HostId host);

	/**
	* Host::rebuild_folder - repopulates a host folder
	*
	* @param store - the appplicable certificate store 
	* @param host - a host name
	*/
	static void rebuildFolder(Store& store, HostId host);

	/**
	* Host::get_interceptor_certificate - gets the path to a hosts interceptor certificate,
	* creating it if neccessary.
	*
	* @param store - the applicable crtificate store
	* @param host - the name of the subject host
	* @return path name of interceptor certificate file in PEM format
	* @throws if soomething goes wrong
	*/
	static Path getInterceptorCertificate(Store& store, HostId host);
 
    /**
    * Builds an interceptor certificate using  certificate builder function.
    *
    * @param store - the certificate store in question
    * @param host - name of the subject host
    * @throws if something goes wrong
    */
    static void buildInterceptorCert(Store& store, HostId host);
	/**
	* Host::create - Creates and populates a host's'folder in a certificate store
	* 
	* @param store - the certificate store in question
	* @param host - name of the subject host
	* @throws if something goes wrong
	*/
	static void create(Store& store, HostId host);

	static void createCertFromConfig(Store& store, HostId host);
	
	/**
	* Host::create_folder - Create the host folder in a certificate store
	*
	* @param store - the certificate store in question
	* @param host - name of the subject host
	* @throws if something goes wrong
	*/
	static void createFolder(Store& store, HostId host);
	/**
	* Host::create_cnf_file - creates an openssl cnf file
	* Using info in the hosts real certificate create an openssl config file
	* to be used in creating a certificate signing request.
	*
	* The key is getting the CN and subjectAltName from the real certificate 
	*
	* @param store - the certificate store in question
	* @param host - name of the subject host
	* @throws if something goes wrong
	*
	*/
	static void createCnfFile(Store& store, HostId host);
	
	/**
	* Use openssl s_client command to download the hosts real certificate
	*/
	static void getRealCertificate(Store& store, HostId host);
    
	/**
	* Generate a signing request for the host and save it as a PEM file
	*
	* @param store - the certificate store in question
	* @param host - name of the subject host
	* @throws if something goes wrong
	*
	*/
	static void makeSigningRequest(Store& store, HostId host);
	
	/**
	* Use openssl x509 command to sign a hosts certificate request.
	* Make sure it is a v3 certificate
	*
	* @param store - the certificate store in question
	* @param host - name of the subject host
	* @throws if something goes wrong
	*
	*/
	static void signRequest(Store& store, HostId host);

	/**	
	*
	* @param store - the certificate store in question
	* @param host - name of the subject host
	* @throws if something goes wrong
	*
	*/
	static void removePassphrase(Store& store, HostId host);
	
	/**	
	*
	* @param store - the certificate store in question
	* @param host - name of the subject host
	* @throws if something goes wrong
	*
	*/
	static void makeP12File(Store& store, HostId host);

	/**
	*
	* @param store - the certificate store in question
	* @param host - name of the subject host
	* @throws if something goes wrong
	*
	*/
	static void renameCertAndKey(Store& store, HostId host);

	static void conf( std::string dir);

	/**
	* Load a config file template ($dir/template_config.cnf), 
	* substitutute the value $self->top_dir
	* for the variable $home and saves the substituted value
	* as $dir/config.cnf
	*/
	static void configFromTemplate(Store& store, std::string dir);

	// # openssl verify -verbose -x509_strict -CAfile allcerts.pem -CApath nosuchdir ssltest.crt.pem
	// PWD=`pwd`
	// CAFILE=${PWD}/allroots/combined-cacert.pem
	// CAFILE=/usr/local/ssl/cert.pem NOTE - this may be wrong
	// SRVCERT=${PWD}/certs/$1/real_certificate.pem
	// openssl verify -verbose -x509_strict -CAfile ${CAFILE} -CApath nosuchdir ${SRVCERT}
	/**
	* Host::verifyInterceptorCertificate - verifies that the interceptor certificate will verify 
	* against the certificate authority. This is a consistence check for a certificate store and host
	*
	* @param store - the certificate store in question
	* @param host - name of the subject host
	* @return nothing
	* @throws if something goes wrong
	*
	*/
	static bool verifyInterceptorCert(Store& store, HostId host);
	private:
        Store& m_store;
        HostId m_host;
};

} //namespace Store
} //namespace Cert
#endif
