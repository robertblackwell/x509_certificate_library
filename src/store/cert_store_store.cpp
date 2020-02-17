 #include <fstream>
#include <iostream>
#include <chrono>
#include <boost/filesystem.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/thread.hpp>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <json/json.hpp>

#include "cert.hpp"
#include "cert_store.hpp"
#include "cert_mozilla.hpp"
#include "cert_keychain.hpp"
#include "cert_authority.hpp"

using namespace Cert;
using namespace Cert::Store;

namespace Cert {
namespace Store {


#pragma mark - cert_store
LocatorSPtr Store::getLocator()
{
    return m_locator_sptr;
}
AuthoritySPtr Store::getAuthority()
{
    return m_cert_auth_sptr;
}
StoreSPtr Store::load(Path storePath)
{
    auto store_sptr = std::make_shared<Store>(storePath);
    store_sptr->loadConfig();
    store_sptr->loadCertAuth();
    return store_sptr;
}
/**
 * private constructor - this does not do everything you need it to do. Dont use it to create
 * a functional Store. It only initializes the locator
 */
Store::Store(Path dirPath) : m_locator_sptr(std::make_shared<Locator>(dirPath))
{
    m_cert_auth_sptr = nullptr;
//    if ( ! Cert::Helpers::fs::is_directory(dirPath)) {
//        throw  std::runtime_error("error " + dirPath.string() + " does not exist");
//    }
//    m_locator_sptr->loadConfig();
}

StoreSPtr Store::makeEmpty(Path storeDirPath)
{
    StoreSPtr store_sptr = std::make_shared<Store>(storeDirPath);
    store_sptr->makeClean();
    return store_sptr;
}

StoreSPtr Store::makeWithCA(Path storeDirPath, Path caJsonSpecificationFile)
{
    StoreSPtr store_sptr = makeEmpty(storeDirPath);
    store_sptr->m_cert_auth_sptr = Cert::Authority::create(store_sptr->m_locator_sptr->ca_dir_path, caJsonSpecificationFile);
    store_sptr->saveConfig(caJsonSpecificationFile.string());
    store_sptr->loadConfig();
    store_sptr->loadCertAuth();
    return store_sptr;
}
void Store::addCACertToKeychain()
{
    assert(false); // not implemented
}
void Store::rootCertsFromKeychain()
{
    ::Cert::Keychain::importRootCerts(*this, "");
}
void Store::rootCertsKeychainActive()
{
    boost::filesystem::copy_file(m_locator_sptr->extended_osx_root_certs, m_locator_sptr->root_certs_bundle_file_path);
}
void Store::rootCertsFromMozilla()
{
    ::Cert::Mozilla::importRootCerts(*this);
}
void Store::rootCertsMozillaActive()
{
    boost::filesystem::copy_file(m_locator_sptr->extended_mozilla_root_certs, m_locator_sptr->root_certs_bundle_file_path);
}
#ifdef USE_STORE
Cert::Identity Store::forgeHostIdentity(HostId host)
{
    std::string bundle_path = m_locator_sptr->root_certs_bundle_file_path.string();
    std::string pem = Cert::Handshaker::getServerCertificatePem(host, bundle_path);
    Cert::Certificate original_cert(pem);
//    X509* original_cert = Cert::x509::Cert_FromPEMString(pem);
    Cert::Builder builder(*m_cert_auth_sptr);
    Cert::Identity res = builder.buildMitmIdentity(original_cert);
    return res;
}
Cert::Identity Store::forgeHostIdentity(X509* original_certificate)
{
    Cert::Certificate cert(original_certificate);
    Cert::Builder builder(*m_cert_auth_sptr);
    Cert::Identity res{builder.buildMitmIdentity(cert)};
    return res;
}
#endif
/**
* makeClean - clean certificate store with all folders and cfg file freshly created
*/
void Store::makeClean()
{
    LocatorSPtr locator = m_locator_sptr;
    Cert::Helpers::fs::create_dir(locator->cert_store_root_dir_path);
    Cert::Helpers::fs::create_dir(locator->ca_dir_path);
    Cert::Helpers::fs::create_dir(locator->sites_dir_path);
    Cert::Helpers::fs::create_dir(locator->root_certs_dir_path);
    Cert::Helpers::fs::create_dir(locator->hosts_dir_path);
}

void Store::loadConfig()
{
    auto js = Cert::Helpers::fs::file_get_contents(m_locator_sptr->config_file_path);
    if( js == "")
        assert(false);
    nlohmann::json j = nlohmann::json::parse(js);
}

void Store::loadCertAuth()
{
    m_cert_auth_sptr = Cert::Authority::load(m_locator_sptr->ca_dir_path);
}
void Store::saveConfig(std::string caJsonConfigFilePath)
{
    LocatorSPtr locator = m_locator_sptr;
    auto js = Cert::Helpers::fs::file_get_contents(caJsonConfigFilePath);
    if( js == "")
        assert(false);
    nlohmann::json j = nlohmann::json::parse(js);
    Cert::Helpers::fs::file_put_contents(m_locator_sptr->config_file_path, js);
}

} // namespace Store
} //namespace Cert
