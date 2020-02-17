#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <boost/filesystem.hpp>
#include <json/json.hpp>

#include "cert_helpers.hpp"
#include "cert_store.hpp"
#include "cert_store_locator.hpp"


using namespace Cert;
using namespace Cert::Store;

namespace Cert {
namespace Store {

void createHostFolder(Locator& locator, std::string host)
{
    NOT_IMPLEMENTED();
}
void getRealHostCertificate(Locator& locator, std::string host)
{
    NOT_IMPLEMENTED();
}
void createHostConfigFile(Locator& locator, std::string host)
{
    NOT_IMPLEMENTED();
}

void makeSigningRequest(Locator& locator, std::string host)
{
    NOT_IMPLEMENTED();
}
void signRequest(Locator& locator, std::string host)
{
    NOT_IMPLEMENTED();
}
void verifyInterceptorCert(Locator& locator, std::string host)
{
    NOT_IMPLEMENTED();
}

void removePassphrase(Locator& locator, std::string host)
{
    NOT_IMPLEMENTED();
}
void makeP12File(Locator& locator, std::string host)
{
    NOT_IMPLEMENTED();
}



#pragma mark - locator
/**
 * A class that helps tests and examples find the test data.
 *
 * This source file MUST be in a folder that is one level below the project root.
 * And the folder of test data 'fixtures' should be a subfolder of where this source file
 * resides.
 */
Locator::Locator(Path dirPath)
{
    initPaths(dirPath);
//    load_config();
}
/**
* store->init_paths() - initialize all folder and file path properties of the instance
* @param dirPath - the path name of the top level folder for the store
*/
void Locator::initPaths(Path dirPath)
{
    this->debug = false;
    this->cert_store_root_dir_path = dirPath;
    this->ca_dir_path = this->cert_store_root_dir_path / "private";

//    this->hosts_dir_path = this->cert_store_root_path / "certs";
//    this->ca_folder_path = this->cert_store_root_path / "certs";

    this->ca_cert_pem_file_path         = this->ca_dir_path / "cacert.pem";
    this->ca_key_pem_path               = this->ca_dir_path / "cakey.pem";
    this->ca_pk12_file_path             = this->ca_dir_path  / "ca.p12";
    this->ca_self_sign_root_cnf_path    = this->ca_dir_path / "caroot.cnf";
    this->ca_password_file_path         = this->ca_dir_path / "password.txt";
    this->ca_serial_number_file_path    = this->ca_dir_path / "serial_number.txt";
    this->ca_cnf_file_path              = this->ca_dir_path / "caroot.cnf";

    this->root_certs_dir_path = this->cert_store_root_dir_path / "root_certs";
    this->root_certs_bundle_file_path   = this->root_certs_dir_path / "active_roots.pem";
    this->mozilla_root_certs            = this->root_certs_dir_path / "mozilla.pem";
    this->extended_mozilla_root_certs   = this->root_certs_dir_path / "mozilla_ext.pem";
    this->osx_root_certs                = this->root_certs_dir_path / "osx.pem";
    this->extended_osx_root_certs       = this->root_certs_dir_path / "osx_ext.pem";

    this->hosts_dir_path = this->cert_store_root_dir_path / "hosts";
    this->sites_dir_path = this->cert_store_root_dir_path / "sites";
    this->config_file_path = this->cert_store_root_dir_path / "config.json";
}
void Locator::loadConfig()
{
    auto js = Cert::Helpers::fs::file_get_contents(this->config_file_path);
    nlohmann::json j = nlohmann::json::parse(js);
    
    passin = j["passin"];
    passout = j["passout"];
    ca_name = j["ca_name"];
    ca_state = j["ca_state"];
    ca_country = j["ca_country"];
    ca_email = j["ca_email"];
    ca_organization = j["ca_organization"];

}
bool Cert::Store::Locator::verify(Cert::Store::LocatorSPtr locator) {
    return Cert::Helpers::fs::is_directory(locator->cert_store_root_dir_path)
    && Cert::Helpers::fs::is_directory(locator->ca_dir_path)
    && Cert::Helpers::fs::is_directory(locator->sites_dir_path)
    && Cert::Helpers::fs::is_directory(locator->root_certs_dir_path)
    && Cert::Helpers::fs::is_directory(locator->hosts_dir_path);
}

void Cert::Store::Locator::clean(Cert::Store::LocatorSPtr locator) {
    auto td = locator->cert_store_root_dir_path;
    namespace fs=boost::filesystem;
    fs::path path_to_remove = td;
    if (!Cert::Helpers::fs::is_directory(td)) {
        return;
    }
    for (fs::directory_iterator end_dir_it, it(path_to_remove); it!=end_dir_it; ++it) {
        fs::remove_all(it->path());
    }
//    Cert::Helpers::fs::create_dir(locator->ca_dir_path);
//    Cert::Helpers::fs::create_dir(locator->sites_dir_path);
//    Cert::Helpers::fs::create_dir(locator->root_certs_dir_path);
//    Cert::Helpers::fs::create_dir(locator->hosts_dir_path);
}

void Cert::Store::Locator::create(Cert::Store::LocatorSPtr locator) {
    Cert::Store::Locator::clean(locator);
    Cert::Helpers::fs::create_dir(locator->cert_store_root_dir_path);
    Cert::Helpers::fs::create_dir(locator->ca_dir_path);
    Cert::Helpers::fs::create_dir(locator->sites_dir_path);
    Cert::Helpers::fs::create_dir(locator->root_certs_dir_path);
    Cert::Helpers::fs::create_dir(locator->hosts_dir_path);
    if (! Cert::Store::Locator::verify(locator)) {
        throw std::string(__func__) + "failed to verify";
    }
}
#pragma mark - host related path functions
boost::filesystem::path Locator::hostFolder(std::string host)
{
    auto res = hosts_dir_path / Path(host);
    return res;
}
boost::filesystem::path Locator::hostConfigPath(std::string host)
{
    return hostFolder(host) / "config.cnf";
}
boost::filesystem::path Locator::hostKeyPath(std::string host)
{
    return hostFolder(host) / "pass_protected_key.pem";
}
boost::filesystem::path Locator::hostUnprotectedKeyPath(std::string host)
{
    return hostFolder(host) / "key.pem";
}
boost::filesystem::path Locator::hostRealCertificatePath(std::string host)
{
    auto res = hostFolder(host) / "real_certificate.pem";
    return res;
}
boost::filesystem::path Locator::hostRealCertificateChainPath(std::string host)
{
    return hostFolder(host) / "real_certificate_chain.pem";
}
boost::filesystem::path Locator::hostInterceptingCertificatePath(std::string host)
{
    return hostFolder(host) / "real_certificate.pem";
}
boost::filesystem::path Locator::hostRequestPath(std::string host)
{
    return hostFolder(host) / "request.pem";
}
boost::filesystem::path Locator::hostP12Path(std::string host)
{
    return hostFolder(host) / "certificate.p12";
}


void Locator::create(std::string host)
{
    
}

bool Locator::certificateExists(std::string host)
{
    return true;
}
} // namespace Store
} //namespace Cert

