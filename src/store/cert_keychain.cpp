#include <boost/format.hpp>
#include <boost/process.hpp>
#include "cert_helpers.hpp"
#include "cert_store.hpp"
#include "cert_keychain.hpp"

using namespace Cert;
using namespace Cert::Store;

namespace Cert {

void Keychain::importCAIdentity(Store::Store& store, std::string keyChain)
{
    #if 0
    Locator loc = store.m_locator_sptr;
    std::string ca_identity = loc->ca_pk12.string();
    std::string p_opts = "-p ssl";
    
    //"sudo security add-trusted-cert -d -r trustRoot $p_opts -k /Library/Keychains/System.keychain {$ca_identity}"
    std::string tmpl = "sudo security add-trusted-cert -d -r trustRoot %1% -k /Library/Keychains/System.keychain %2%"
    std::string cmd = str(boost::format(tmpl) % p_opts % ca_identity );
    boost::pocess::system(cmd);
    #endif
}
void Keychain::importRootCerts(Store::Store& store, std::string keyChain)
{
    LocatorSPtr loc = store.m_locator_sptr;
    
    Path osxroots = loc->osx_root_certs;
    Path osx_ext_roots = loc->extended_osx_root_certs;
    std::string ca_name = loc->ca_name;
    boost::process::system("security find-certificate -a -p ", boost::process::std_out > osxroots.string());
    Cert::Helpers::fs::combinePEM(loc->extended_osx_root_certs, loc->osx_root_certs, loc->ca_cert_pem_file_path, loc->ca_name);

    #if 0
    \CertUte\CertStore\Helpers::exec("security find-certificate -a -p > {$osxroots}");
    $roots = file_get_contents($osxroots);
    $tag = "\n{$ca_name} \n========================\n";
    $ca_root = file_get_contents($store->cacert_pem);
    file_put_contents($osx_ext_roots, $roots . $tag . $ca_root);
    #endif
}
} //namespace Cert

