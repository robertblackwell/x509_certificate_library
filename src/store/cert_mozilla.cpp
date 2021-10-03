#include <boost/format.hpp>
#include <boost/process.hpp>

#include <cert/cert.hpp>
#include <cert/cert_store.hpp>
#include <cert/cert_mozilla.hpp>
#define MOZ_URL "https://curl.se/ca/cacert.pem"
using namespace Cert;

namespace Cert {

void Mozilla::importRootCerts(Store::Store& store)
{
    Store::LocatorSPtr loc = store.m_locator_sptr;
    
    Path moz_roots = loc->mozilla_root_certs;
    Path moz_ext_roots = loc->extended_mozilla_root_certs;
    std::string tag = loc->ca_name;
    Path src2 = loc->ca_cert_pem_file_path;
    // wget is not always available on osx
    #ifdef USE_WGET
    //"wget -O {$moz_roots} https://curl.haxx.se/ca/cacert.pem");
    //
    // we require wget to download mozilla root certs but osx does  not come with wget.
    // so test toi see if we have it and abort if not
    //
    std::vector<boost::filesystem::path> paths = {
        boost::filesystem::path("/usr/bin"),
        boost::filesystem::path("/usr/local/bin"),
    };
    
    auto wget_test = boost::process::search_path("wget", paths);
    if (wget_test.string() == "") {
        THROW("could not find wget");
    }
    std::string wget = "/usr/local/bin/wget";
    wget = wget_test.string();
    std::string tmpl = "%1% -O %2% https://curl.haxx.se/ca/cacert.pem";
//    std::string tmpl = "/usr/local/bin/wget %1% ";
    std::string cmd = str(boost::format(tmpl) % wget % moz_roots.string());
    std::error_code ec;
    boost::process::system(cmd, boost::process::std_out > boost::process::null, ec);
    std::cout << cmd << std::endl;
    if(ec) {
        THROW(__func__ << " error while processing command " << cmd << " error msg: " << ec.message());
    }
    #else
    
    std::string curl = "/usr/bin/curl";
    /// @NOTE the -k option turns off certificate checking - because I had a bug in my bash profile
    // std::string tmpl = "%1% -k -o %2% https://curl.haxx.se/ca/cacert.pem";
    std::string tmpl = "%1% --insecure -o %2% %3%";
//    std::string tmpl = "/usr/local/bin/wget %1% ";
    std::string cmd = str(boost::format(tmpl) % curl % moz_roots.string() % MOZ_URL);
    std::cout << cmd << std::endl;
    std::error_code ec;
    boost::process::system(cmd);//, boost::process::std_out > boost::process::null, boost::process::std_err > boost::process::null,  ec);
    if(ec) {
        THROW(__func__ << " error while processing command " << cmd << " error msg: " << ec.message());
    }
    // now add our CA cert to the root file
    assert(boost::filesystem::exists(store.m_locator_sptr->mozilla_root_certs));
    
    #endif
    Cert::Helpers::fs::combinePEM(loc->extended_mozilla_root_certs, loc->mozilla_root_certs, loc->ca_cert_pem_file_path, loc->ca_name);
}
} //namespace Cert

