
#include <boost/format.hpp>
#include <boost/process.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ts.h>

#include <cert/x509.hpp>
#include <cert/cert_handshaker.hpp>
#include <cert/cert_helpers.hpp>
#include <cert/cert_store.hpp>

using namespace Cert;
using namespace Cert::Store;

namespace Cert {
namespace Store {


bool debug = false;

Host::Host(Store& store, HostId host) : m_store(store), m_host(host)
{}

bool Host::certExists(Store& store, HostId host)
{
    auto hp = store.m_locator_sptr->hostInterceptingCertificatePath(host);
    bool res = ( (Cert::Helpers::fs::exists(hp)) && (! Cert::Helpers::fs::is_directory(hp)) );
    return res;
}

void Host::rebuildFolder(Store& store, HostId host)
{
    Path hp = store.m_locator_sptr->hostFolder(host);
    // clean out the host folder
    boost::filesystem::remove_all(hp);
    // std::string cmd = str( boost::format("rm -rf %1%/*") % hp.string() );
    // boost::process::system(cmd);
    // Helpers::exec(cmd);
    // now rebfill it
    create(store, host);
}

Path Host::getInterceptorCertificate(Store& store, HostId host)
{
    if( ! store.m_locator_sptr->certificateExists(host) ) {
        create(store, host);
    }
    return store.m_locator_sptr->hostInterceptingCertificatePath(host);
}
void Host::buildInterceptorCert(Store& store, HostId host)
{
    assert(false);
}

void Host::create(Store& store, HostId host)
{
	createFolder(store, host);
	getRealCertificate(store, host);
    #ifdef USE_X509_BUILDER
        buildInterceptorCert();
    #elseif
        createCnfFile(store, host);
        makeSigningRequest(store, host);
        signRequest(store, host);
        verifyInterceptorCert(store, host);
        removePassphrase(store, host);
        makeP12File(store, host);
    #endif
}

void Host::createCertFromConfig(Store& store, HostId host)
{
    makeSigningRequest(store, host);
    signRequest(store, host);
    makeP12File(store, host);
}

void Host::createFolder(Store& store, HostId host)
{
    // HACK TODO fix error handling
    Path hd = store.m_locator_sptr->hostFolder(host);
    auto x1 = (store.m_locator_sptr->hostFolder(host));
    if(x1.string() == "") {
        std::cout << __func__ << std::endl;
    }
    bool x2 = false;
    x2 = Helpers::fs::is_directory(x1);
    if( x2 ) {
            std::cout << std::string(__func__) + " hello" << std::endl;
    }
    if( ! Helpers::fs::is_directory(store.m_locator_sptr->hostFolder(host)) ) {
        boost::filesystem::create_directories(hd);
        //std::string cmd = "mkdir -p " + hd.string();
        //boost::process::system(cmd);
        //system('rm $hd/*');
    }
}
/**
* /todo - fix dont use hardcoded password or delete this function
*/
void Host::createCnfFile(Store& store, HostId host)
{
    Path fn = store.m_locator_sptr->hostRealCertificatePath(host);
    auto data = Cert::Helpers::fs::file_get_contents(fn);

    /**
    * This requires two variables to be set:
    *
    *	$commonName - from the original certificate
    *	$alt_names - subjectAltName in a single line string
    */
    Path dir = store.m_locator_sptr->cert_store_root_dir_path;
    Path ca_dir = store.m_locator_sptr->ca_dir_path;
    Path new_cert_dir = store.m_locator_sptr->hostFolder(host);
//    auto alt_names = subjectAltNames;
    std::string cfg = R"EOD(
[ ca ]
default_ca 		= exampleca

[ exampleca ]
dir 				= {$ca_dir}
certificate 		= {$ca_dir}/cacert.pem
database 			= {$ca_dir}/index.txt
new_certs_dir 		= {$new_cert_dir}/certs
private_key 		= {$ca_dir}/cakey.pem
serial 				= {$ca_dir}/serial

default_crl_days 	= 7
default_days 		= 365
default_md 			= md5

[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
commonName 				= {$common_name}
stateOrProvinceName 	= WA
countryName 			= US
emailAddress 			= rob@blackwellapps.com
organizationName 		= blackwellapps
organizationalUnitName 	= BlackwellApps Root Certificate

[v3_req]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
#subjectAltName = @alt_names
subjectAltName = {$alt_names}

#[alt_names]
#DNS.1 = blackwellapps.com
#DNS.2 = one.blackwellapps.com
#DNS.3 = wto.blackwellapps.com";
)EOD";
    Path cfgfn = store.m_locator_sptr->hostConfigPath(host);
    Cert::Helpers::fs::file_put_contents(cfgfn, cfg);
}
using namespace std;
static string join(const vector<string>& vec, const char* delim)
{
    stringstream res;
    for(const std::string& pem : vec) {
        X509* cert = Cert::x509::Cert_FromPEMString(pem);
        std::string subj_cname, issuer_cname;
        #if 1
        subj_cname = Cert::x509::Cert_GetSubjectNameAsSpec(cert)[NID_commonName];
        issuer_cname = Cert::x509::Cert_GetIssuerNameAsSpec(cert)[NID_commonName];
        #else
        auto sn = Cert::x509::Cert_GetSubjectName(cert);
        auto sn1l = Cert::x509::Name_AsOneLine(sn);
        auto in = Cert::x509::Cert_GetSubjectName(cert);
        auto in1l = Cert::x509::Name_AsOneLine(in);
        subj_cname = sn1l;
        issuer_cname = in1l;
        #endif
        res << "subject: " << subj_cname << std::endl;
        res << "issuer: " << issuer_cname << std::endl;
        res << pem << std::endl;
    }
//    copy(vec.begin(), vec.end(), ostream_iterator<string>(res, delim));
    return res.str();
}
void Host::getRealCertificate(Store& store, HostId host)
{
    auto root_certs_bundle = store.m_locator_sptr->root_certs_bundle_file_path.string();
//    std::string pem_str = Handshaker::getServerCertificatePem(host, root_certs_bundle);
    Cert::Handshaker::Result::Value res = Handshaker::handshakeWithServer(host, root_certs_bundle);
    if( res.is_success() ){
        std::cout << "Handshake succeeded for " << host << std::endl;
	} else {
        std::cout << "Handshake failed for " << host << std::endl;
//        assert(false);
    } 
    std::string pem_str = res.getPem();
    std::vector<std::string> pem_chain_vec = res.getPemChain();
    std::string pem_chain_str = join(pem_chain_vec, "\n");
    if (!Cert::Helpers::fs::is_directory(store.m_locator_sptr->hostFolder(host))) {
        Cert::Helpers::fs::create_dir(store.m_locator_sptr->hostFolder(host));
    }
    Cert::Helpers::fs::file_put_contents(store.m_locator_sptr->hostRealCertificatePath(host), pem_str);
    Cert::Helpers::fs::file_put_contents(store.m_locator_sptr->hostRealCertificateChainPath(host), pem_chain_str);
}
/**
* /todo - fix dont use hardcoded password or delete this function
*/
void Host::makeSigningRequest(Store& store, HostId host)
{
    Path kp = store.m_locator_sptr->hostKeyPath(host);
    Path rp = store.m_locator_sptr->hostRequestPath(host);
    Path cnf = store.m_locator_sptr->hostConfigPath(host);
    /**
    * This is not right - must collec some info from real certificate
    * so that the new interceptor certificate has the correct names
    */
    std::string cmd =
    "openssl req -newkey rsa:2048 -keyout " + kp.string() +
    " -keyform PEM -out " + rp.string() +
    " -outform PEM -passout pass:blackwellapps -sha256 -config " + cnf.string();

}

/**
* /todo - fix dont use hardcoded password or delete this function
*/
void Host::signRequest(Store& store, HostId host)
{
    Path cak = store.m_locator_sptr->ca_key_pem_path;
    Path cac = store.m_locator_sptr->ca_cert_pem_file_path;
    Path rp = store.m_locator_sptr->hostRequestPath(host);
    Path cp = store.m_locator_sptr->hostInterceptingCertificatePath(host);
    Path cfg = store.m_locator_sptr->hostConfigPath(host);
    std::string p_in = "blackwellapps";
    std::string p_out = "blackwellapps";

    std::string cmd = "openssl x509 -req -in " + rp.string() +
       " -inform PEM -sha256 -CA " + cac.string() +
       " -CAkey " + cak.string() +
       " -CAcreateserial -extfile " + cfg.string() +
       " -extensions v3_req -out " + cp.string() +
       " -outform PEM -passin pass:" + p_in + " -days 500 ";

}

/**
* /todo - fix dont use hardcoded password or delete this function
*/
void Host::removePassphrase(Store& store, HostId host)
{
    Path pkp = store.m_locator_sptr->hostKeyPath(host);
    Path upkp = store.m_locator_sptr->hostUnprotectedKeyPath(host);
	
    std::string cmd = "openssl rsa -in " + pkp.string() + " -out " + upkp.string() + " -passin pass:blackwellapps" ;
}

/**
* /todo - fix dont use hardcoded password or delete this function
*/
void Host::makeP12File(Store& store, HostId host)
{
    Path key = store.m_locator_sptr->hostKeyPath(host);
    Path cert = store.m_locator_sptr->hostInterceptingCertificatePath(host);
    Path p12  = store.m_locator_sptr->hostP12Path(host);
	
    std::string cmd = "openssl pkcs12 -export -out " + p12.string() + " -inkey " + key.string() + " -in " + cert.string() + " -passin pass:blackwellapps -passout pass:blackwellapps";
}

void Host::renameCertAndKey(Store& store, HostId host)
{
    Path cp = store.m_locator_sptr->hostInterceptingCertificatePath(host);
    Path kp = store.m_locator_sptr->hostUnprotectedKeyPath(host);
    Path new_cp = store.m_locator_sptr->hostFolder(host) / (host + ".crt.pem");
    Path new_kp = store.m_locator_sptr->hostFolder(host) / (host + ".key.pem");
    boost::filesystem::copy_file(cp, new_cp);
    boost::filesystem::copy_file(kp, new_kp);
}
#if 0
void Host::configFromTemplate(CertStore& store, Path dir)
{
	// auto path = dir ."/template_config.cnf";
	// $home = $root;
	// $info = new SplFileInfo($path);
	// $rp = $info->getRealPath();
	// $contents = file_get_contents($rp);
	// $s_u = '$xx = "'.$contents.'";' ;
	// eval($s_u);
	// $new_content = $xx;
	// file_put_contents($dir."/config.cnf", $new_content);
	// print $new_content . "\n";
}
#endif
bool Host::verifyInterceptorCert(Store& store, HostId host)
{
    Path ca_cert_file = store.m_locator_sptr->ca_cert_pem_file_path;
    Path server_cert = store.m_locator_sptr->hostInterceptingCertificatePath(host);
    std::string tmpl = "openssl verify -verbose -x509_strict -CAfile %1%$ca_cert_file -CApath nosuchpath %2%$server_cert";
    std::string cmd = str(boost::format(tmpl) % ca_cert_file.string() % server_cert.string() );
    boost::process::system(cmd);
    return true;
}
} // namespace Store
} //namespace Cert

