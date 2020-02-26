#include <vector>
#include <boost/format.hpp>
#include <boost/process.hpp>
#include <json/json.hpp>

//#include <cert/cert_store_auth.hpp>
#include <cert/cert_helpers.hpp>
#include <cert/cert_store.hpp>

using namespace Cert;

using namespace boost;

namespace Cert {

filesystem::path caCertPemFilePath(filesystem::path caDirPath) { return (caDirPath / "cacert.pem"); }
filesystem::path caPrivateKeyPemPath(filesystem::path caDirPath) { return (caDirPath / "cakey.pem");}
filesystem::path caPk12FilePath(filesystem::path caDirPath) { return (caDirPath  / "ca.p12");}
filesystem::path caSelfSignRootCnfPath (filesystem::path caDirPath) { return (caDirPath / "caroot.cnf");}
filesystem::path caKeyPasswordFilePath(filesystem::path caDirPath) {return (caDirPath / "password.txt");}
filesystem::path caSerialNumberFilePath(filesystem::path caDirPath) {return (caDirPath / "serial_number.txt");}
filesystem::path caCnfFilePath (filesystem::path caDirPath) {return (caDirPath / "caroot.cnf");}


namespace AuthHelpers {

/**
* Create a string containing openssl config details from which to create a
* self signed certificate authority
*
* @param ca_name std::string - the common name of the CA
* @param state std::string - the state for the CA
* @param country std::string - the country for the CA
* @param email std::string - the email address for the CA
* @param organization std::string - the org name for the CA
* @param cakey_pem Store::Path - path for CA key output
* @return std::string
*/

static std::string ca_cnf_string(
    std::string ca_name,
    std::string state,
    std::string country,
    std::string email,
    std::string organization,
    boost::filesystem::path cakey_pem
)
{
        /// create the openssl cnf file with which to create the CA key and certificate
        if ( state == "") state = "Washington";
        if (country == "") country = "US";
        if (organization == "" ) organization = "Blackwell Apps Root Certification Authority";
        if (email == "") email = "rob@blackwellsapps.com";
    
        std::string cnf=R"EOD(
#
# cnf file for making self signed root
#
[ req ]
default_bits         = 2048
default_keyfile     = %1%
default_md             = md5
default_days         = 365

prompt = no
distinguished_name     = root_ca_distinguished_name

x509_extensions     = root_ca_extensions

[ root_ca_distinguished_name ]
commonName                 = %2%
stateOrProvinceName     = %3%
countryName             = %4%
emailAddress             = %5%
organizationName         = %6%

[ root_ca_extensions ]
basicConstraints     = CA:true
)EOD";
        std::string ks = cakey_pem.string();
        std::string res = str(boost::format(cnf) % ks % ca_name % state % country % email % organization) ;
//        std::cout << res << std::endl;
        return res;
}
/**
* Create a shell command string to make a CA key
* an existing config file
*
* @param cakey_pem Store::Path - path to write the key to
* @param passout std::string - the pass phrase used to secure the key when it is outputted
* @return std::string
*/
static std::string ca_key_cmd(boost::filesystem::path cakey_pem, std::string passout)
{
    std::string p1 = cakey_pem.string();
    std::string p2 = passout;
    
    //    openssl genrsa -out cakey.pem -passout pass:blackwellapps -aes256 2048
    std::string tmpl =R"EOD( openssl genrsa -out %1% -passout pass:%2% -aes256 2048 )EOD";
    std::string cmd = str(boost::format(tmpl) % p1 % p2 );
    return cmd;
}
/**
* Create a shell command string to make a self signed CA certificate using
* an existing config file
*
* @param cakey_pem Store::Path - path to the CA key which must already exist
* @param cacert_pem Store::Path - path for CA certificate
* @param ca_self_signed_root_cnf Store::Path - path to config file to use for openssl x509 command
* @return std::string
*/
static std::string ca_cert_cmd(
    boost::filesystem::path cakey_pem,
    boost::filesystem::path cacert_pem,
    boost::filesystem::path ca_self_signed_root_cnf,
    std::string passin,
    std::string passout)
{
    std::string p1 = ca_self_signed_root_cnf.string();
    std::string p2 = cakey_pem.string();
    std::string p3 = cacert_pem.string();
    std::string p4 = passin;
    
    //openssl req -config self-sign-root.cnf  -key cakey.pem -x509 -days 7300 -sha256 -out cacert.pem -passin pass:blackwellapps
    //openssl req -x509 -newkey rsa:2048 -out %1% -passout pass:blackwellapps -passin pass:blackwellapps -days 3650 -outform PEM -config %2%
    std::string tmpl =
    R"EOD(openssl req -config %1%  -key %2% -new -x509 -days 7300 -sha256 -out %3% -passin pass:%4% )EOD";

    std::string cmd_str = str(boost::format(tmpl) % p1 % p2 % p3 % p4 );;
    return cmd_str;
}
#if 0
static std::vector<std::string> ca_create_args(Path cacert_pem, Path ca_self_signed_root_cnf)
{
    std::vector<std::string> v;
    v.push_back("-x509");
    v.push_back("-newkey");
    v.push_back("rsa:2048");
    v.push_back("-out"); v.push_back(cacert_pem.string());

    v.push_back("-passin"); v.push_back("pass:blackwellapps");
    v.push_back("-passout"); v.push_back("pass:blackwellapps");

    v.push_back("-days"); v.push_back("3650");
    v.push_back("-outform"); v.push_back("PEM");
    v.push_back("-config"); v.push_back(ca_self_signed_root_cnf.string());
    return v;
}
#endif
/**
* Create a shell command string to convert CA key and cert into pk12 format
*
* @param ca_name std::string - the comman name of the CA
* @param cakey_pem Store::Path - path for CA private key
* @param cacert_pem Store::Path - path for CA certificate
* @param passin std::string - in password
* @param passout std::string - out passowrd
* @param ca_pk12 Store::Path - path for CA certificate + pkey in pk12 format
* @return std::string
*/
static std::string ca_pk12_cmd(
    std::string ca_name,
    boost::filesystem::path cakey_pem,
    boost::filesystem::path cacert_pem,
    boost::filesystem::path ca_pk12,
    std::string passin,
    std::string passout
)
{
    /// create a PKCS12 file for osx keychain import
    std::string tmpl =
        R"EOD( openssl pkcs12 -name %1% -export -out %2% -inkey %3% -in %4% -passin pass:%5% -passout pass:%6% )EOD";

    std::string cmd = str(boost::format(tmpl) % ca_name % ca_pk12 % cakey_pem.string() % cacert_pem.string() % passin % passout );
    return cmd;
}

void runCommand(std::string cmd, bool withStdout) {
    std::error_code ec;
    if (withStdout) {
        boost::process::system(cmd, ec);
    } else {
        boost::process::system(cmd, boost::process::std_out > boost::process::null, boost::process::std_err > boost::process::null, ec);
    }
    if(ec) {
        THROW(" failed with command " << cmd << " msg:" << ec.message());
    }
}

/**
 * Warning: this function executes console commands using the system() lib function
 *
 * create a certificate authority in the provide Store. Specifically that means:
 *
 *   -   create an openssl cnf file with the relevant ca details and save it in the stores ca directory
 *   -   put the password for the ca's private key in a file and save that in the store's ca directory
 *   -   run an openssl command to create a new key in pem format and save in the stores'ca directory and protect that
 *       key with the password saved in earlier step
 *   -   run an openssl command to generate a self signed certificate using the key geneated in the previous
 *       step and save that in the store's ca directory
 *   -   run an openssl command to combine the newly created private key and certificate into a pkcs12
 *       file and put that in the store' ca directory
 *
 * @param store Store - the certificate store where the CA is to be created
 *
 * Assumption : details of the CA have already been stored in the store config file
 *
 * Warning: this function executes console commands using the system() lib function
 */
void createCertAuthority(boost::filesystem::path caDirPath, boost::filesystem::path caJsonSpecificationFile)
{
    bool withStdout = false;
    if (!Cert::Helpers::fs::is_directory(caDirPath)) {
        THROW("caDirPath is not a valid directory path: " << caDirPath.string());
    }
    std::string js = Cert::Helpers::fs::file_get_contents(caJsonSpecificationFile);
    nlohmann::json j = nlohmann::json::parse(js);
    std::string ca_name = j["ca_name"];
    std::string ca_state = j["ca_state"];
    std::string ca_country = j["ca_country"];
    std::string ca_email = j["ca_email"];
    std::string ca_organization = j["ca_organization"];
    std::string passin = j["passin"];
    std::string passout = j["passout"];
    std::string password = j["ca_key_password"];
    boost::filesystem::path cacert_pem = caCertPemFilePath(caDirPath);
    boost::filesystem::path cakey_pem = caPrivateKeyPemPath(caDirPath);
    boost::filesystem::path ca_pk12 = caPk12FilePath(caDirPath);
    boost::filesystem::path ca_self_sign_root_cnf = caSelfSignRootCnfPath(caDirPath);
    boost::filesystem::path ca_password_file = caKeyPasswordFilePath(caDirPath);
    
    auto cnf_str = ca_cnf_string(
        ca_name,
        ca_state,
        ca_country,
        ca_email,
        ca_organization,
        cakey_pem
    );
    Cert::Helpers::fs::file_put_contents(ca_self_sign_root_cnf, cnf_str);
    Cert::Helpers::fs::file_put_contents(ca_password_file.string(), password);
    std::string cmd1 = ca_key_cmd(cakey_pem, passout);
    std::string cmd2 = ca_cert_cmd(cakey_pem, cacert_pem, ca_self_sign_root_cnf, passin, passout);
    std::string cmd3 = ca_pk12_cmd(ca_name, cakey_pem, cacert_pem,ca_pk12,passin, passout);
//        std::cout << cmd2 << std::endl;

    runCommand(cmd1, withStdout);
    runCommand(cmd2, withStdout);
    runCommand(cmd3, withStdout);
}

} // namespace AuthHelpers
} //namespace Cert

