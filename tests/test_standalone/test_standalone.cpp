#include <boost/filesystem.hpp>
#include <boost/algorithm/string/replace.hpp>
#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include <cert/x509.hpp>
#include <cert/cert_helpers.hpp>
#include <cert/cert_store.hpp>
//#include "cert_store_authority.hpp"
#include <cert/cert_store_host.hpp>
#include <cert/cert_builder.hpp>
#include "test_helpers.hpp"
#include <cert/cert.hpp>
using namespace Cert::Store;

int main( int argc, char* argv[] )
{
    
    // global setup...

    char* t_argv[2] = {argv[0], (char*)"*"}; // change the filter to restrict the tests that are executed
    int t_argc = 2;
    int result = Catch::Session().run( t_argc, t_argv );

    // global clean-up...

    return result;
}

X509* buildCertificateExample(Cert::Authority& cert_auth)
{
    /**
    * specify the subject name
    */
    Cert::x509::NameSpecification subject_name_spec = {
        {Cert::x509::NameNid_countryName, "AU"},
        {Cert::x509::NameNid_stateOrProvince, "NSW"},
        {Cert::x509::NameNid_organizationName, "MyOrganization"},
        {Cert::x509::NameNid_organizationalUnitName, "MyOrganization-Unit-One"},
        {Cert::x509::NameNid_commonName, "myorg.com"},
    };
    /**
    * specify the extensions to add
    */
    Cert::x509::ExtSpecifications extension_specifications = {
        {Cert::x509::ExtNid_basicConstraints, "CA:false"},
        {Cert::x509::ExtNid_keyUsage, "digitalSignature, keyEncipherment"},
        {Cert::x509::ExtNid_extendedKeyUsage, "serverAuth, clientAuth"},
        {Cert::x509::ExtNid_subjectKeyIdentifier, "hash"}
    };
    /**
    * specify the subject_alt_name extension - do this as a separate argument to this
    * function to force the specification of alternate DNS names
    */
    std::string subject_alt_names= "DNS:alternate_one.com,DNS:alternatie_two.com";
    /**
     * generate a key pair
     */
    EVP_PKEY* new_pkey = Cert::x509::Rsa_Generate();
    /**
     * Now build the certificate
     */
    long ser_num = cert_auth.getNextSerialNumber();
    X509* cert = Cert::x509::create(
            cert_auth.getCACert(),
            cert_auth.getCAPKey(),
            ser_num,
            2L,
            new_pkey,
            -(60*60*24*365), //not before one year before now
            (60*60*24*365*10), // not after 10 years from now
            subject_name_spec,
            subject_alt_names,
            extension_specifications
    );
    /**
     * check it verified against the CA that signed it
     */
    auto vres = Cert::x509::Cert_Verify(cert, cert_auth);
    CHECK(vres);
    EVP_PKEY_free(new_pkey);
    return cert;
}


/// test all certificate get functions in a non-cluttered environment
/// no memory leaks
TEST_CASE("standalone","")
{
    using namespace boost::filesystem;
    using namespace Cert;
    using namespace x509;
    path this_file{__FILE__};
    path this_dir = this_file.parent_path();
    path test_dir = this_dir.parent_path();
    path fixture = test_dir / "fixture" / "CA";
    std::string geeks_host = "www.geeksforgeeks.org";
    path host_geeks = fixture / "hosts" / geeks_host / "real_certificate.pem";
    if (! is_regular_file(host_geeks)) {
        REQUIRE(false);
    }
    Cert::Store::Locator locator{fixture};
    auto x = locator.hostRealCertificatePath("www.geeksforgeeks.org");
    CHECK((x.string() == host_geeks));
    std::string s = fixture.string();

    SECTION("x509_gets")
    {

        X509* c = Cert_ReadFromFile(host_geeks.string());
        /// you now own the X509*

        std::string c_pem_as_string = Cert_PrintToString(c);
        std::string issuer = Cert_GetIssuerNameAsOneLine(c);
        std::string subject = Cert_GetSubjectNameAsOneLine(c);
        boost::optional<std::string> altnames = Cert_GetSubjectAlternativeNamesAsString(c);
        std::string altstr = altnames.get();
        auto p1  = Cert_GetVersion(c);
        auto p21 = Cert_GetIssuerNameAsMultiLine(c);
        auto p22 = Cert_GetIssuerNameAsOneLine(c);
        auto p23 = Cert_GetIssuerNameAsSpec(c);

        auto p31 = Cert_GetSubjectAlternativeDNSNames(c);
        auto p32 = Cert_GetSubjectNameAsMultiLine(c);
        auto p33 = Cert_GetSubjectNameAsOneLine(c);
        auto p34 = Cert_GetSubjectNameAsSpec(c);
        auto p35 = Cert_GetSubjectName(c);
        
        auto p41 = Cert_GetSubjectAlternativeDNSNames(c);
        auto p42 = Cert_GetSubjectAlternativeNamesAsString(c);
        auto p43 = Cert_altNames(c);
        auto p45 = Cert_GetSubjectAltName(c);

        auto p51 = Cert_GetNotAfter(c);
        auto p52 = Cert_GetNotBefore(c);

        /// you DO NOT OWN This
        X509_EXTENSIONS* extensions = Cert_GetExtensions(c);
        /// so DO NOT do this - valgrind has spoken
        // sk_X509_EXTENSION_free(extensions);
        auto ex2 = Cert_extensionsAsDescription(c);

        auto ps1 = Cert_PEMString(c);

        /// this one produces a leak if we make the BIO NOCLOSE - see the code
        /// seems to be a recent change in openssl 1.1.1f
        X509* c2 = Cert_FromPEMString(c_pem_as_string);

        /// you now own the pkey
        EVP_PKEY* pkey = Cert_GetPublicKey(c);
        
        X509_free(c2);
        EVP_PKEY_free(pkey);
        X509_free(c);
        std::cout << "cert::x509 gets" << std::endl;
    }
    SECTION("x509 ")
    {
        path store_root = locator.cert_store_root_dir_path;
        Cert::Store::LocatorSPtr locator_sptr = std::make_shared<Cert::Store::Locator>(store_root);
        Cert::AuthoritySPtr cert_auth = Cert::Authority::load(locator_sptr->ca_dir_path);

        X509* x = buildCertificateExample(*cert_auth);
        X509_free(x);
        std::cout << "buildCertificate" << std::hex << x << std::endl;
    }
    SECTION("gets required by mitm")
    {
        path store_root = locator.cert_store_root_dir_path;
        Cert::Store::LocatorSPtr locator_sptr = std::make_shared<Cert::Store::Locator>(store_root);
        Cert::AuthoritySPtr cert_auth = Cert::Authority::load(locator_sptr->ca_dir_path);
        X509* original_cert_X509 = Cert_ReadFromFile(host_geeks.string());

            // call the genuine forger function
        Cert::Certificate cert(original_cert_X509);

        Cert::Builder builder(*cert_auth);

        Cert::Identity id = builder.buildMitmIdentity(geeks_host, cert);
        // bool b0 = mitmWorked(original_cert_X509, geeks_host, id);
        std::cout << "mitm" << " " << std::hex << id.getX509() << std::endl;
        X509_free(original_cert_X509);
        return;

    }
    SECTION("handshake")
    {
        using namespace boost::filesystem;

        path  root_certificates_file_path = locator.root_certs_bundle_file_path;
        if (!exists(root_certificates_file_path)) {
            throw std::string(__func__) + std::string(" openssl default cert file does not exist ") + (root_certificates_file_path.string());
        }
        // X509_STORE_load_locations(store, df.c_str(), NULL);
        // SSL_CTX_set_cert_store(ctx.native_handle(), store);
        Cert::Handshaker::Result::Value v =  Cert::Handshaker::handshakeWithServer(geeks_host, root_certificates_file_path.string());
        std::cout << "handshake" << std::endl;
    }
}
