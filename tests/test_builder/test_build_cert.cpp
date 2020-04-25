#include <iostream>
#include <map>
#include <boost/filesystem.hpp>
#include <catch2/catch.hpp>

#include <cert/x509.hpp>
#include <cert/cert.hpp>
#include <cert/cert_store.hpp>

#include "test_fixture_new.hpp"

using namespace boost::filesystem;
/**
 * Use Cert:x509::create() to make the certificate
 *
 * A function that builds an example certificate using the Cert::Authority
 * and verifies the result agains the same ca.
 *
 * Use Cert:x509::create() to make the certificate
 *
 * @param cert_auth
 * @return The new certificate in PEM format as a std::string
 */
std::string buildCertificateExample(Cert::Authority& cert_auth)
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
    X509* cert = Cert::x509::create(
            cert_auth.getCACert(),
            cert_auth.getCAPKey(),
            cert_auth.getNextSerialNumber(),
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
    BIO* out_bio;
    out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
//    Cert::x509::Cert_Print(cert, out_bio);
    std::string ss = Cert::x509::Cert_PEMString(cert);
    X509_free(cert);
    EVP_PKEY_free(new_pkey);
    BIO_free(out_bio);
    return ss;
}
/**
 * Use Cert:Builder::build() to make the certificate
 *
 * A function that builds an example certificate using the Cert::Authority
 * and verifies the result agains the same ca.
 *
 * @param cert_auth
 * @return The new certificate in PEM format as a std::string
 */

std::string buildCertificateExample2(Cert::Authority& cert_auth)
{
    /*
    * specify the subject name
    */
    Cert::x509::NameSpecification subject_name_spec = {
        {Cert::x509::NameNid_countryName, "AU"},
        {Cert::x509::NameNid_stateOrProvince, "NSW"},
        {Cert::x509::NameNid_organizationName, "MyOrganization"},
        {Cert::x509::NameNid_organizationalUnitName, "MyOrganization-Unit-One"},
        {Cert::x509::NameNid_commonName, "myorg.com"},
    };
    /*
    * specify the extensions to add
    */
    Cert::x509::ExtSpecifications extension_specifications = {
        {Cert::x509::ExtNid_basicConstraints, "CA:false"},
        {Cert::x509::ExtNid_keyUsage, "digitalSignature, keyEncipherment"},
        {Cert::x509::ExtNid_extendedKeyUsage, "serverAuth, clientAuth"},
        {Cert::x509::ExtNid_subjectKeyIdentifier, "hash"}
    };
    /*
    * specify the subject_alt_name extension - do this as a separate argument to this
    * function to force the specification of alternate DNS names
    */
    std::string subject_alt_names= "DNS:alternate_one.com,DNS:alternatie_two.com";
    EVP_PKEY* new_pkey = Cert::x509::Rsa_Generate();
    ::Cert::Builder builder(cert_auth);
    Cert::Certificate res = builder.build(
            cert_auth.getNextSerialNumber(),
            2L,
            new_pkey,
            -(60*60*24*365), //not before one year before now
            (60*60*24*365*10), // not after 10 years from now
            subject_name_spec,
            subject_alt_names,
            extension_specifications
    );
    auto vres = Cert::x509::Cert_Verify(res.native(), cert_auth);
    CHECK(vres);

    EVP_PKEY_free(new_pkey);
    std::string ss =  res.asPEMString();
//    std::cout << res.printToString() << std::endl;
    return ss;
}

/**
 * Build a Mitm certificate by to illustrate how it is done and test the process.
 * Later this will get wrapped in Build::buildMitmIdentity()
 * only used during development when testing how to forge a certificate
*/
std::string forgeCertificate(X509* original_cert, Cert::Authority& certAuth)
{
    /** Get the subject name from the original certificate - this is one of the things
     * that allows the Mitm certificate to pretent to be the original host*/
    Cert::x509::NameSpecification  subject_name_spec = Cert::x509::Cert_GetSubjectNameAsSpec(original_cert);
    /**
     * specify the extensions to add - we dont copy these from the original certificate
     * to ensure we have control of them
     */
    Cert::x509::ExtSpecifications extension_specifications = {
        {Cert::x509::ExtNid_basicConstraints, "CA:false"},
        {Cert::x509::ExtNid_keyUsage, "digitalSignature, keyEncipherment"},
        {Cert::x509::ExtNid_extendedKeyUsage, "serverAuth, clientAuth"},
        {Cert::x509::ExtNid_subjectKeyIdentifier, "hash"}
    };
    
    /*
    * specify the subject_alt_name extension - do this as a separate argument to this
    * function to force the specification of alternate DNS names
    */
    std::string subject_alt_names= "DNS:alternate_one.com,DNS:alternatie_two.com";
    
    /**
    * This is tricky and needs explanation
    */
    /** get the subject_alt_names from the orignal certificate */
    boost::optional<std::string> subject_alt_opt = Cert::x509::Cert_GetSubjectAlternativeNamesAsString(original_cert);
    std::string subject_alt_names_string = (subject_alt_opt) ? subject_alt_opt.get() : "";
//    auto san = Cert::x509::Cert_GetSubjectAlternativeDNSNames(original_cert);
//    auto ssan = Cert::x509::Cert_extensionsAsDescription(original_cert);

    /** a new key pair */
    EVP_PKEY* new_pkey = Cert::x509::Rsa_Generate();

    X509* cert = Cert::x509::create(
            certAuth.getCACert(),
            certAuth.getCAPKey(),
            certAuth.getNextSerialNumber(),
            2L,
            new_pkey,
            -(60*60*24*365), //not before one year before now
            (60*60*24*365*10), // not after 10 years from now
            subject_name_spec,
            subject_alt_names_string,
            extension_specifications
    );
    auto vres = Cert::x509::Cert_Verify(cert, certAuth);
    CHECK(vres);
    BIO* out_bio;
    out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
//    Cert::x509::Cert_Print(cert, out_bio);
    std::string ss = Cert::x509::Cert_PEMString(cert);
    auto id = std::make_shared<Cert::Identity>(cert, new_pkey);
//    X509_free(cert);
//    EVP_PKEY_free(new_pkey);
    BIO_free(out_bio);
    return ss;
}

//TEST_CASE_METHOD(TestFixture, "ca-privatekey")
//{
//    TestHelper helper;
//    std::string pkey_path = this->ca_key_path;
//    auto pkey =  Cert::x509::PKey_ReadPrivateKeyFrom(pkey_path);
//    CHECK(pkey != NULL);
//    std::string cert_path = this->ca_cert_path;
//    auto ca_cert = Cert::x509::Cert_ReadFromFile(cert_path);
//    CHECK(ca_cert != NULL);
//}
TEST_CASE_METHOD(TestFixtureNew, "builder", "[]")
{
    this->loadExisting();
    
    path store_root = this->storeRootDirPath();
    Cert::Store::LocatorSPtr locator_sptr = std::make_shared<Cert::Store::Locator>(store_root);
    Cert::AuthoritySPtr cert_auth = Cert::Authority::load(locator_sptr->ca_dir_path);
    std::string pem =  buildCertificateExample(*cert_auth);
    CHECK(pem.size() > 0);
    X509* cert = Cert::x509::Cert_FromPEMString(pem);
    std::string moz_only = this->mozRootCertificateBundleFilePath().string();
    CHECK( ! Cert::x509::Cert_Verify(cert, moz_only)); // VERIFY IS EXPECTED TO FAIL mozilla cert bundle does
    //std::cout << "expected : the local CA is not in the Mozilla bundle" << std::endl;
    std::string moz_with_ca = this->mozCombinedRootCertificateBundleFilePath().string();
    CHECK( Cert::x509::Cert_Verify(cert, moz_with_ca)); // VERIFY IS EXPECTED TO SUCCEED this version doesa have the local CA
    X509_free(cert);
}

TEST_CASE_METHOD(TestFixtureNew, "builder2", "")
{
    this->loadExisting();
    auto store_root = this->storeRootDirPath();
    Cert::Store::LocatorSPtr locator_sptr = std::make_shared<Cert::Store::Locator>(store_root);
    Cert::AuthoritySPtr cert_auth = Cert::Authority::load(locator_sptr->ca_dir_path);
    std::string pem =  buildCertificateExample2(*cert_auth);
    CHECK(pem.size() > 0);
    X509* cert = Cert::x509::Cert_FromPEMString(pem);
    std::string moz_only = this->mozRootCertificateBundleFilePath().string();
    CHECK( ! Cert::x509::Cert_Verify(cert, moz_only)); // VERIFY IS EXPECTED TO FAIL mozilla cert bundle does not contain the local CA
    std::string moz_with_ca = this->mozCombinedRootCertificateBundleFilePath().string();
    CHECK( Cert::x509::Cert_Verify(cert, moz_with_ca)); // VERIFY IS EXPECTED TO SUCCEED this version doesa have the local CA
    X509_free(cert);
}

/// checks that the mitm certificate has the host name
/// as the CN of the subject name
/// and a DNS: name in the subjest alt names
bool mitmWorked(X509* original_cert_X509, std::string host, Cert::Identity id)
{
    Cert::Certificate org_cert(original_cert_X509);

    auto orig_spec = Cert_GetSubjectNameAsSpec(original_cert_X509);
    auto orig_cn = (*orig_spec.find(NameNid_commonName)).second;
    
    auto new_spec = Cert_GetSubjectNameAsSpec(id.getX509());
    auto new_cn = (*new_spec.find(NameNid_commonName)).second;

    /// if the host the common name ? - possibly not
    bool b1 = (new_cn == host);

    boost::optional<std::string> orig_san = Cert_GetSubjectAlternativeNamesAsString(original_cert_X509);
    std::string orig_san2 = org_cert.getSubjectAlternativeNamesAsString();
    boost::optional<std::string> new_san = Cert_GetSubjectAlternativeNamesAsString(id.getX509());
    std::string orig_san_string {(orig_san) ? orig_san.get(): "NOVALUE"};
    std::string orig_san2_string {orig_san2};
    std::string new_san_string  {(new_san) ? new_san.get(): "NOVALUE"};

    bool b2;
    b2 = (new_san_string.find(host) != std::string::npos);
    return b1 && b2;
    if (orig_san && new_san) {
        /// both have a value
        b2 = (orig_san.get() == new_san.get()); 
    } else if ((!orig_san)&&(!new_san)) {
        // both dont have a value
        b2 = true;
    } else {
        b2 = false;
    }
    bool b3 = new_san_string.find(host);
    return (b1||b3)&&b2;
}

TEST_CASE_METHOD(TestFixtureNew, "buildMitm")
{
    this->loadExisting();
    path store_root = this->storeRootDirPath();
    Cert::Store::LocatorSPtr locator_sptr = std::make_shared<Cert::Store::Locator>(store_root);
    Cert::AuthoritySPtr cert_auth = Cert::Authority::load(locator_sptr->ca_dir_path);
    std::string host = this->hostForForgeTest();
    std::string cert_file_name = this->realCertFilePathForHost(host).string();
    if( ! Cert::Helpers::fs::is_regular_file (cert_file_name) ) {
        std::cout << "Host real certfile does not exist " << cert_file_name << std::endl;
        assert(false);
    }
    X509* original_cert_X509 = Cert::x509::Cert_ReadFromFile(cert_file_name);

        // call the genuine forger function
    Cert::Certificate org_cert(original_cert_X509);
    Cert::Builder builder(*cert_auth);
    Cert::Identity id = builder.buildMitmIdentity(host, org_cert);

    bool b0 = mitmWorked(original_cert_X509, host, id);
    CHECK(b0);
    std::string pem = Cert::x509::Cert_PEMString(id.getX509());
    CHECK(pem.size() > 0);

}
TEST_CASE_METHOD(TestFixtureNew, "buildMitm - geeksforgeeks.org")
{
    this->loadExisting();
    path store_root = this->storeRootDirPath();
    Cert::Store::LocatorSPtr locator_sptr = std::make_shared<Cert::Store::Locator>(store_root);
    Cert::AuthoritySPtr cert_auth = Cert::Authority::load(locator_sptr->ca_dir_path);
    std::string host = this->hostForGeekTest();
    std::string cert_file_name = this->realCertFilePathForHost(host).string();
    if( ! Cert::Helpers::fs::is_regular_file (cert_file_name) ) {
        std::cout << "Host real certfile does not exist " << cert_file_name << std::endl;
        assert(false);
    }
    X509* original_cert_X509 = Cert::x509::Cert_ReadFromFile(cert_file_name);
        // call the genuine forger function
    Cert::Certificate cert(original_cert_X509);
    Cert::Builder builder(*cert_auth);
    Cert::Identity id = builder.buildMitmIdentity(host, cert);
    bool b0 = mitmWorked(original_cert_X509, host, id);
    CHECK(b0);
    std::string pem = Cert::x509::Cert_PEMString(id.getX509());
    CHECK(pem.size() > 0);
}
TEST_CASE_METHOD(TestFixtureNew, "buildMitm - www.geeksforgeeks.org")
{
    this->loadExisting();
    path store_root = this->storeRootDirPath();
    Cert::Store::LocatorSPtr locator_sptr = std::make_shared<Cert::Store::Locator>(store_root);
    Cert::AuthoritySPtr cert_auth = Cert::Authority::load(locator_sptr->ca_dir_path);
    std::string host = this->hostForWWWGeekTest();
    std::string cert_file_name = this->realCertFilePathForHost(host).string();
    if( ! Cert::Helpers::fs::is_regular_file (cert_file_name) ) {
        std::cout << "Host real certfile does not exist " << cert_file_name << std::endl;
        assert(false);
    }
    X509* original_cert_X509 = Cert::x509::Cert_ReadFromFile(cert_file_name);
        // call the genuine forger function
    Cert::Certificate cert(original_cert_X509);
    Cert::Builder builder(*cert_auth);
    Cert::Identity id = builder.buildMitmIdentity(host, cert);
    bool b0 = mitmWorked(original_cert_X509, host, id);
    CHECK(b0);
    std::string pem = Cert::x509::Cert_PEMString(id.getX509());
    CHECK(pem.size() > 0);
}

