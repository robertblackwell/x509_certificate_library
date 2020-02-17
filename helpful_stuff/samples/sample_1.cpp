
#include <iostream>
#include <map>
#include "cert/x509.hpp"
#include "test_helpers.hpp"

void buildCertificateExample()
{
    TestHelper helper;
    auto ca_private_directory = helper.caPrivateDirPath();
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

    Cert::x509::CertificateAuthority certAuth(ca_private_directory);
    X509* cert = Cert::x509::create(
            certAuth.getCACert(),
            certAuth.getCAPKey(),
            certAuth.getNextSerialNumber(),
            2L,
            new_pkey,
            -(60*60*24*365), //not before one year before now
            (60*60*24*365*10), // not after 10 years from now
            subject_name_spec,
            subject_alt_names,
            extension_specifications
    );

    BIO* out_bio;
    out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    Cert::x509::Cert_Print(cert, out_bio);
    std::string ss = Cert::x509::Cert_PEMString(cert);
    X509_free(cert);
    EVP_PKEY_free(new_pkey);
    BIO_free(out_bio);

}

int main(int argc, const char * argv[]) {
    OpenSSL_add_all_algorithms ();
    ERR_load_crypto_strings ();
    ERR_load_BIO_strings();
    ERR_load_ERR_strings();

    buildCertificateExample();
    return 0;
}
