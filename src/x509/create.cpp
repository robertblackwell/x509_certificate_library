#include "x509.hpp"
#include "x509_cert_impl.hpp"
#include "x509_create.hpp"

#pragma mark - certificate builder function

using namespace Cert;
using namespace x509;

namespace Cert {
namespace x509 {

/**
 * Creates a new certificate. Note A new key pair must be created for the subject_name before this function
 * can be called; thats in addition to having a CA and all the other data in the call signatures.
 * 
*/
X509* create(
                     X509*                      ca_cert,
                     EVP_PKEY*                  ca_private_key,
                     Cert::x509::SerialNumber      serial,
                     Cert::x509::Version           version,
                     EVP_PKEY*                  new_pkey_pair,
                     Cert::x509::TimeOffset        not_before_offset,
                     Cert::x509::TimeOffset        not_after_offset,
                     Cert::x509::NameSpecification subject_name_spec,
                     std::string                subject_alt_name_string,
                     Cert::x509::ExtSpecifications extra_extensions
                     )
{
    //    EVP_PKEY* new_pkey_pair = x509Rsa_Generate();
    
    EVP_PKEY *pubkey = new_pkey_pair;
    const EVP_MD *digest;
    X509 *cert;
    X509_NAME *subject_name = Cert::x509::Name_fromSpec(subject_name_spec);
    std::string subject_name_string = Cert::x509::Name_AsOneLine(subject_name);
    X509_EXTENSION* issuerAltName = Cert::x509::Cert_GetSubjectAltName(ca_cert);
    if (issuerAltName != nullptr) {
        std::string issuer_alt_names_string = Cert::x509::Extension_ValueAsString(issuerAltName);
        extra_extensions[Cert::x509::ExtNid_issuerAlternativeName] = issuer_alt_names_string;
    }
    if (!(cert = X509_new ()))
        X509_TRIGGER_ERROR ("Error creating X509 object");
    
    Cert::x509::Cert_SetSubjectName(cert, subject_name);
    Cert::x509::Cert_SetIssuerName(cert, Cert::x509::Cert_GetSubjectName(ca_cert));
    Cert::x509::Cert_SetVersion(cert, (long)version);
    Cert::x509::Cert_SetSerialNumber(cert, serial);
    Cert::x509::Cert_SetPublicKey(cert, pubkey);
    Cert::x509::Cert_SetNotBefore(cert, not_before_offset);// minus 1 year
    Cert::x509::Cert_SetNotAfter(cert, not_after_offset); // plus 5 years
    
    extra_extensions[Cert::x509::ExtNid_subjectAlternativeName] = subject_alt_name_string;
    
    for(auto const& ext_spec : extra_extensions) {
        X509_EXTENSION* xt = Cert::x509::Extension_create(ca_cert, cert, ext_spec.first, ext_spec.second);
        Cert::x509::Cert_AddExtension(cert, xt);
    }
    /*
     ** select the digest to use for signing. Since we only use RSA keys
     ** and we want to ALWAYS use sha256 - there is no decision
     */
    if (EVP_PKEY_base_id(ca_private_key) == EVP_PKEY_RSA) {
        digest = EVP_sha1();
    } else {
        X509_TRIGGER_ERROR ("Error  CA private key is NOT RSA");
    }
    /*
     ** The big moment sign the cert
     ** sign the certificate with the CA private key
     */
    if (!(X509_sign(cert, ca_private_key, digest)))
        X509_TRIGGER_ERROR ("Error signing certificate");
    
    return cert;
}
} // namespace x509
} // namespace Cert

