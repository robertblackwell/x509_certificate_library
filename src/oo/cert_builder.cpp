//
//  x509_builder.cpp
//  x509
//
//  Created by ROBERT BLACKWELL on 11/15/17.
//  Copyright © 2017 ROBERT BLACKWELL. All rights reserved.
//

#include <cert/x509.hpp>
#include <cert/x509_cert_impl.hpp>
#include <cert/cert_builder.hpp>
#include <cert/cert_certificate.hpp>
#include <cert/cert_authority.hpp>

#pragma mark - certificate builder function

using namespace Cert;

Builder::Builder(Cert::Authority& cert_auth): m_cert_auth(cert_auth), m_cache(std::map<std::string, MitmResult>()){}
Builder::~Builder()
{

}
//using namespace Cert::Builder;
#if 1
Cert::Certificate Builder::build(
                     Cert::x509::SerialNumber       serial,
                     Cert::x509::Version            version,
                     EVP_PKEY*                      new_pkey_pair,
                     Cert::x509::TimeOffset         not_before_offset,
                     Cert::x509::TimeOffset         not_after_offset,
                     Cert::x509::NameSpecification  subject_name_spec,
                     std::string                    subject_alt_name_string,
                     Cert::x509::ExtSpecifications  extra_extensions
                     )
{
    //    EVP_PKEY* new_pkey_pair = x509Rsa_Generate();
    
    EVP_PKEY *pubkey = new_pkey_pair;
    const EVP_MD *digest;
    X509 *x509_cert;
    auto ca_cert = m_cert_auth.getCACert();
    auto ca_private_key = m_cert_auth.getCAPKey();
    X509_NAME *subject_name = Cert::x509::Name_fromSpec(subject_name_spec);
    std::string subject_name_string = Cert::x509::Name_AsOneLine(subject_name);
    X509_EXTENSION* issuerAltName = Cert::x509::Cert_GetSubjectAltName(ca_cert);
    if (issuerAltName != nullptr) {
        std::string issuer_alt_names_string = Cert::x509::Extension_ValueAsString(issuerAltName);
        extra_extensions[Cert::x509::ExtNid_issuerAlternativeName] = issuer_alt_names_string;
    }
    if (!(x509_cert = X509_new ()))
        X509_TRIGGER_ERROR ("Error creating X509 object");
    
    Cert::x509::Cert_SetSubjectName(x509_cert, subject_name);
    Cert::x509::Cert_SetIssuerName(x509_cert, Cert::x509::Cert_GetSubjectName(ca_cert));
    Cert::x509::Cert_SetVersion(x509_cert, (long)version);
    Cert::x509::Cert_SetSerialNumber(x509_cert, serial);
    Cert::x509::Cert_SetPublicKey(x509_cert, pubkey);
    Cert::x509::Cert_SetNotBefore(x509_cert, not_before_offset);// minus 1 year
    Cert::x509::Cert_SetNotAfter(x509_cert, not_after_offset); // plus 5 years
    
    extra_extensions[Cert::x509::ExtNid_subjectAlternativeName] = subject_alt_name_string;
    
    for(auto const& ext_spec : extra_extensions) {
        X509_EXTENSION* xt = Cert::x509::Extension_create(ca_cert, x509_cert, ext_spec.first, ext_spec.second);
        Cert::x509::Cert_AddExtension(x509_cert, xt);
    }
    /*
     ** select the digest to use for signing. Sicne we only use RSA keys
     ** and we want to ALWAYS use sha256 - there is no decision
     */
//    if (EVP_PKEY_type(ca_private_key->type) == EVP_PKEY_RSA)
    if (EVP_PKEY_base_id(ca_private_key) == EVP_PKEY_RSA)
        digest = EVP_sha1();
    else
        X509_TRIGGER_ERROR ("Error  CA private key is NOT RSA");
    /*
     ** The big moment sign the cert
     ** sign the certificate with the CA private key
     */
    if (!(X509_sign(x509_cert, ca_private_key, digest)))
        X509_TRIGGER_ERROR ("Error signing certificate");
    
    Cert::Certificate cert(x509_cert);
    X509_free(x509_cert);
    return cert;
}
#endif
/**
* Create a new certificate and private key based on an original certificate and
* signed by the Builder instance's Certificate Authority
*
* @param original_cert X509*            - the original certificate to be forged or impersonated
* @param certAuth CertificateAuthority  - the certificate authority to sign the new certificate
*
* @return x4zero9::Identity
*/
Identity Builder::buildMitmIdentity(Cert::Certificate& original_cert)
{
    //Cert::x509::Cert_Print(original_cert);
    X509* x509_original_cert = original_cert.native();
    x509::NameSpecification  subject_name_spec = original_cert.getSubjectNameAsSpec();//  Cert::x509::Cert_GetSubjectNameAsSpec(x509_cert);
    /*
    * specify the extensions to add
    */
    x509::ExtSpecifications extension_specifications = {
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
    
    auto sss = original_cert.getSubjectAlternativeNamesAsString();

    auto subj_altname_ext = Cert::x509::Cert_GetSubjectAltName(x509_original_cert);
    std::string subject_alt_names_string = Cert::x509::Extension_ValueAsString(subj_altname_ext);

    auto san = Cert::x509::Cert_GetSubjectAlternativeDNSNames(x509_original_cert);
    auto ssan = Cert::x509::Cert_extensionsAsDescription(x509_original_cert);

    EVP_PKEY* new_pkey_pair = Cert::x509::Rsa_Generate();
    assert(sss == subject_alt_names_string);
    X509* x509_new_cert = ::Cert::x509::create(
            m_cert_auth.getCACert(),
            m_cert_auth.getCAPKey(),
            m_cert_auth.getNextSerialNumber(),
            2L,
            new_pkey_pair,
            -(60*60*24*365), //not before one year before now
            (60*60*24*365*10), // not after 10 years from now
            subject_name_spec,
            subject_alt_names_string,
            extension_specifications
    );
    auto vres = x509::Cert_Verify(x509_new_cert, m_cert_auth);
    assert(vres);

    Identity identity(x509_new_cert, new_pkey_pair);
    X509_free(x509_new_cert);
    EVP_PKEY_free(new_pkey_pair);
    return identity;
}
