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
    boost::optional<X509_EXTENSION*> issuerAltName = Cert::x509::Cert_GetSubjectAltName(ca_cert);
    if (issuerAltName) {
        std::string issuer_alt_names_string = Cert::x509::Extension_ValueAsString(issuerAltName.get());
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
    
    ///
    /// what happens if subject_alt_name_string is empty
    ///
    if(subject_alt_name_string != "") {
        extra_extensions[Cert::x509::ExtNid_subjectAlternativeName] = subject_alt_name_string;
    }
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
bool paranoidTest(X509* original_cert_X509, std::string host, Cert::Identity id)
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
/**
* Create a new certificate and private key based on an original certificate and
* signed by the Builder instance's Certificate Authority
*
* @param required_common_name           - a name the must be in the subkect or subkect alt field
*                                        in a live system the host name of the request
* @param original_cert X509*            - the original certificate to be forged or impersonated
* 
* @return x4zero9::Identity
*/
Identity Builder::buildMitmIdentity(
    std::string required_common_name,
    Cert::Certificate& original_cert
)
{
    //Cert::x509::Cert_Print(original_cert);
    X509* x509_original_cert = original_cert.native();
    x509::NameSpecification  subject_name_spec = original_cert.getSubjectNameAsSpec();//  Cert::x509::Cert_GetSubjectNameAsSpec(x509_cert);

    ///
    /// here must test to see if common name is equal to the required_common_name
    ///
    std::string cn;
    auto cn_itr = subject_name_spec.find(NameNid_commonName);
    if (cn_itr != subject_name_spec.end()) {
        cn = (*cn_itr).second;
        /// LOG an error
    }
    if (cn != required_common_name) {
        /// log a warning
    }
    subject_name_spec[NameNid_commonName] = required_common_name;
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
    // std::string subject_alt_names= "DNS:alternate_one.com,DNS:alternatie_two.com";
    
    auto sss = original_cert.getSubjectAlternativeNamesAsString();
    std::string subject_alt_names_string = "";
    auto yy = Cert::x509::Cert_altNames(x509_original_cert);
    std::vector<std::string> yy2;
    if (yy) {
        yy2 = yy.get();
    }
    #if 0
    boost::optional<X509_EXTENSION*>  subj_altname_ext = Cert::x509::Cert_GetSubjectAltName(x509_original_cert);

    if (subj_altname_ext) {
        subject_alt_names_string = "";
    } else {
        subject_alt_names_string = Cert::x509::Extension_ValueAsString(subj_altname_ext.get());
    }
    #else
    subject_alt_names_string = sss;
    #endif
    /// force the required common name into the DNS names
    subject_alt_names_string = "DNS:"+required_common_name+","+subject_alt_names_string;

    sss =  "DNS:"+required_common_name+","+sss;
    auto san = Cert::x509::Cert_GetSubjectAlternativeDNSNames(x509_original_cert);
    auto ssan = Cert::x509::Cert_extensionsAsDescription(x509_original_cert);

    EVP_PKEY* new_pkey_pair = Cert::x509::Rsa_Generate();
    if (sss != subject_alt_names_string) {
        // std::cout << std::endl << std::endl 
        // << "WARNING: buildMitmIdentity subject alt names disagree: " << sss << " != "<< subject_alt_names_string<< std::endl;
        subject_alt_names_string = sss;
    }
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
    ///
    /// patanoid test - better to fail here than somewhere in the guts of an app using this stuff
    ///
    Identity identity(x509_new_cert, new_pkey_pair);
    #ifdef APPLY_PARANOID_TEST
    if (! paranoidTest(x509_original_cert, required_common_name, identity)) {
        THROW("paranoid test failed in buildMitmIdentity for host " + required_common_name);
    }
    #endif
    X509_free(x509_new_cert);
    EVP_PKEY_free(new_pkey_pair);
    return identity;
}
