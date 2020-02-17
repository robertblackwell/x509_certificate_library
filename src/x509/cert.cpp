#include "x509.hpp"
#include "x509_cert_impl.hpp"
#include "cert_authority.hpp"

#pragma mark - Cert::x509::Cert read/write
//http://fm4dd.com/openssl/certverify.htm

using namespace Cert;

/**
* \todo create a Certificate object to manage the life time of X509*
*
* \todo a new set of functions for CertChains particularly read/writeing of them
*
* \todo review x509 *.cpp files and test_init to ensure there are no memory leaks
*
* \todo find out how to use valgrind and apply it to this project
*/
/**
 * Read a certificate from a file which is in PEM format
 * @param std::string fileName from which to read the pem string
 * @return X509* caller is responsible for deallocating wioth X509_free
 */
X509* Cert::x509::Cert_ReadFromFile(std::string fileName)
{
    X509* cert = X509_new();
    X509* cert_result;
    char* fn = (char*)fileName.c_str();
    FILE* fp;
    
    if (!(fp = fopen (fn, "r")))
        X509_TRIGGER_ERROR ("Error reading CA certificate file");
    if (!(cert_result = PEM_read_X509 (fp, &cert, NULL, NULL)))
        X509_TRIGGER_ERROR ("Error reading CA certificate in file");
    assert(cert == cert_result);
    fclose (fp);
    return cert;
}

X509* Cert::x509::Cert_FromPEMString(std::string pem)
{
    X509 *cert = NULL;
    BIO *cbio;
    const char *cert_buffer = pem.c_str();

    cbio = BIO_new_mem_buf((void*)cert_buffer, -1);
    cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
    return cert;
}

void
Cert::x509::Cert_WriteToFilePEM(X509* cert, std::string fileName)
{
    FILE* fp;
    char* fn = (char*) fileName.c_str();
    if (!(fp = fopen (fn, "w")))
        X509_TRIGGER_ERROR ("Error writing to certificate file");
    if (PEM_write_X509 (fp, cert) != 1)
        X509_TRIGGER_ERROR ("Error while writing certificate");
    fclose (fp);
}

void
Cert::x509::Cert_WriteToFile(X509* cert, std::string fileName)
{
    FILE* fp;
    char* fn = (char*) fileName.c_str();
    if (!(fp = fopen (fn, "w")))
        X509_TRIGGER_ERROR ("Error writing to certificate file");
    if (PEM_write_X509 (fp, cert) != 1)
        X509_TRIGGER_ERROR ("Error while writing certificate");
    fclose (fp);
}

#pragma mark - certificate verify functions
/**
* Verify a certificate against an existing X509_STORE* object
*/
bool
Cert::x509::Cert_Verify(X509* cert, X509_STORE* store)
{
    X509_STORE_CTX* vrfy_ctx = X509_STORE_CTX_new();
    assert(vrfy_ctx != NULL);
    X509_STORE_CTX_init(vrfy_ctx, store, cert, NULL);
    auto ret = X509_verify_cert(vrfy_ctx);
    #if 0
    std::cout << "Verification return code: " << ret << std::endl;
    std::string msg{X509_verify_cert_error_string(vrfy_ctx->error)};
    if(ret == 0 || ret == 1)
        std::cout << "Verification result text: " <<  X509_verify_cert_error_string(vrfy_ctx->error) << std::endl;
    
    /// note - if this fails read the details at http://fm4dd.com/openssl/certverify.htm
    #endif
    if(ret == 0) {
    #if 0
        /*  get the offending certificate causing the failure */
        error_cert  = X509_STORE_CTX_get_current_cert(vrfy_ctx);
        certsubject = X509_NAME_new();
        certsubject = X509_get_subject_name(error_cert);
        BIO_printf(outbio, "Verification failed cert:\n");
        X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
        BIO_printf(outbio, "\n");
    #endif
    }

    return (ret == 1);

}
/**
* Verify a certificate against an existing certificate bundle file
*/
bool
Cert::x509::Cert_Verify(X509* cert, std::string cert_bundle_path)
{
    X509_STORE* store = X509_STORE_new();
    assert( store != NULL);
    const char* ca_bundlestr = cert_bundle_path.c_str();
    auto ret1 = X509_STORE_load_locations(store, ca_bundlestr, NULL);
    assert( ret1 == 1);
    return Cert_Verify(cert, store);
}
/**
* Verify a certificate against the provide CertificateAuthority
*/
bool
Cert::x509::Cert_Verify(X509* cert, ::Cert::Authority& certAuth)
{
    std::string ca_cert_path = certAuth.getCaCertPath();
    bool res = Cert_Verify(cert, ca_cert_path);
    return res;
}

#pragma mark - subject_name getters and setters

Cert::x509::NameSpecification
Cert::x509::Cert_GetSubjectNameAsSpec(X509* cert)
{
    return Cert::x509::Name_getSpec(Cert::x509::Cert_GetSubjectName(cert));
}
void Cert::x509::Cert_SetSubjectName(X509* cert, Cert::x509::NameSpecification spec)
{
    Cert::x509::Cert_SetSubjectName(cert, Cert::x509::Name_fromSpec(spec));
}

std::string Cert::x509::Cert_GetSubjectNameAsOneLine(X509* cert)
{
    auto sn = Cert::x509::Cert_GetSubjectName(cert);
    std::string sn1l = Cert::x509::Name_AsOneLine(sn);
    return sn1l;
}
std::string Cert::x509::Cert_GetSubjectNameAsMultiLine(X509* cert)
{
    auto sn = Cert::x509::Cert_GetSubjectName(cert);
    std::string snml = Cert::x509::Name_AsMultiLine(sn);
    return snml;
}
#pragma mark - issuer_name getters and setters

Cert::x509::NameSpecification
Cert::x509::Cert_GetIssuerNameAsSpec(X509* cert)
{
    return Cert::x509::Name_getSpec(Cert::x509::Cert_GetIssuerName(cert));
}

void Cert::x509::Cert_SetIssuerName(X509* cert, Cert::x509::NameSpecification spec)
{
    Cert::x509::Cert_SetIssuerName(cert, Cert::x509::Name_fromSpec(spec));
}
std::string Cert::x509::Cert_GetIssuerNameAsOneLine(X509* cert)
{
    auto sn = Cert::x509::Cert_GetIssuerName(cert);
    std::string sn1l = Cert::x509::Name_AsOneLine(sn);
    return sn1l;
}
std::string Cert::x509::Cert_GetIssuerNameAsMultiLine(X509* cert)
{
    auto sn = Cert::x509::Cert_GetIssuerName(cert);
    std::string snml = Cert::x509::Name_AsMultiLine(sn);
    return snml;
}

#pragma mark - version number getters and setters

long
Cert::x509::Cert_GetVersion(X509* cert)
{
    long ret = X509_get_version(cert);
    return ret;
}

void
Cert::x509::Cert_SetVersion(X509* cert, long version)
{
    if (X509_set_version (cert, version) != 1)
        X509_TRIGGER_ERROR ("Error settin certificate version");
}

#pragma mark - serial number getters and setters

void
Cert::x509::Cert_SetSerialNumber(X509* cert, long serial)
{
    ASN1_INTEGER_set (X509_get_serialNumber (cert), serial);
}

#pragma mark - certificate private key getters and setters

EVP_PKEY*
Cert::x509::Cert_GetPublicKey(X509* cert)
{
    EVP_PKEY* key;
    key = X509_get_pubkey(cert);
    if (! key) {
        X509_TRIGGER_ERROR("failed getting public key from certificate");
    }
    return key;
}

void
Cert::x509::Cert_SetPublicKey(X509* cert, EVP_PKEY* pubkey)
{
    /* set public key in the certificate */
    if (X509_set_pubkey (cert, pubkey) != 1)
        X509_TRIGGER_ERROR ("Error setting public key of the certificate");
}

#pragma mark - not_before and not_after getters and setters

void
Cert::x509::Cert_SetNotBefore(X509* cert, int secs)
{
    /* set duration for the certificate */
    if (!(X509_gmtime_adj (X509_get_notBefore(cert), secs)))
        X509_TRIGGER_ERROR ("Error setting beginning time of the certificate");
}

void
Cert::x509::Cert_SetNotAfter(X509* cert, int secs)
{
    if (!(X509_gmtime_adj (X509_get_notAfter(cert), secs)))
        X509_TRIGGER_ERROR ("Error setting ending time of the certificate");
}
#pragma mark - extension functions

std::string
Cert::x509::Cert_GetSubjectAlternativeNamesAsString(X509* cert)
{
    auto subj_altname_ext = Cert::x509::Cert_GetSubjectAltName(cert);
    std::string subject_alt_names_string = Cert::x509::Extension_ValueAsString(subj_altname_ext);
    return subject_alt_names_string;
}

Cert::x509::AlternativeDNSNameSet Cert::x509::Cert_GetSubjectAlternativeDNSNames(X509* cert)
{
    Cert::x509::AlternativeDNSNameSet ret;
    STACK_OF(GENERAL_NAME) *altnames;
    altnames = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if(!altnames)
        return ret;
    int numalts;
    int i;

    /* get amount of alternatives, RFC2459 claims there MUST be at least
       one, but we don't depend on it... */
    numalts = sk_GENERAL_NAME_num(altnames);

    /* loop through all alternatives while none has matched */
    for (i=0; (i<numalts); i++)
    {
        /* get a handle to alternative name number i */
    
        const GENERAL_NAME *check = sk_GENERAL_NAME_value(altnames, i);
        /* get data and length */
        if(check->type == GEN_DNS) {
            const char *altptr = (char *)ASN1_STRING_get0_data(check->d.ia5);
            
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Wunused-variable"
            size_t altlen = (size_t) ASN1_STRING_length(check->d.ia5);
            #pragma clang diagnostic pop
            
            std::string s(altptr);
            ret.insert(s);
//            ret[s] = s;
        }
//        _subjectAltnames.insert(s);
//        if (debug_trace) std::cout << s << std::endl;
    }
    GENERAL_NAMES_free(altnames);
    return ret;
}


void Cert::x509::Cert_AddExtensionsFromSpecs(X509* ca_cert, X509* cert, Cert::x509::ExtSpecifications extra_extensions)
{
    for(auto const& ext_spec : extra_extensions) {
        X509_EXTENSION* xt = Cert::x509::Extension_create(ca_cert, cert, ext_spec.first, ext_spec.second);
        Cert::x509::Cert_AddExtension(cert, xt);
    }
}

Cert::x509::ExtDescriptions Cert::x509::Cert_extensionsAsDescription(X509* cert)
{
    return Cert::x509::ExtensionStack_asDescriptions(Cert::x509::Cert_GetExtensions(cert));
}

#pragma mark output functions

std::string Cert::x509::Cert_PEMString(X509* cert)
{
    BIO* out_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(out_bio, cert);
    
    std::string s = BIO_to_string(out_bio);
    BIO_free(out_bio);
    return s;
    #if 0
    BUF_MEM* bmp;
    BIO_get_mem_ptr(out_bio, &bmp);

    char* pem = (char *) malloc(bmp->length + 1);
    if (NULL == pem) {
        BIO_free(out_bio);
        return NULL;
    }
    memset(pem, 0, bmp->length + 1);
    BIO_read(out_bio, pem, (int)bmp->length);
    BIO_free(out_bio);
    std::string ret(pem);
    free(pem);
    return ret;
    #endif
}

void Cert::x509::Cert_Print(X509* cert, BIO* out_bio)
{
    X509_print(out_bio, cert);
}

std::string Cert::x509::Cert_PrintToString(X509* cert)
{
    BIO* out_bio = BIO_new(BIO_s_mem());
    X509_print(out_bio, cert);
    std::string s = BIO_to_string(out_bio);
    BIO_free(out_bio);
    return s;

}
void Cert::x509::Cert_Print(X509* cert)
{
    BIO* out_bio  = BIO_new_fp(stdout, BIO_NOCLOSE);
    X509_print(out_bio, cert);
    BIO_free(out_bio);
}
//http://fm4dd.com/openssl/certverify.htm
/** @} */
