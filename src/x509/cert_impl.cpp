#include <cert/x509.hpp>
#include <cert/x509_cert_impl.hpp>

#pragma mark - subject_name getters and setters

X509_NAME*
Cert::x509::Cert_GetSubjectName(X509* cert)
{
    X509_NAME *name;
    if (!(name = X509_get_subject_name (cert)))
        X509_TRIGGER_ERROR ("Error getting subject name from certificate");
    return name;
}

void
Cert::x509::Cert_SetSubjectName(X509* cert, X509_NAME* name)
{
    if (X509_set_subject_name (cert, name) != 1)
        X509_TRIGGER_ERROR ("Error setting subject name of certificate");
}

#pragma mark - issuer_name getters and setters

X509_NAME*
Cert::x509::Cert_GetIssuerName(X509* cert)
{
    X509_NAME* name = X509_get_issuer_name(cert);
    if (! name )
        X509_TRIGGER_ERROR ("Error getting issuer name of certificate");
    return name;
}
void
Cert::x509::Cert_SetIssuerName(X509* cert, X509_NAME* name)
{
    if (X509_set_issuer_name (cert, name) != 1)
        X509_TRIGGER_ERROR ("Error setting issuer name of certificate");
}

#pragma mark - serial number getters and setters


ASN1_INTEGER*
Cert::x509::Cert_GetSerialNumber(X509* cert)
{
    ASN1_INTEGER* n = X509_get_serialNumber(cert);
    if(! n) {
        X509_TRIGGER_ERROR("failed getting serial number from certificate");
    }
    return n;
}


#pragma mark - not_before and not_after getters and setters

ASN1_TIME*
Cert::x509::Cert_GetNotBefore(X509* cert)
{
    ASN1_TIME* t = X509_get_notBefore(cert);
    if (t == nullptr) {
        X509_TRIGGER_ERROR("could not get not before");
    }
    return t;
}
void
Cert::x509::Cert_SetNotBefore(X509* cert, ASN1_TIME* tm_src)
{
    ASN1_TIME* tm_dest = Cert::x509::Cert_GetNotBefore(cert);
    //    ASN1_TIME_print(out, nb2); BIO_printf(out, "\n");
    
    auto st = ASN1_STRING_copy((ASN1_STRING*)tm_dest, (ASN1_STRING*)tm_src);
    if ( ! st ) {
        X509_TRIGGER_ERROR("Cert::x509::Cert_SetNotBefore copy of tm_src failed");
    }
}

ASN1_TIME*
Cert::x509::Cert_GetNotAfter(X509* cert)
{
    ASN1_TIME* t = X509_get_notAfter(cert);
    if (t == nullptr) {
        X509_TRIGGER_ERROR("could not get not after");
    }
    return t;
}
void
Cert::x509::Cert_SetNotAfter(X509* cert, ASN1_TIME* tm_src)
{
    ASN1_TIME* tm_dest = Cert::x509::Cert_GetNotAfter(cert);
    //    ASN1_TIME_print(out, nb2); BIO_printf(out, "\n");
    
    auto st = ASN1_STRING_copy((ASN1_STRING*)tm_dest, (ASN1_STRING*)tm_src);
    if ( ! st ) {
        X509_TRIGGER_ERROR("Cert::x509::Cert_SetNotBefore copy of tm_src failed");
    }
}
#pragma mark - extension functions

STACK_OF(X509_EXTENSION)*
Cert::x509::Cert_GetExtensions(X509* cert)
{
//    auto x = cert->cert_info->extensions;
    // remove the const
    STACK_OF(X509_EXTENSION)* x = (STACK_OF(X509_EXTENSION)*) X509_get0_extensions(cert);
//    assert(false);
    return x;
}
X509_EXTENSION*
Cert::x509::Cert_GetSubjectAltName(X509* cert)
{
    //return NULL;
    X509_EXTENSION *subjAltName;
    STACK_OF (X509_EXTENSION) * req_exts;
    int subjAltName_pos;
    if (!(req_exts = Cert::x509::Cert_GetExtensions (cert)))
        X509_TRIGGER_ERROR ("Error getting the request's extensions");
    subjAltName_pos = X509v3_get_ext_by_NID (req_exts,
                                             OBJ_sn2nid ("subjectAltName"), -1);
    subjAltName = X509v3_get_ext (req_exts, subjAltName_pos);
    return subjAltName;
}

void
Cert::x509::Cert_AddExtension(X509* cert, X509_EXTENSION* ext)
{
    /* add the subjectAltName in the request to the cert */
    if (!X509_add_ext (cert, ext, -1))
        X509_TRIGGER_ERROR ("Error adding subjectAltName to certificate");
}

#if 0
void
Cert::x509::Cert_Add_ExtensionsFromStack(X509* CAcert, X509* cert, STACK_OF(X509_EXTENSION)* stack)
{
    int nbr = sk_X509_EXTENSION_num(stack);
    for(int i = 0; i < nbr; i++) {
        auto ext = sk_X509_EXTENSION_value(stack, i);
        auto ext_dup = X509_EXTENSION_dup(ext);
        if (!X509_add_ext (cert, ext_dup, -1))
        {
            X509_TRIGGER_ERROR ("Error adding X509 extension to certificate");
        }
        X509_EXTENSION_free (ext_dup);
    }
}

void Cert::x509::Cert_SetExtensions(X509* cert, STACK_OF(X509_EXTENSION)* exts)
{
    auto tmp = cert->cert_info->extensions;
    STACK_OF(X509_EXTENSION)* ext_new = sk_X509_EXTENSION_dup(exts);
    cert->cert_info->extensions = ext_new;
    sk_X509_EXTENSION_free(tmp);
}
#endif
/**
* @}
*/
