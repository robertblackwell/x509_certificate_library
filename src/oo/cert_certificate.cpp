#include <cert/x509.hpp>
#include <cert/x509_cert_impl.hpp>
#include <cert/cert.hpp>


Cert::Certificate::Certificate(boost::filesystem::path pem_file)
{
    X509* x = Cert_ReadFromFile(pem_file.native());
    m_x509 = x;
    X509_up_ref(m_x509);
    X509_free(x);
}
Cert::Certificate::Certificate(std::string pem_string)
{
    X509* x = Cert_FromPEMString(pem_string);
    m_x509 = x;
    X509_up_ref(m_x509);
    X509_free(x);
}
Cert::Certificate::Certificate(X509* x509_cert)
{
    m_x509 = x509_cert;
    X509_up_ref(m_x509);
}

Cert::Certificate::~Certificate()
{
    if (m_x509 != nullptr) {
        X509_free(m_x509);
    }
}

X509* 
Cert::Certificate::native()
{
    return m_x509;
}

void 
Cert::Certificate::writeToFile(boost::filesystem::path  filePath)
{
    X509* x = native();
    Cert_WriteToFile(x, filePath.native());
}
#pragma mark - certificate subject_name getters/setters

::Cert::x509::NameSpecification 
Cert::Certificate::getSubjectNameAsSpec()
{
    return Cert_GetIssuerNameAsSpec(native());
}

std::string 
Cert::Certificate::getSubjectNameAsOneLine()
{
    return Cert_GetSubjectNameAsOneLine(native());
}

std::string 
Cert::Certificate::getSubjectNameAsMultiLine()
{
    return Cert_GetSubjectNameAsMultiLine(native());
}

void 
Cert::Certificate::setSubjectName(::Cert::x509::NameSpecification subjectValues)
{
    Cert_SetSubjectName(native(), subjectValues);
}

#pragma mark - certificate issuer_name getters/setters

::Cert::x509::NameSpecification 
Cert::Certificate::getIssuerNameAsSpec()
{
    return Cert_GetIssuerNameAsSpec(native());
}

std::string 
Cert::Certificate::getIssuerNameAsOneLine()
{
    return Cert_GetIssuerNameAsOneLine(native());
}

std::string 
Cert::Certificate::Certificate::getIssuerNameAsMultiLine()
{
    return Cert_GetIssuerNameAsMultiLine(native());
}

void 
Cert::Certificate::setIssuerName(::Cert::x509::NameSpecification spec)
{
    Cert_SetIssuerName(native(), spec);
}

#pragma mark - certificate version getters/setters

::Cert::x509::Version 
Cert::Certificate::getVersion()
{
    return Cert_GetVersion(native());
}

void 
Cert::Certificate::setVersion(::Cert::x509::Version version)
{
    Cert_SetVersion(native(), version);
}

#pragma mark - certificate serial number getters/setters
std::string
Cert::Certificate::getSerialNumber()
{
    auto serial = Cert::x509::Cert_GetSerialNumber(native());
    std::string s1 = Cert::x509::Serial_AsString(serial);
    return s1;
}

void 
Cert::Certificate::setSerialNumber(::Cert::x509::SerialNumber serial)
{
    Cert_SetSerialNumber(native(), serial);
}

#pragma mark - certificate public key getters/setters

//EVP_PKEY*
Cert::EvpPKey
Cert::Certificate::getPublicKey()
{
    EVP_PKEY* k = Cert_GetPublicKey(native());
    EvpPKey kk(k);
    return kk;
}

void 
//Certificate::setPublicKey(EVP_PKEY* pubkey)
Cert::Certificate::setPublicKey(EvpPKey pubkey)
{
    Cert_SetPublicKey(native(), pubkey.native());
}

#pragma mark - certificate not before and not after getters/setters

void 
Cert::Certificate::setNotBefore(int offset_from_now_secs)
{
    Cert_SetNotBefore(native(), offset_from_now_secs);
}

void 
Cert::Certificate::setNotAfter(int offset_from_now_secs)
{
    Cert_SetNotAfter(native(), offset_from_now_secs);

}

#pragma mark - extension functions
std::string 
Cert::Certificate::getSubjectAlternativeNamesAsString()
{
    return Cert_GetSubjectAlternativeNamesAsString(native());
}

AlternativeDNSNameSet 
Cert::Certificate::getSubjectAlternativeDNSNames()
{
    return Cert_GetSubjectAlternativeDNSNames(native());
}

::Cert::x509::ExtDescriptions 
Cert::Certificate::getExtensionsAsDescription()
{
    return Cert_extensionsAsDescription(native());
}

void 
Cert::Certificate::addExtensionsFromSpecs(X509* ca_cert, ::Cert::x509::ExtSpecifications extra_extensions)
{
    Cert_AddExtensionsFromSpecs(native(), ca_cert, extra_extensions);
}

#pragma mark - certificate output functions

std::string 
Cert::Certificate::asPEMString()
{
    return Cert_PEMString(native());
}

void 
Cert::Certificate::writeToFilePEM(boost::filesystem::path  filePath)
{
    Cert_WriteToFile(native(), filePath.native());
}

void 
Cert::Certificate::print(boost::filesystem::path outputPath)
{
    assert(false);
}

void 
Cert::Certificate::print()
{
    Cert_Print(native());
}
std::string
Cert::Certificate::printToString()
{
    return Cert_PrintToString(native());
}

