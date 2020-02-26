
#include <cert/cert.hpp>

namespace Cert {
Identity::~Identity()
{
    if(m_cert != nullptr && m_private_key != nullptr) {
        X509_free(m_cert);
        EVP_PKEY_free(m_private_key);
    } else if( (m_cert == nullptr) && (m_private_key == nullptr) ) {
        // do nothing
    } else {
//        throw std::string(__func__) + std::string(" identity is inconsistent one of the points is null and the other not");
        THROW("failed in Identity destructor"); // should not get here
    }
}

Identity::Identity(X509* certificate, EVP_PKEY* keypair)//: m_cert(certificate), m_private_key(keyptr)
{
    m_cert = certificate; X509_up_ref(certificate);
    m_private_key = keypair; EVP_PKEY_up_ref(keypair);
};
X509*
Identity::getX509()
{
    return m_cert;
}
EVP_PKEY*
Identity::getEVP_PKEY()
{
    return m_private_key;
}
} //namespace Cert

