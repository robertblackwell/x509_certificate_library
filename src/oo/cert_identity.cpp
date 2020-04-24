
#include <cert/cert.hpp>

namespace Cert {

class Identity::Impl 
{
public:
    Impl()
    {
        m_cert = nullptr;
        m_private_key = nullptr;
    }
    Impl(X509* certificate, EVP_PKEY* keypair)//: m_cert(certificate), m_private_key(keyptr)
    {
        m_cert = certificate; X509_up_ref(certificate);
        m_private_key = keypair; EVP_PKEY_up_ref(keypair);
    }
    ~Impl()
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
    X509* getX509() {return m_cert;}
    EVP_PKEY* getPKey() {return m_private_key;}
    X509*       m_cert;
    EVP_PKEY*   m_private_key;
};

Identity::~Identity()
{
    m_impl_sptr = nullptr;
}
Identity::Identity()
{
    m_impl_sptr = std::make_shared<Identity::Impl>();
}
Identity::Identity(X509* certificate, EVP_PKEY* keypair)//: m_cert(certificate), m_private_key(keyptr)
{
    m_impl_sptr = std::make_shared<Identity::Impl>(certificate, keypair);
};
Identity::operator bool() const
{
    return ((m_impl_sptr->m_cert != nullptr) && (m_impl_sptr->m_private_key != nullptr));
}
X509*
Identity::getX509()
{
    return m_impl_sptr->m_cert;
}
Certificate
Identity::getCertificate()
{
    return Certificate(m_impl_sptr->m_cert);
}
EVP_PKEY*
Identity::getEVP_PKEY()
{
    return m_impl_sptr->m_private_key;
}
EvpPKey
Identity::getEvpPKey()
{
    return EvpPKey(m_impl_sptr->m_private_key);
}
} //namespace Cert

