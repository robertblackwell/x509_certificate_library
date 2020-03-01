
#include <cert/cert.hpp>

using namespace Cert::x509;

namespace Cert {

EvpPKey::EvpPKey()
{
    m_evp_pkey = nullptr;
}

EvpPKey::EvpPKey(boost::filesystem::path pemFilePath, std::string password)
{
    EVP_PKEY* x = PKey_ReadPrivateKeyFrom(pemFilePath.native(), password);
    m_evp_pkey = x;
    EVP_PKEY_up_ref(m_evp_pkey);
    EVP_PKEY_free(x);
}
EvpPKey::EvpPKey(EVP_PKEY* pk)
{
    m_evp_pkey = pk;
    EVP_PKEY_up_ref(pk);
}
EvpPKey::~EvpPKey()
{
    if (m_evp_pkey != nullptr) {
        EVP_PKEY_free(m_evp_pkey);
    }
}
EvpPKey::operator bool() const
{
    return (m_evp_pkey != nullptr);
}
EVP_PKEY* EvpPKey::native()
{
    return m_evp_pkey;
}
std::string
EvpPKey::privateKeyAsPemString()
{
    std::string s = PKeyPrivate_AsPEMString(native());
    return s;
}
void
EvpPKey::writePrivateKeyToFile(boost::filesystem::path filePath)
{
    Helpers::fs::file_put_contents(filePath, privateKeyAsPemString());
}
std::string
EvpPKey::printPrivateKeyToString()
{
    return "";
}
void
EvpPKey::printPrivateKeyToFile(boost::filesystem::path filePath)
{
    ASSERT(false, "NOT IMPLEMENTED");
}
std::string EvpPKey::publicKeyToString()
{
    return PKey_PublicKeyAsPEMString(native());
}


} // namespace
