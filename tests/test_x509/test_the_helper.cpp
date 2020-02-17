
#include <catch2/catch.hpp>
#include <boost/filesystem.hpp>

#include <cert/x509.hpp>
#include <cert/cert.hpp>
#include <cert/cert_store.hpp>

#include "test_fixture_new.hpp"
// info related to the code in this project
//https://zakird.com/2013/10/13/certificate-parsing-with-openssl
//http://fm4dd.com/openssl/add_oids_to_openssl.htm
//http://www.zytrax.com/tech/survival/ssl.html
//https://apidock.com/ruby/v1_9_3_125/OpenSSL/X509/Certificate/extensions%3D
//http://openssl.cs.utah.edu/docs/apps/x509v3_config.html#certificate_policies_
//http://fm4dd.com/openssl/certverify.htm
#if 1
void RsaGenAndWrite(std::string fn1, std::string fn2, std::string password)
{
    if( Cert::Helpers::fs::is_regular_file(fn1)) {
        boost::filesystem::remove(fn1);
    }
    if( Cert::Helpers::fs::is_regular_file(fn2)) {
        boost::filesystem::remove(fn2);
    }

    EVP_PKEY* tmp_pkey = nullptr;
    BIGNUM* bne = nullptr;
    RSA* rsa = nullptr;
    FILE* fp1 = fopen(fn1.c_str(), "w");
    FILE* fp2 = fopen(fn2.c_str(), "w");
    unsigned char* pw = (unsigned char*) password.c_str();
    int len = (int)password.size();
    bne = BN_new();
    int bits = 1024;
    unsigned long e = RSA_F4;
    BN_set_word(bne, e);
    rsa = RSA_new();
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-variable"
    int res = RSA_generate_key_ex(rsa, bits, bne, NULL);
    auto enc = EVP_aes_128_cbc();
    int r2 = PEM_write_RSAPrivateKey(fp1, rsa, enc, pw, len, nullptr, nullptr);

    tmp_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(tmp_pkey, rsa);
    int r3 = PEM_write_PrivateKey(fp2, tmp_pkey, enc, pw, len, nullptr, nullptr);
    #pragma clang diagnostic pop
    RSA_free(rsa);
    BN_free(bne);
}
std::pair<RSA*, EVP_PKEY*>
KeysGen(std::string password) {
    EVP_PKEY* tmp_pkey = nullptr;
    BIGNUM* bne = nullptr;
    RSA* rsa = nullptr;
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-variable"
    unsigned char* pw = (unsigned char*) password.c_str();
    int len = (int)password.size();
    #pragma clang diagnostic pop
    bne = BN_new();
    int bits = 1024;
    unsigned long e = RSA_F4;
    if (1 != BN_set_word(bne, e)) {
        assert(false);
    }
    rsa = RSA_new();
    int res;
    if( 1 != (res = RSA_generate_key_ex(rsa, bits, bne, NULL))){
        assert(false);
    }
    tmp_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(tmp_pkey, rsa);
    std::pair<RSA*, EVP_PKEY*> result;
    result.first = rsa;
    result.second = tmp_pkey;
    return result;
}

void KeysWrite(std::string fn1, std::string fn2, std::pair<RSA*, EVP_PKEY*> keys, std::string password)
{
    if( Cert::Helpers::fs::is_regular_file(fn1)) {
        boost::filesystem::remove(fn1);
    }
    if( Cert::Helpers::fs::is_regular_file(fn2)) {
        boost::filesystem::remove(fn2);
    }

    EVP_PKEY* tmp_pkey = keys.second;
    RSA* rsa = keys.first;
    FILE* fp1 = fopen(fn1.c_str(), "w");
    FILE* fp2 = fopen(fn2.c_str(), "w");
    unsigned char* pw = (unsigned char*) password.c_str();
    int len = (int)password.size();
    auto enc = EVP_aes_128_cbc();
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-variable"

    int r2 = PEM_write_RSAPrivateKey(fp1, rsa, enc, pw, len, nullptr, nullptr);
    int r3 = PEM_write_PrivateKey(fp2, tmp_pkey, enc, pw, len, nullptr, nullptr);
    #pragma clang diagnostic pop
}
#endif

/// @brief test pkey password works and confirms it is not hard coded
TEST_CASE("private_key_password","")
{
    TestFixtureNew fixture{};
    fixture.loadExisting();
    auto fn = (boost::filesystem::path(__FILE__).parent_path() / "test_key.pem");
    auto fn2 = (boost::filesystem::path(__FILE__).parent_path() / "2test_key.pem");

    RsaGenAndWrite(fn.string(), fn2.string(), std::string("thisisapassword"));
    std::pair<RSA*, EVP_PKEY*> keys = KeysGen(std::string("thisisapassword"));
    KeysWrite(fn.string(), fn2.string(), keys, std::string("thisisapassword"));
    
    EVP_PKEY* pk = Cert::x509::Rsa_Generate();
//    auto fn = (boost::filesystem::path(__FILE__).parent_path() / "test_key.pem");
//    if( Cert::Helpers::fs::is_regular_file(fn)) {
//        boost::filesystem::remove(fn);
//    }
    
    std::string pw = "thisisapassword";
    Cert::x509::PKey_WritePrivateKey(pk, fn.string(), pw);
    EVP_PKEY* pk2 = Cert::x509::PKey_ReadPrivateKeyFrom(fn.string(), pw);
    CHECK(pk2 != nullptr);
}
TEST_CASE("access-ca-cert-ca-privatekey")
{
    TestFixtureNew fixture{};
    fixture.loadExisting();
    Cert::Store::Locator locator(fixture.storeRootDirPath());
    Cert::Store::LocatorSPtr locator_sptr = fixture.m_locator_sptr;
    Cert::AuthoritySPtr auth_sptr = fixture.m_authority_sptr;
    // got here then key is loaded - ok
    auto pkey = auth_sptr->getCAPKey();
    auto ca_cert = auth_sptr->getCAPKey();
//    std::string pkey_path = fixture.ca_key_path;  //helper.caKeyPath();
//    std::string pkey_password = fixture.ca_key_password; //helper.caKeyPassword();
//    auto pkey =  Cert::x509::PKey_ReadPrivateKeyFrom(pkey_path, pkey_password);
    CHECK(pkey != NULL);
//    std::string ca_cert_path = helper.caCertPath();
//    auto ca_cert = Cert::x509::Cert_ReadFromFile(ca_cert_path);
    CHECK(ca_cert != NULL);
}

