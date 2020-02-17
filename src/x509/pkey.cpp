//
//  x509_pkey.cpp
//  openssl_10_6
//
//  Created by ROBERT BLACKWELL on 10/26/17.
//  Copyright © 2017 Blackwellapps. All rights reserved.
//
#include <openssl/rsa.h>
#include <openssl/rsaerr.h>
#include "x509.hpp"

//std::string const_password("blackwellapps");

typedef int (*PemPasswordCb)(char *buf, int size, int rwflag, void *u);

int password_cb(char *buf, int size, int rwflag, void *u)
{
    #if 0
        std::string s(const_password);
        const char* c_s = s.c_str();
        std::strcpy(buf, c_s);
    return (int)s.length();
    #else
        const char* up = (char*)u;
        std::strcpy(buf, up);
        return (int)strlen(up);
    #endif
}

EVP_PKEY* Cert::x509::Rsa_Generate()
{
    EVP_PKEY* tmp_pkey = nullptr;
    BIGNUM* bne = nullptr;
    RSA* rsa = nullptr;
    bne = BN_new();
    int bits = 1024;
    unsigned long e = RSA_F4;
    int ret = BN_set_word(bne, e); 
    if(ret == 1){
        rsa = RSA_new();
        if (1 == RSA_generate_key_ex(rsa, bits, bne, NULL)) {
            tmp_pkey = EVP_PKEY_new();
            EVP_PKEY_assign_RSA(tmp_pkey, rsa);
        } else {
            X509_TRIGGER_ERROR("RSA key generation failed in RSA_generate_key_ex");
        }
        // NOTE:: it is tempting to free the RSA* BUT - it is captured in the EVP_PKEY*
        // as a result of the EVP+PKEY_assign_RSA
        // RSA_free(rsa);
        BN_free(bne);
        return tmp_pkey;
    } else {
        X509_TRIGGER_ERROR("RSA key generation failed at BN_set_word");
        return nullptr;
    }
}

EVP_PKEY*
Cert::x509::PKey_ReadPrivateKeyFrom(std::string fileName, std::string password)
{
    /*
    * Type conversion nonsense - because C code does not convert well to C++
    */
    EVP_PKEY* dummyIn = EVP_PKEY_new();
    EVP_PKEY *pkey;
    FILE* fp;
    char* fileNameCStr = (char*)fileName.c_str();
    
    if (!(fp = fopen (fileNameCStr, "r")))
        X509_TRIGGER_ERROR( "ReadPrivateKeyFrom:: failed to open key file : " + fileName);

// have not implemented the callback version of loading a private key

#define PWCB //use password callback
#ifdef PWCB
    void* pw = (void*) password.c_str();
    if (!(pkey = PEM_read_PrivateKey (fp, &dummyIn, &password_cb, pw)))
        X509_TRIGGER_ERROR ("ReadPrivateKey::Error reading private key in file : " + fileName);
#else
    PemPasswordCb nullCb = nullptr;
    char* pwchptr = (char*) password.c_str();
    void* pw = (void*) password.c_str();
    if (!(pkey = PEM_read_PrivateKey (fp, dummyIn, nullCb, pw)))
        X509_TRIGGER_ERROR ("ReadPrivateKey::Error reading private key in file");
#endif
    assert(pkey == dummyIn);
    fclose(fp);
    
    return pkey;
}
#if 0 // remove function to read pkey without password or with default password
EVP_PKEY* Cert::x509::PKey_ReadPrivateKeyFrom(std::string fileName)
{
//    throw "not implemented";
    return Cert::x509::PKey_ReadPrivateKeyFrom(fileName, const_password);
}
#endif
void Cert::x509::PKey_WritePrivateKey(EVP_PKEY* pkey, std::string filename, std::string password)
{
    FILE * fp;
    std::string passphrase = password;
    char* fn_cstr = (char*)filename.c_str();
    if (!(fp = fopen(fn_cstr, "w")) )
        X509_TRIGGER_ERROR("Error openning to key file for write");
//    void* pw = (void*) password.c_str();
    unsigned char* passphrase_cstr = (unsigned char*)passphrase.c_str();
    int passphraseLength = (int)passphrase.size();
    int retCode = PEM_write_PrivateKey(
            fp,
            pkey,
            EVP_aes_128_cbc(),
            passphrase_cstr, passphraseLength, //send password in as passphrase
            nullptr, nullptr //ignore password cb and arg
        );
    if (retCode != 1) {
        X509_TRIGGER_ERROR("Error writing to key file");
    }
    fclose (fp);
}
std::string
Cert::x509::PKey_PublicKeyAsPEMString(EVP_PKEY* pkey)
{
    BIO* out_bio = BIO_new(BIO_s_mem());
    EVP_PKEY_print_public(out_bio, pkey, 0, nullptr);
    std::string s = BIO_to_string(out_bio);
    BIO_free(out_bio);
    return s;
    #if 0
    char* ret = (char *) malloc(BIO_mem_length(out_bio) + 1);
    if (NULL == ret) {
        BIO_free(out_bio);
        X509_TRIGGER_ERROR("malloc failed in Cert::x509::PKey_PublicKeyAsString");
    }

    memset(ret, 0, BIO_mem_length(out_bio) + 1);
    BIO_read(out_bio, ret, (int)BIO_mem_length(out_bio));
    std::string s(ret);
    BIO_free(out_bio);
    return s;
    #endif
}

std::string Cert::x509::PKeyPrivate_AsPEMString(EVP_PKEY* pkey)
{
    BIO* out_bio = BIO_new(BIO_s_mem());
    EVP_PKEY_print_private(out_bio, pkey, 0, nullptr);
    std::string s = BIO_to_string(out_bio);
    BIO_free(out_bio);
    return s;
    #if 0
    char* ret = (char *) malloc(BIO_mem_length(out_bio) + 1);
    if (NULL == ret) {
        BIO_free(out_bio);
        X509_TRIGGER_ERROR("malloc failed in Cert::x509::PKeyPrivate_AsPEMString");
    }

    memset(ret, 0, BIO_mem_length(out_bio) + 1);
    BIO_read(out_bio, ret, (int)BIO_mem_length(out_bio));
    std::string s(ret);
    BIO_free(out_bio);
    return s;
    #endif
}
EVP_PKEY* Cert::x509::PKeyPrivate_FromPEMString(std::string pem)
{
    return NULL;
}
std::string Cert::x509::PKeyPrivatePEM_FromFile(std::string filename)
{
    return "";
}
void Cert::x509::PKeyPrivatePEM_ToFile(std::string pem, std::string filename, std::string password)
{
    
}
