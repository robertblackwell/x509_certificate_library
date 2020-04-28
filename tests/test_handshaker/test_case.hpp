#ifndef cert_test_handshake_test_case_hpp
#define cert_test_handshake_test_case_hpp
#include <cstdlib>
#include <iostream>
#include <set>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/unordered_set.hpp>

#include <cert/cert.hpp>

using namespace Cert;
using namespace Handshaker::Result;

// These are header only
/**
* Provides functions that encapsulate common test patters for testing Handshaker functions
*/
namespace Testcase{

// Gets the certificate from server and does an ssl verify of that certificate
// using the OSX standard certificate bundle file
#if 0
inline Value xwithDefaultCertFile(std::string server)
{
    boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    int opt = 3;
    if (opt == 1) {
        ctx.set_default_verify_paths();
    } else if (opt == 2) {
        SSL_CTX_set_default_verify_paths(ctx.native_handle());
    } else if( opt ==3) {
        auto df = Cert::Helpers::replace_openssl_get_default_cert_file();
        if (!boost::filesystem::exists(df)) {
            throw std::string(__func__) + std::string(" openssl default cert file does not exist ") + std::string(df);
        }
        SSL_CTX_load_verify_locations(ctx.native_handle(), df.c_str(), NULL);
    } else {
        assert(false);
    }
    Handshaker::Result::Value v = Handshaker::handshakeWithServer(server, ctx);
    return v;
};
#endif
// Gets the certificate from server and does an ssl verify of that certificate
// using the OSX standard certificate bundle file but with that bundle loaded
// into memory as an X509CertStore
inline Value xwithDefaultCertFileViaX509Store(std::string server)
{
    // boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
    // ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    // X509_STORE *store = X509_STORE_new();
    auto df = Cert::Helpers::replace_openssl_get_default_cert_file();
    if (!boost::filesystem::exists(df)) {
        throw std::string(__func__) + std::string(" openssl default cert file does not exist ") + std::string(df);
    }
    // X509_STORE_load_locations(store, df.c_str(), NULL);
    // SSL_CTX_set_cert_store(ctx.native_handle(), store);
    Handshaker::Result::Value v = Handshaker::handshakeWithServer(server, df);
    return v;

};

// Gets the certificate from server and does an ssl verify of that certificate
// using a certificate bundle file that is NOT the the OSX standard certificate bundle file.
inline Value withNonDefaultCertFile(std::string server, std::string certFilePath)
{
    // boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
    // ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    // #ifdef NNNN2
    //     auto df = (const char*)sertFilePath
    //     SSL_CTX_load_verify_locations(ctx.native_handle(), df, NULL);
    //     SSL_CTX_load_verify_locations(ctx.native_handle(), df, NULL);
    // #else
    //     X509_STORE *store = X509_STORE_new();
    //     X509_STORE_load_locations(store, (const char*)certFilePath.c_str(), NULL);
    //     SSL_CTX_set_cert_store(ctx.native_handle(), store);
    // #endif
    Handshaker::Result::Value v = Handshaker::handshakeWithServer(server, certFilePath);
    return v;
};
// Gets the certificate from server and does an ssl verify of that certificate
// using a certificate bundle file that is NOT the the OSX standard certificate bundle file
// and with that non-standard bundle file loaded as a X509CertStore
inline Value withNonDefaultCertFileViaX509Store(std::string server, std::string certFilePath)
{
    // boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
    // ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    // X509_STORE *store = X509_STORE_new();
    // X509_STORE_load_locations(store, (const char*)certFilePath.c_str(), NULL);
    // SSL_CTX_set_cert_store(ctx.native_handle(), store);
    Handshaker::Result::Value v = Handshaker::handshakeWithServer(server, certFilePath);
    return v;
};

}
#endif // header guard
