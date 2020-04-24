
#include <cstdlib>
#include <iostream>
#include <set>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/unordered_set.hpp>
#include <boost/filesystem.hpp>

#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>
#include <cert/cert.hpp>

#include "test_fixture_new.hpp"


void printCertificate(X509* x)
{
    std::string s = Cert::x509::Cert_PrintToString(x);
    std::cout << s << std::endl;
}
void printCertificate(Cert::Certificate x)
{
    std::string s = Cert::x509::Cert_PrintToString(x.native());
    std::cout << s << std::endl;
}
void printCertificateChain(STACK_OF(X509)* chain)
{
    int n = sk_X509_num(chain);
    for(int i = 0; i < n; i++) {
        X509* x = sk_X509_value(chain, i);
        printCertificate(x);
    }
}
void printServerCerts(std::string server, std::string cert_bundle_path)
{
    boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
#define XTURN_OFF_VERIFY
#ifdef TURN_OFF_VERIFY
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
#else
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
#endif
    //
    // use a non default root certificate location, AND load them into a custom X509_STORE
    //
    X509_STORE *store = X509_STORE_new();
    X509_STORE_load_locations(store, (const char*)cert_bundle_path.c_str(), NULL);
    // attach X509_STORE to boost ssl context
    SSL_CTX_set_cert_store(ctx.native_handle(), store);

    boost::asio::io_service io;
    Handshaker::client c("https", server, ctx, io);
    c.handshake([server, &c](boost::system::error_code err) {
        if (err.failed()) {
            std::cout << "handshake callback : " << server << " err: [" << err.message() << "]" << std::endl;
//            assert(false);
        } else {
            std::cout << "handshaker callback : " << server << " success" << std::endl;
            std::cout << "Certificate for host : " << server << "===============================================" << std::endl;
            printCertificate(c.m_raw_x509_p);
            std::cout << "Cert Chain  for host : " << server << "===============================================" << std::endl;
            printCertificateChain(c.m_raw_stack_x509);
            std::cout << "======================================================================================" << std::endl;
        }
    });
    io.run();
}

/// @todo - something wqrong with the export of OSX keychain
//#define TEST_OSX_KEYCHAIN

//////////////////////////////////////////////////////////////////////////////////////////////////////
TEST_CASE_METHOD(TestFixtureNew,  "get_server_cert_file", "[]")
{
    this->loadExisting();
    std::string host = std::string("www.geeksforgeeks.org");
    std::string moz_only = this->mozRootCertificateBundleFilePath().string();
    std::string non_default = this->nonDefaultRootCertificateBundleFilePath().string();
    std::string www_geeks = "www.geeksforgeeks.org";
    std::string no_www_geeks = "geeksforgeeks.org";
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    printServerCerts(www_geeks, non_default);
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    printServerCerts(no_www_geeks, non_default);
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    std::cout << "Done" << std::endl;
}


int main( int argc, char* argv[] ) {
    // global setup...
    std::cout << "Starting" << std::endl;
    OpenSSL_add_all_algorithms ();
    ERR_load_crypto_strings ();
    ERR_load_BIO_strings();
    ERR_load_ERR_strings();

    char* t_argv[2] = {argv[0], (char*)"*"}; // change the filter to restrict the tests that are executed
    int t_argc = 2;
    TestFixtureNew f{};
    f.setup();
    int result = Catch::Session().run( t_argc, t_argv );

    // global clean-up...
    return result;
}


