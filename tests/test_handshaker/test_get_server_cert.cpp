
#include <cstdlib>
#include <iostream>
#include <string>
#include <set>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/unordered_set.hpp>
#include <boost/filesystem.hpp>

#include <catch2/catch.hpp>
#include <cert/cert.hpp>

#include "test_case.hpp"
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
    X509_STORE *store = X509_STORE_new();
    X509_STORE_load_locations(store, (const char*)cert_bundle_path.c_str(), NULL);

    boost::asio::io_service io;
    Handshaker::client c("https", server, io);
    c.becomeSecure(store);
    c.handshake([server](boost::system::error_code err) {
        if (err.failed()) {
            std::cout << "handshake callback : " << server << " err: [" << err.message() << "]" << std::endl;
//            assert(false);
        } else {
            std::cout << "handshaker callback : " << server << " success" << std::endl;
        }
    });
    io.run();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
/// Duplicate: Handshakes with https://badssl.com and verifies certificate using 3 options
/// for the validating certificate bundle.
///     OSX standard location and standard bundle,
///     non-standard location for the standard openssl bundle,
///     a non standard location for the Mozilla bundle
//////////////////////////////////////////////////////////////////////////////////////////////////////
TEST_CASE_METHOD(TestFixtureNew,  "get_server_cert_file", "[]")
{
    this->loadExisting();
    std::string host = this->hostForBundleTests();
    std::string moz_only = this->mozRootCertificateBundleFilePath().string();
    std::string non_default = this->nonDefaultRootCertificateBundleFilePath().string();
    auto pem = Handshaker::getServerCertificatePem(host, non_default);

    CHECK(pem.size() > 0);
    pem = Handshaker::getServerCertificatePem(host, moz_only);
    CHECK(pem.size() > 0);
    {
        X509_STORE* store =  X509_STORE_new();
        X509_STORE_load_locations(store, (const char*)non_default.c_str(), NULL);
        auto pem = Handshaker::getServerCertificatePem(host, store);
        CHECK(pem.size() > 0);
    }
    {
        X509_STORE* store =  X509_STORE_new();
        X509_STORE_load_locations(store, (const char*)moz_only.c_str(), NULL);
        auto pem = Handshaker::getServerCertificatePem(host, store);
        CHECK(pem.size() > 0);
    }
}

