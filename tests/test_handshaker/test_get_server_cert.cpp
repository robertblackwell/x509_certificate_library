
#include <cstdlib>
#include <iostream>
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
    // auto pem = Handshaker::getServerCertificatePem(host);
    // CHECK(pem.size() > 0);
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

