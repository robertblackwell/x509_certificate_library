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
#if 0
/**
* @TODO - something wrong with the export of OSX keychain
*/
//#define TEST_OSX_KEYCHAIN

//////////////////////////////////////////////////////////////////////////////////////////////////////
// Handshakes with https://ssltest.com with both the default and a non-default
// certificate bundle file
TEST_CASE_METHOD(TestFixtureNew, "ssltest_file", "[file]")
{
    this->loadExisting();
    Handshaker::Result::Value res;
    res = Testcase::withDefaultCertFile("ssltest");
    CHECK(Handshaker::Result::validateFailInHandshake(res, "ssltest + default"));

    res = Testcase::withNonDefaultCertFile("ssltest", this->nonDefaultRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateFailInHandshake(res, "ssltest + explicit use of default file"));

 #ifdef TEST_OSX_KEYCHAIN
    res = Testcase::withNonDefaultCertFile("ssltest", osxCombinedRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, "ssltest + osx keychain export with local ca"));
 #endif
    res = Testcase::withNonDefaultCertFile("ssltest", this->mozCombinedRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, "ssltest + moz with local ca"));
    
    Handshaker::Result::NameSet s;

    s.insert("ssltest");
    s.insert("api.ssltest");
    s.insert("www.ssltest");

    Handshaker::Result::validateSubjectAltNames(res, s, "ssltest + testing subjectAltNames");
};

//////////////////////////////////////////////////////////////////////////////////////////////////////
// Handshakes with https://ssltest.com with both the default and a non-default
// certificate bundle file loaded as an X509CertStore
TEST_CASE_METHOD(TestFixtureNew, "ssltest_store", "[store]")
{
    this->loadExisting();
    Handshaker::Result::Value res;
        res = Testcase::withDefaultCertFileViaX509Store("ssltest");
        CHECK(Handshaker::Result::validateFailInHandshake(res, "ssltest + default + x509 store"));
        res = Testcase::withNonDefaultCertFileViaX509Store("ssltest", this->nonDefaultRootCertificateBundleFilePath().string());
        CHECK(Handshaker::Result::validateFailInHandshake(res, "ssltest + explicit use of default file + x509 store"));
 #ifdef TEST_OSX_KEYCHAIN
        res = Testcase::withNonDefaultCertFileViaX509Store("ssltest", this->osxRootCertificateBundleFilePath().string());
        CHECK(Handshaker::Result::validateSuccess(res, "ssltest + local cert file that has BlackwellApps root + x509 store"));
#endif
        res = Testcase::withNonDefaultCertFileViaX509Store("ssltest", this->osxCombinedRootCertificateBundleFilePath().string());
        CHECK(Handshaker::Result::validateSuccess(res, "ssltest + local cert file that has BlackwellApps root + x509 store"));
    
        Handshaker::Result::NameSet s;
        s.insert("ssltest");
        s.insert("api.ssltest");
        s.insert("www.ssltest");

        Handshaker::Result::validateSubjectAltNames(res, s, "ssltest + testing subjectAltNames");
};

#endif
