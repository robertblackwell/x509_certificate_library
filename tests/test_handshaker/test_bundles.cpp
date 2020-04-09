
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
/// Handshake with host(https://badssl.com) using all 4 sources for cert bundle as a file
/// Sources are:
///     - ssl standard location on OSX
///     - non-standard location (but openssl bundle)
///     - non-standard location and using the Mozilla bundle
///     - 4th option not working
//////////////////////////////////////////////////////////////////////////////////////////////////////
TEST_CASE_METHOD(TestFixtureNew,  "bundle_file", "[bundle, file]")
{
    this->loadExisting();
    std::string host = this->hostForBundleTests();
#if 0
    auto res = Testcase::withDefaultCertFile(host);
    CHECK(Handshaker::Result::validateSuccess(res, "bundle + default"));
    res = Testcase::withNonDefaultCertFile(host, this->nonDefaultRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, "bundle + explicit use of default file"));
#endif
#if 0
    res = Testcase::withNonDefaultCertFile(host, wwo_with);
    CHECK(Handshaker::Result::validateSuccess(res, "bundle + local cert file that has the required root"));
    res = Testcase::withNonDefaultCertFile(host, wwo_without);
    CHECK(Handshaker::Result::validateFailInHandshake(res, "bundle + local cert file that DOES NOT have required root cert"));
#endif

#ifdef TEST_OSX_KEYCHAIN
    res = Testcase::withNonDefaultCertFile(host, this->osxRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, "bundle + osx keychain export"));
#endif

    auto res2 = Testcase::withNonDefaultCertFile(host, this->mozRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res2, "bundle + mozilla download"));
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
/// Handshake with host(https://badssl.com) using all 4 sources for cert
/// bundle as a file loaded as X509CertStore
/// Sources are:
///     - ssl standard location on OSX as X509CertStore
///     - non-standard location (but openssl bundle) as X509CertStore
///     - non-standard location and using the Mozilla bundle as X509CertStore
///     - 4th option not working
//////////////////////////////////////////////////////////////////////////////////////////////////////
TEST_CASE_METHOD(TestFixtureNew,  "bundle_store", "[store]")
{
    this->loadExisting();
    std::string host = this->hostForBundleTests();
    #if 0
    auto res = Testcase::withDefaultCertFileViaX509Store(host);
    CHECK(Handshaker::Result::validateSuccess(res, "bundle + default + x509 store"));
    res = Testcase::withNonDefaultCertFileViaX509Store(host, this->nonDefaultRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, "bundle + explicit use of default file + x509 store"));
#endif
#if 0
    res = Testcase::withNonDefaultCertFileViaX509Store(host, wwo_with);
    CHECK(Handshaker::Result::validateSuccess(res, "bundle + local cert file that has the required root + x509 store"));
    res = Testcase::withNonDefaultCertFileViaX509Store(host, wwo_without);
    CHECK(Handshaker::Result::validateFailInHandshake(res, "bundle + local cert file that DOES NOT have required root cert + x509 store"));
#endif

#ifdef TEST_OSX_KEYCHAIN
    res = Testcase::withNonDefaultCertFileViaX509Store(host, this->osxRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, "bundle + os keychain export"));
#endif

    auto res2 = Testcase::withNonDefaultCertFileViaX509Store(host, this->mozRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res2, "bundle + mozilla download"));
}



