
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

#include "test_case.hpp"
#include "test_fixture_new.hpp"

/// @todo - something wqrong with the export of OSX keychain
//#define TEST_OSX_KEYCHAIN

//////////////////////////////////////////////////////////////////////////////////////////////////////
TEST_CASE_METHOD( TestFixtureNew, "generic host_file","[file]")
{
    this->loadExisting();
    std::string host = this->hostForWithWithoutTests();
#if 0
    auto res = Testcase::withDefaultCertFile(host);
    CHECK(Handshaker::Result::validateSuccess(res, host + " default"));
    res = Testcase::withNonDefaultCertFile(host, this->nonDefaultRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, "generic + explicit use of default file"));
#endif
    auto res = Testcase::withNonDefaultCertFile(host, this->mozRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, host + " + mozilla cert "));
    res = Testcase::withNonDefaultCertFile(host, this->mozCombinedRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, host + " + mozilla cert + ca"));

#ifdef TEST_OSX_KEYCHAIN
    res = Testcase::withNonDefaultCertFile(host, this->osxRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, host + " + osx cert "));
    res = Testcase::withNonDefaultCertFile(host, this->osxCombinedRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, host + " + osx cert + ca "));
#endif

};

TEST_CASE_METHOD(TestFixtureNew, "generic_host_store", "[store]")
{
    this->loadExisting();
    std::string host = this->hostForWithWithoutTests();
    Handshaker::Result::Value res;
 
#if 0
    res = Testcase::withDefaultCertFileViaX509Store(host);
    CHECK(Handshaker::Result::validateSuccess(res, host + " + default + x509 store"));
#endif    
    res = Testcase::withNonDefaultCertFileViaX509Store(host, this->nonDefaultRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, host + " + explicit use of default file + x509 store"));
    
    res = Testcase::withNonDefaultCertFileViaX509Store(host, this->mozRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, host + " + mozilla download + x509 store"));
    res = Testcase::withNonDefaultCertFileViaX509Store(host, this->mozCombinedRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, host + " + mozilla local ca cert  + x509 store"));

#ifdef TEST_OSX_KEYCHAIN
    res = Testcase::withNonDefaultCertFileViaX509Store(host, this->osxRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, host + " + osx + x509 store"));
    res = Testcase::withNonDefaultCertFileViaX509Store(host, othis->osxCombinedRootCertificateBundleFilePath().string());
    CHECK(Handshaker::Result::validateSuccess(res, host + " + osx +  local ca cert  + x509 store"));
#endif
};


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


