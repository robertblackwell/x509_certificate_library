
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
/// Handshakes with host (bankofamerica.com) and verifies the hosts root certificate against 2 specially prepared
/// certificate bundles:
/// -   the 'with' bundle has the hosts root certificate and hence verifies OK
/// -   the 'without' bundle which does not have the hosts root certificate and hence verification
///     should fail; that is the test.
//////////////////////////////////////////////////////////////////////////////////////////////////////
TEST_CASE_METHOD(TestFixtureNew,  "wwo_file", "[wwo, file]")
{
    this->loadExisting();
    std::string wwo_host = this->hostForWithWithoutTests();
    std::string wwo_with = this->withWithoutRootCertificateBundleFilePath("with").string();
    std::string wwo_without = this->withWithoutRootCertificateBundleFilePath("without").string();
    auto res1 = Testcase::withNonDefaultCertFile(wwo_host, wwo_with);
    CHECK(Handshaker::Result::validateSuccess(res1, "wwo + local cert file that has the required root"));
    // THIS FAILS
    std::cout << std::endl << "NOTE:  Verify should fail for host : " << wwo_host << std::endl << std::endl;
    auto res2 = Testcase::withNonDefaultCertFile(wwo_host, wwo_without);
    CHECK(Handshaker::Result::validateFailInHandshake(res2, "wwo + local cert file that DOES NOT have required root cert"));

}
//////////////////////////////////////////////////////////////////////////////////////////////////////
/// Handshakes with host (bankofamerica.com) as above but loads each certificate
/// bundle into an X509CertStore instead of using a disk file for the verification
/// using X509Store
//////////////////////////////////////////////////////////////////////////////////////////////////////
TEST_CASE_METHOD(TestFixtureNew,  "wwo_store", "[wwo, store]")
{
    this->loadExisting();
    std::string wwo_host = this->hostForWithWithoutTests();
    std::string wwo_with = this->withWithoutRootCertificateBundleFilePath("with").string();
    std::string wwo_without = this->withWithoutRootCertificateBundleFilePath("without").string();
    auto res = Testcase::withNonDefaultCertFileViaX509Store(wwo_host, wwo_with);
    CHECK(Handshaker::Result::validateSuccess(res, "wwo + local cert file that has the required root + x509 store"));
    std::cout << std::endl << "NOTE:  Verify should fail for host : " << wwo_host << std::endl << std::endl;
    res = Testcase::withNonDefaultCertFileViaX509Store(wwo_host, wwo_without);
    CHECK(Handshaker::Result::validateFailInHandshake(res, "wwo + local cert file that DOES NOT have required root cert + x509 store"));
}
