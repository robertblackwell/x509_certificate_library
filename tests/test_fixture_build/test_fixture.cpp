
#include <catch2/catch.hpp>
#include <boost/filesystem.hpp>

#include <cert/cert_helpers.hpp>
#include <cert/x509.hpp>
#include <cert/x509_cert_impl.hpp>

#include "test_fixture_new.hpp"
using namespace boost::filesystem;

//
// Demonstrates thet Cert::x509::_GetNotBefore and Cert::x509::_GetNotAfter return
// references to NOT COPIES of
// an ASN1_TIME object embedded inside the X509 object
//
// Further a X509_time_adj and Cert::x509::_SetNotBefore do NOT invalidate the reference
//
// Hence the ASN1_TIME objects are not owned by the caller of Cert::x509::_GetNotBefore/Cert::x509::_GetNotAfter
//
//
TEST_CASE("fixture_setup")
{
    TestFixtureNew fixture{};
    fixture.setup();
}
TEST_CASE("fixture_load_existing")
{
    TestFixtureNew fixture{};
    fixture.loadExisting();
    fixture.getAndSaveCertsForTestHosts();
}
