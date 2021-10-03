
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
TEST_CASE("time")
{
    TestFixtureNew fixture{};
    fixture.loadExisting();
    std::string cert_file_name = fixture.realCertFilePathForHost("host_b").string();
    boost::filesystem::path p3 = cert_file_name;
    if(   ! Cert::Helpers::fs::exists(p3) ) {
        std::cout << "WARNING - certificate used for testing does not exist" << std::endl;
    }
    REQUIRE( Cert::Helpers::fs::exists(p3) );
    
    SECTION("CertGetterIsReferenceOnly")
    {
        X509* original_cert = Cert::x509::Cert_ReadFromFile(fixture.realCertFilePathForHost("host_b").string());
        ASN1_TIME* t_1 = Cert::x509::Cert_GetNotBefore(original_cert);
        auto s1 = Cert::x509::TimeAsString(t_1);
        
        X509_time_adj(t_1, 60*60*24*365, nullptr);
        auto s2 = Cert::x509::TimeAsString(t_1);
        ASN1_TIME* t_2 = Cert::x509::Cert_GetNotBefore(original_cert);
        auto s3 = Cert::x509::TimeAsString(t_2);
        // these assertions demonstrates that t_1 and T-2 are references to the same ASN1_TIME object
        REQUIRE(s2 == s3);
        REQUIRE(s1 != s3);
    //    ASSERT_EQ(s2, s3);
    //    ASSERT_NE(s1, s3);
        // ASN1_TIME_free(t_1); this is definitley WRONG
        // ASN1_TIME_free(t_2);
        X509_free(original_cert);
    }

    /**
    ** Tests setting a time value in NotBefore - see internal comments in NotAfter below
    */
    SECTION("SetGetNotBefore")
    {
        X509* cert1 = Cert::x509::Cert_ReadFromFile(fixture.realCertFilePathForHost("host_b").string());
        X509* cert2 = X509_new();
        ASN1_TIME* t_1 = Cert::x509::Cert_GetNotBefore(cert1);
        ASN1_TIME* t_2 = Cert::x509::Cert_GetNotBefore(cert2);
        ASN1_STRING* s_1 = (ASN1_STRING*) t_1;
        ASN1_STRING* s_2 = (ASN1_STRING*) t_2;
        auto r1 = ASN1_STRING_cmp(s_1, s_2);
        REQUIRE(r1 != 0);
    //    ASSERT_NE(r1, 0) << "first comparison should be NE" << std::endl;;
        Cert::x509::Cert_SetNotBefore(cert2, t_1);
        // there is no comparison function for ASN1_TIME so cast them to ASN1_STRING and use ASN1_STRING_cmp()
        auto r2 = ASN1_STRING_cmp(s_1, s_2);
        REQUIRE(r2 == 0);
    //    ASSERT_EQ(r2, 0) << "second comparisons should be equal" << std::endl;
        X509_free(cert1);
        X509_free(cert2);
    }
    /**
    ** Tests setting a time value in NotBefore
    */
    SECTION("Time_SetGetNotAfter")
    {
        X509* cert1 = Cert::x509::Cert_ReadFromFile(fixture.realCertFilePathForHost("host_b").string());
        X509* cert2 = X509_new();
        ASN1_TIME* t_1 = Cert::x509::Cert_GetNotAfter(cert1);
        ASN1_TIME* t_2 = Cert::x509::Cert_GetNotAfter(cert2);
        ASN1_STRING* s_1 = (ASN1_STRING*) t_1;
        ASN1_STRING* s_2 = (ASN1_STRING*) t_2;
        auto r1 = ASN1_STRING_cmp(s_1, s_2);
        // the two certificates have different NotAfter times
        REQUIRE(r1 != 0);
    //    ASSERT_NE(r1, 0) << "first comparison should be NE" << std::endl;
        // change the NotAfter time for cert2
        Cert::x509::Cert_SetNotAfter(cert2, t_1);
        // s_1 and s_ are now equal - demonstrating that the set worked
        // but also that the internal pointer to the NotAfter of cert1 IS STILL VALID
        auto r2 = ASN1_STRING_cmp(s_1, s_2);
        REQUIRE(r2 == 0);
    //    ASSERT_EQ(r2, 0) << "second comparisons should be equal" << std::endl;
        X509_free(cert1);
        X509_free(cert2);
    }
}
