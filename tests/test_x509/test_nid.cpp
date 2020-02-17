
#include <catch2/catch.hpp>

#include <cert/cert_helpers.hpp>
#include <cert/x509.hpp>

#include "test_fixture_new.hpp"


/**
* Tests NID GetDescriptor - get correct details and also fails as expected
*/
TEST_CASE("nid")
{
    TestFixtureNew fixture{};
    fixture.loadExisting();
    SECTION("get_descriptor")
    {
        Cert::x509::NidDescriptor desc1;
        try {
            desc1 = Cert::x509::Nid_GetDescriptor(Cert::x509::ExtNid_subjectAltName);
            REQUIRE(true); //"should get here";
        } catch(std::exception &e) {
            REQUIRE(false);//  "should not get here";
        }
        REQUIRE(desc1.valid == true);
        REQUIRE(desc1.nid == 85);
        REQUIRE(desc1.long_name == "X509v3 Subject Alternative Name");
        REQUIRE(desc1.short_name == "subjectAltName");
//        REQUIRE(desc1.oid_hex == "{ 0x55, 0x1d, 0x11}");
    }
    SECTION("bad") // and we throw a 5zero9::Exception
    {
        Cert::x509::NidDescriptor desc2;
        int state = 0;
        
        try {
            desc2 = Cert::x509::Nid_GetDescriptor(4444);
            REQUIRE(false);// << "should not get here";
            state = 1;
        } catch(Cert::Exception &e) {
            std::cout << "This was a deliberately triggered error" << std::endl;
            REQUIRE(true); // << "should get here";
            state = 2;
        } catch (std::runtime_error& exception) {
            std::cout << "got here" << std::endl;
            state = 3;
        }
        
        REQUIRE(state == 2);
    }
}
