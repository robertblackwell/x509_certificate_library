
#include <catch2/catch.hpp>
#include <boost/filesystem.hpp>

#include <cert/cert_helpers.hpp>
#include <cert/x509.hpp>

#include "test_fixture_new.hpp"

/// test making an X509_NAME from scratch
TEST_CASE("name", "")
{
    TestFixtureNew fixture{};
    fixture.loadExisting();
    std::string host_b_cert_file_name = fixture.realCertFilePathForHost("host_b").string();
    boost::filesystem::path p3 = host_b_cert_file_name;
    if(   ! Cert::Helpers::fs::exists(p3) ) {
        std::cout << "WARNING - certificate used for testing does not exist" << std::endl;
    }
    REQUIRE( Cert::Helpers::fs::exists(p3) );

    SECTION("Name_Make3FromScratch")
    {
    }
    SECTION("Name_Make2FromScratch")
    {
        std::map<int, std::string> spec = {
            {Cert::x509::NameNid_countryName, "AU"},
            {Cert::x509::NameNid_stateOrProvince, "NSW"},
            {Cert::x509::NameNid_organizationName, "MyOrganization"},
            {Cert::x509::NameNid_organizationalUnitName, "MyOrganization-Unit-One"},
            {Cert::x509::NameNid_commonName, "myorg.com"},
        };
        X509_NAME* name = Cert::x509::Name_fromSpec(spec);
        Cert::x509::NameSpecification s1 = Cert::x509::Name_getSpec(name);
        
        REQUIRE(s1 == spec);
        X509_NAME_free(name);

    }
    /// test making an X509_NAME from scratch
    SECTION("Name_MakeFromScratch")
    {
        {
            X509_NAME* name1;
            name1 = X509_NAME_new();
            Cert::x509::Name_AddEntryByNID(name1,Cert::x509::NameNid_countryName, "AU");
            Cert::x509::Name_AddEntryByNID(name1,Cert::x509::NameNid_stateOrProvince, "NSW");
            Cert::x509::Name_AddEntryByNID(name1,Cert::x509::NameNid_organizationName, "MyOrganization");
            Cert::x509::Name_AddEntryByNID(name1,Cert::x509::NameNid_organizationalUnitName, "MyOrganization-Unit-One");
            Cert::x509::Name_AddEntryByNID(name1,Cert::x509::NameNid_commonName, "myorg.com");
            std::string s1 = Cert::x509::Name_AsOneLine(name1);
            REQUIRE(s1 == "C=AU, ST=NSW, O=MyOrganization, OU=MyOrganization-Unit-One, CN=myorg.com");
            X509_NAME_free(name1);
        }
    }
    // test we can get the coponents of an X509_NAME correctly
    SECTION("Name_GetNameEntries")
    {
        X509_NAME* name1;
        name1 = X509_NAME_new();
        X509* cert = Cert::x509::Cert_ReadFromFile(host_b_cert_file_name);
//        X509_NAME* name2 = Cert::x509::Cert_GetIssuerName(cert);
//        std::map<int, std::string> res = Cert::x509::Name_getSpec(name2);
        Cert::x509::NameSpecification res = Cert::x509::Cert_GetIssuerNameAsSpec(cert);
        // verify that we got the correct values
        for(auto const & ent : res) {
    //        std::cout << ent.nid_descriptor.short_name << "  : " << ent.value << std::endl;
            switch(ent.first) {
            case Cert::x509::NameNid_countryName:
                REQUIRE(ent.second == "US");
                break;
            case Cert::x509::NameNid_organizationName:
                REQUIRE(ent.second == "Google Trust Services");
                break;
            case Cert::x509::NameNid_commonName:
                REQUIRE(ent.second == "Google Internet Authority G3");
                break;
            case Cert::x509::NameNid_stateOrProvince:
            case Cert::x509::NameNid_organizationalUnitName:
            default:
                REQUIRE(false);
                break;
            }
        }
        X509_NAME_free(name1);
    }
}
