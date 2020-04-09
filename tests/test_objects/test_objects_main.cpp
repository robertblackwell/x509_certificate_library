#include <iostream>
#include <map>
#include <boost/filesystem.hpp>

#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>
#include <cert/cert_certificate.hpp>
#include <cert/cert_identity.hpp>
#include <cert/cert_evp_pkey.hpp>

/**
* This file tests the behavious of Cert::Certificate, Cert::Identity and Cert::EvpKey
*
*/

TEST_CASE("Certificate") 
{
    SECTION("act like references") 
    {
        X509* x = X509_new();
        Cert::Certificate c1{x};
        // new scope to force a destructor call
        // destoying a copy does not damage the original
        {
            Cert::Certificate c2 = c1;
            CHECK(c1.native() == c2.native());
        }
        auto y = c1.native();
        CHECK(c1.native() == x);
    }
    SECTION("bool operator") 
    {
        Cert::Certificate c;
        bool x = !c;
        REQUIRE(x);
        if (c) {
            REQUIRE(false);
        } else {
            REQUIRE(true);
        }
    }

}

TEST_CASE("Identity") 
{
    SECTION("act like reference") 
    {
        EVP_PKEY* k = EVP_PKEY_new();
        X509* cert = X509_new();
        Cert::Identity id1{cert, k};
        {
            Cert::Identity id2 = id1;
            CHECK(id1.getEVP_PKEY() == id2.getEVP_PKEY() );
            CHECK(id1.getX509() == id2.getX509() );
        }
        CHECK(id1.getEVP_PKEY() == k);
        CHECK(id1.getX509() == cert);
    }
    SECTION("bool operator") 
    {
        Cert::Identity id;
        bool x = !id;
        REQUIRE(x);
        if (id) {
            REQUIRE(false);
        } else {
            REQUIRE(true);
        }
    }
}

TEST_CASE("EvpKey") 
{
    SECTION("act like reference") 
    {
        EVP_PKEY* k = EVP_PKEY_new();
        Cert::EvpPKey pk1{k};
        {
            Cert::EvpPKey pk2 = pk1;
            CHECK(pk1.native() == pk2.native() );
        }
        CHECK(pk1.native() == k);
    }
    SECTION("bool operator") 
    {
        Cert::EvpPKey pk;
        bool x = !pk;
        REQUIRE(x);
        if (pk) {
            REQUIRE(false);
        } else {
            REQUIRE(true);
        }
    }
}

int main( int argc, char* argv[] )
{
    
    // global setup...
    OpenSSL_add_all_algorithms ();
    ERR_load_crypto_strings ();
    ERR_load_BIO_strings();
    ERR_load_ERR_strings();

    char* t_argv[2] = {argv[0], (char*)"*"}; // change the filter to restrict the tests that are executed
    int t_argc = 2;

    int result = Catch::Session().run( t_argc, t_argv );

    // global clean-up...

    return result;
}
