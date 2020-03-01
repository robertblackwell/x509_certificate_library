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

TEST_CASE("Certificate") {
    SECTION("act like references") {

    }
    SECTION("bool operator") {
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

TEST_CASE("Identity") {
    SECTION("act like reference") {

    }
    SECTION("bool operator") {
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

TEST_CASE("EvpKey") {
    SECTION("act like reference") {

    }
    SECTION("bool operator") {
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
