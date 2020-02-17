#include <iostream>
#include <map>
#include <boost/filesystem.hpp>

#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include <cert/cert.hpp>
#include "test_helpers.hpp"
#include "test_fixture_new.hpp"


int main( int argc, char* argv[] )
{
    
    // global setup...
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

