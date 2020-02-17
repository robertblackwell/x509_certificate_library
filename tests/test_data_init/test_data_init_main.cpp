#include <iostream>
#include <map>
#include <boost/filesystem.hpp>

#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include <cert/cert.hpp>
#include "test_helpers.hpp"
#include "test_fixtures.hpp"
void initTestData();
/**
* This is an executable that should be run to refresh the test data in the test/fixtures directory
*/
class TestDummyClass {

};
TEST_CASE_METHOD(TestDummyClass,  "dummy", "dummy")
{
    int a = 23;
    int b = 20;
    b = b + 3;
    CHECK(a == b); // this is to force catch2 output from this run
}
int main( int argc, char* argv[] )
{
    
    // global setup...
    OpenSSL_add_all_algorithms ();
    ERR_load_crypto_strings ();
    ERR_load_BIO_strings();
    ERR_load_ERR_strings();
    initTestData();

    char* t_argv[2] = {argv[0], (char*)"*"}; // change the filter to restrict the tests that are executed
    int t_argc = 2;
    int result = Catch::Session().run( t_argc, t_argv );

    std::cout << "A NECESSARY CHANGE" << std::endl;
    // global clean-up...

    return result;
}
