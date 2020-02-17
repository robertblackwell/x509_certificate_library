#include <boost/filesystem.hpp>
#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include "cert_helpers_fs.hpp"
#include "cert_store.hpp"
#include "cert_store_authority.hpp"
#include "cert_store_host.hpp"

int main( int argc, char* argv[] )
{
    
    // global setup...

    char* t_argv[2] = {argv[0], (char*)"server*"}; // change the filter to restrict the tests that are executed
    int t_argc = 2;
    int result = Catch::Session().run( t_argc, t_argv );

    // global clean-up...

    return result;
}


TEST_CASE("server", "")
{
    SECTION("get_cert")
    {
    }
}
