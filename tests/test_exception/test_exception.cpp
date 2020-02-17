#include <boost/filesystem.hpp>
#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>
#include <cert/error.hpp>
#include <cert/cert.hpp>

#include <cert/cert_store.hpp>
#include <cert/cert_authority.hpp>
#include "../test_fixture_new.hpp"

int main( int argc, char* argv[] )
{
    
    // global setup...

    char* t_argv[2] = {argv[0], (char*)"*"}; // change the filter to restrict the tests that are executed
    int t_argc = 2;
    int result = Catch::Session().run( t_argc, t_argv );

    // global clean-up...

    return result;
}

TEST_CASE("exception-x509_trigger")
{
    try {
        X509_TRIGGER_ERROR("this is a message");
    } catch(::Cert::Exception e) {
        std::cout <<"got Cert::Exception msg is: " << std::endl << e.what() << std::endl;
        REQUIRE(true);
        return;
    } catch(std::exception e) {
        std::cout <<"got std::exceptione"<<std::endl;
        REQUIRE(false);
    } catch(...) {
        std::cout <<"got exception with unknown type"<<std::endl;
        REQUIRE(false);
    }
    std::cout <<"got here"<<std::endl;
    REQUIRE(false);
}
void notImplementedFunction() {
    NOT_IMPLEMENTED();
}
TEST_CASE("not implemented")
{
    try {
        notImplementedFunction();
    } catch(::Cert::Exception e) {
        std::cout <<"got Cert::Exception msg is: " << std::endl << e.what() << std::endl;
        REQUIRE(true);
        return;
    } catch(std::exception e) {
        std::cout <<"got std::exceptione"<<std::endl;
        REQUIRE(false);
    } catch(...) {
        std::cout <<"got exception with unknown type"<<std::endl;
        REQUIRE(false);
    }
    std::cout <<"got here"<<std::endl;
    REQUIRE(false);
}

TEST_CASE("throw")
{
    try {
        THROW("this is a message" << 76 << " seventy six");
    } catch(::Cert::Exception e) {
        std::cout <<"got Cert::Exception msg is: " << std::endl << e.what() << std::endl;
        REQUIRE(true);
        return;
    } catch(std::exception e) {
        std::cout <<"got std::exceptione"<<std::endl;
        REQUIRE(false);
    } catch(...) {
        std::cout <<"got exception with unknown type"<<std::endl;
        REQUIRE(false);
    }
    std::cout <<"got here"<<std::endl;
    REQUIRE(false);


}

TEST_CASE("exception-iftrue-throw")
{
    try {
        IFTRUE_THROW((1 == 1), "this is a message");
    } catch(::Cert::Exception e) {
        std::cout <<"got Cert::Exception msg is: " << std::endl << e.what() << std::endl;
        REQUIRE(true);
        return;
    } catch(std::exception e) {
        std::cout <<"got std::exceptione"<<std::endl;
        REQUIRE(false);
    } catch(...) {
        std::cout <<"got exception with unknown type"<<std::endl;
        REQUIRE(false);
    }
    std::cout <<"got here"<<std::endl;
    REQUIRE(false);
}
TEST_CASE("exception-iftrue-no-throw")
{

    try {
        IFTRUE_THROW((1 == 2), "this is a message");
    } catch(::Cert::Exception e) {
        std::cout <<"got Cert::Exception msg is: " << std::endl << e.what() << std::endl;
        REQUIRE(false);
        return;
    } catch(std::exception e) {
        std::cout <<"got std::exceptione"<<std::endl;
        REQUIRE(false);
    } catch(...) {
        std::cout <<"got exception with unknown type"<<std::endl;
        REQUIRE(false);
    }
    std::cout <<"got here"<<std::endl;
    REQUIRE(true);
}
TEST_CASE("exception-iffalse-throw")
{
    try {
        IFFALSE_THROW((1 == 2), "this is a message");
    } catch(::Cert::Exception e) {
        std::cout <<"got Cert::Exception msg is: " << std::endl << e.what() << std::endl;
        REQUIRE(true);
        return;
    } catch(std::exception e) {
        std::cout <<"got std::exceptione"<<std::endl;
        REQUIRE(false);
    } catch(...) {
        std::cout <<"got exception with unknown type"<<std::endl;
        REQUIRE(false);
    }
    std::cout <<"got here"<<std::endl;
    REQUIRE(false);
}
TEST_CASE("exception-iffalse-no-throw")
{
    try {
        IFFALSE_THROW((1 != 2), "this is a message");
    } catch(::Cert::Exception e) {
        std::cout <<"got Cert::Exception msg is: " << std::endl << e.what() << std::endl;
        REQUIRE(false);
        return;
    } catch(std::exception e) {
        std::cout <<"got std::exceptione"<<std::endl;
        REQUIRE(false);
    } catch(...) {
        std::cout <<"got exception with unknown type"<<std::endl;
        REQUIRE(false);
    }
    std::cout <<"got here"<<std::endl;
    REQUIRE(true);
}
