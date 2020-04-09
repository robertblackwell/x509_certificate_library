
#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>
#include <boost/filesystem.hpp>

#include <cert/cert_helpers.hpp>
#include <cert/x509.hpp>

#include "test_fixture_new.hpp"

// info related to the code in this project
//https://zakird.com/2013/10/13/certificate-parsing-with-openssl
//http://fm4dd.com/openssl/add_oids_to_openssl.htm
//http://www.zytrax.com/tech/survival/ssl.html
//https://apidock.com/ruby/v1_9_3_125/OpenSSL/X509/Certificate/extensions%3D
//http://openssl.cs.utah.edu/docs/apps/x509v3_config.html#certificate_policies_
//http://fm4dd.com/openssl/certverify.htm
#if 0
static std::string const_password("blackwellapps");
TEST_CASE("identity","")
{
    X509* cert = X509_new();
    EVP_PKEY* key = EVP_PKEY_new();
    Cert::x509::Identity ident1(key, cert);
    Cert::x509::Identity ident2(std::move(ident1));
    auto f = []() -> Cert::x509::Identity {
        X509* cert = X509_new();
        EVP_PKEY* key = EVP_PKEY_new();
        Cert::x509::Identity ident1(key, cert);
        return ident1;
    };
    Cert::x509::Identity ident3 = f();
}
#endif
#if 0
TEST_CASE("testhelper", "")
{
    TestHelper helper;
    auto sfix = helper.fixturesDirPath();
    boost::filesystem::path fpath(sfix);
    boost::filesystem::path this_file(__FILE__);
    boost::filesystem::path fpath2 = this_file.parent_path().parent_path() / "fixtures";
    CHECK(fpath == fpath2);
    auto s1 = helper.caKeyPath();
    auto s2 = helper.caCertPath();
    auto s3 = helper.certTestDirPath();
    auto s4 = helper.realCertForHostPath("play.google.com");
}
#endif
int main( int argc, char* argv[] ) {
    // global setup...
    OpenSSL_add_all_algorithms ();
    ERR_load_crypto_strings ();
    ERR_load_BIO_strings();
    ERR_load_ERR_strings();

    char* t_argv[2] = {argv[0], (char*)"**"}; // change the filter to restrict the tests that are executed
    int t_argc = 2;
    TestFixtureNew f{};
    std::cout << "YYYYYYYYYYYYYYYYYYYYYYY before fixture setup " << std::endl;
    f.setup();
    std::cout << "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZJust completed Fixture setup" << std::endl;
    int result = Catch::Session().run( t_argc, t_argv );
    std::cout << "Dont panic there should be one error message displayed" << std::endl;
    std::cout << "But provided all 'tests passed' everything is OK" << std::endl;
    // global clean-up...
    return result;
}

