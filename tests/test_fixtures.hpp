#ifndef x509_test_handshake_fixtures_hpp
#define x509_test_handshake_fixtures_hpp
#include <cstdlib>
#include <iostream>
#include <set>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/unordered_set.hpp>
#include <boost/filesystem.hpp>

#include <cert/cert/cert.hpp>
#include <cert/cert_store.hpp>
//#include "cert_helpers.hpp"
//#include "cert_handshake_result.hpp"
//#include "cert_handshaker.hpp"
//#include "test_case.hpp"
#include "test_helpers.hpp"

/// @todo something wqrong with the export of OSX keychain
//#define TEST_OSX_KEYCHAIN

inline void test_file_exists(std::string fp)
{
    boost::filesystem::path p(fp);
    if( ! Cert::Helpers::fs::is_regular_file(p) ) {
        throw std::runtime_error(" file " + fp + " does not exist");
    }
}
/**
* @brief A class that is a "test fixture" in the sense of Catch2 - a class that is derived from
* to make a TEST_CASE_METHOD. This one is common across all tests and really only provides location information
* about data in the "fixtures" or "test data" directory under ....tests.
* NOTE - it tests for the existence of the resource files associated with testing
* and hence should not be instanciated unless all resources have previously been
* put in place, with for example, test_data_init
*
*/
class TestFixture
{
    public:
        std::string fixture_root;
        std::string ca_cert_path;
        std::string ca_key_path;
        std::string ca_key_password;
        std::string non_default_1;
        std::string moz_only;
        std::string moz_with_ca;
        std::string osx_only;
        std::string osx_with_ca;
        std::string wwo_with;
        std::string wwo_without;
        std::string store_root_path;
        std::string ca_json_config_path;
        std::string host_for_handshake;
        Cert::Store::StoreSPtr store;
        std::string host_for_wwo_test;
        std::string host_for_bundle_test;
        std::string host_for_forge_test;
        
        std::vector<std::string> initial_hosts;
        TestHelper helper;
    
        void init()
        {
            non_default_1 = "/usr/local/ssl/cert.pem";
            non_default_1 = "/usr/local/etc/openssl@1.1/cert.pem";
            host_for_handshake = helper.hostForForgeTest();
            host_for_wwo_test = helper.hostForWithWithoutTests();
            host_for_bundle_test = helper.hostForBundleTests();
            host_for_forge_test = helper.hostForForgeTest();
            
            ca_cert_path = helper.caCertPath();
            ca_key_path = helper.caKeyPath();
            ca_json_config_path = helper.caConfigFilePath();
            
            store_root_path = helper.certStoreRoot();
            
            moz_only = helper.rootCertStoreMoz();
            moz_with_ca = helper.rootCertStoreMozCombined();

            osx_only = helper.rootCertStoreOsx();
            osx_with_ca = helper.rootCertStoreOsxCombined();
            wwo_with = helper.withWithoutCertRootStore("with");
            wwo_without = helper.withWithoutCertRootStore("without");
            auto df = Cert::Helpers::replace_openssl_get_default_cert_file();
            if (!boost::filesystem::exists(df)) {
                throw std::string(__func__) + std::string(" openssl default cert file does not exist ") + std::string(df);
            }

            initial_hosts = {
                "bankofamerica.com",
                "paypal.com",
                "www.google.com",
                "www.httpsnow.org",
                "yahoo.com",
                "www.wellsfargo.com",
                "www.digicert.com",
                "badssl.com",
                "www.godaddy.com"
            };
            
            test_file_exists(non_default_1);
            test_file_exists(moz_only);
            test_file_exists(osx_only);
            test_file_exists(osx_with_ca);
            test_file_exists(wwo_with);
            test_file_exists(wwo_without);
            test_file_exists(helper.realCertForHostPath("host_a"));
            test_file_exists(helper.realCertForHostPath("host_b"));

            store = Cert::Store::Store::load(store_root_path);
        }
        /**
        * create a fixture object with an aribitary root
        */
        TestFixture(boost::filesystem::path root_path) : helper(root_path.string())
        {
            fixture_root = helper.fixture_path();
            init();
        }
        /**
        * construct a fixture object where the root location is ${project_dir}/tests/fixture
        */
        TestFixture() : helper()
        {
            init();
        }

};

#endif

