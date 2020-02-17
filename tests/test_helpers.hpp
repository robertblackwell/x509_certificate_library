//
//  test_helpers.hpp
//  x509
//
//  Created by ROBERT BLACKWELL on 11/8/17.
//  Copyright © 2017 ROBERT BLACKWELL. All rights reserved.
//

#ifndef test_helpers_hpp
#define test_helpers_hpp

#include <cstdlib>
#include <iostream>
#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>
#include <json/json.hpp>
#include <cert/constants.hpp>
/**
* @brief This class provides convenience properties for accessing the names/paths
* of files and within the fixtures directory and other constants needed for running the test suite.
*
* It is really a config object for the various test executables
*
* It only returns names of various resources - it does not need any of the resources to actually exist
*/
class TestHelper
{
    private:
        std::string m_ca_dir;
        boost::filesystem::path m_this_file;
        boost::filesystem::path m_this_directory;
        boost::filesystem::path m_test_directory;
        boost::filesystem::path m_ca_config_file_path;
        boost::filesystem::path m_project_root;
        boost::filesystem::path m_fixtures;
        boost::filesystem::path m_ca_root;
    public:
    /**
    * create a default helper object which expects the fixture root to be ${project_dir}/tests/fixture.
    *
    * The exact path is determined by assuming that this file is in ${project_dir}/tests
    */
    TestHelper()
        : m_ca_dir("CA"),
        m_this_file(boost::filesystem::canonical(__FILE__)),
        m_this_directory(m_this_file.parent_path()),
        m_test_directory(m_this_file.parent_path()),
        m_project_root(m_test_directory.parent_path())   // project root is one level up
//        m_fixtures(m_test_directory / "fixtures" ),       // fixture folder is a subfoler of this files folder
//        m_fixtures(m_test_directory / TestConstants::TESTDATA_DIR_NAME()),
//        m_ca_config_file_path(m_fixtures / "ca_config.json"),
//        m_ca_root(m_fixtures / m_ca_dir)
    {
        m_fixtures = m_test_directory / "fixtures";
        m_ca_config_file_path = m_fixtures / "ca_config.json";
        m_ca_root = m_fixtures / m_ca_dir;
    //    std::cout << "hi" << std::endl;
    }
    /**
    * Create a helper object with the fixture root at an arbitary location.
    */
    TestHelper(boost::filesystem::path test_data_dir_path, std::string store_name = "CA")
        : m_ca_dir(store_name),
        m_this_file(boost::filesystem::canonical(__FILE__)),
        m_this_directory(m_this_file.parent_path()),
        m_test_directory(m_this_file.parent_path()),
        m_project_root(m_this_directory.parent_path())   // project root is one level up
//        m_fixtures(m_test_directory / "fixtures" ),       // fixture folder is a subfoler of this files folder
//        m_fixtures(test_data_dir_path),
//        m_ca_config_file_path(test_data_dir_path / "ca_config.json"),
//        m_ca_root(m_fixtures / m_ca_dir)
    {
        m_fixtures = test_data_dir_path;
        m_ca_config_file_path = m_fixtures / "ca_config.json";
        m_ca_root = m_fixtures / m_ca_dir;
//        assert(false);
    //    std::cout << "hi" << std::endl;
    }
    std::string defaultCertBundlePath()
    {
        return CERTLIB_DEFAULT_CERT_FILE_PATH;
    }
    /**
    * Details of the custom CA generated for testing
    */
    nlohmann::json caConfig()
    {
 
//        std::map<std::string, std::string> cfg = {
        nlohmann::json cfg = {
            {"ca_name" , "A_CA_Fo_Testing_libcert"},
            {"ca_state" , "WA"},
            {"ca_country" , "AU"},
            {"ca_organization" , "the_dev_guys_at_testlibcert"},

            {"ca_email" , "someone@testing_libcert.com"},
            /// these password should all be the same
            {"passin" , "a_password_for_testing"},
            {"passout" , "a_password_for_testing"},
            {"ca_key_password" , "a_password_for_testing"}
        };
        return cfg;
    }
    /**
    * returns the path of a directory where copies of pre-existing test data is kept.
    * That is test data that was constructed during development and does not need to be
    * created by test_data_init but only copied into the relevant place in the "fixture"
    * directory
    */
    std::string preExistingTestDataDir()
    {
        return (m_test_directory / "preexisting_test_data").native();
    }
    std::string preExistingTestFile(std::string filename)
    {
        return (m_test_directory / "preexisting_test_data" / filename).native();
    }
    /**
    * Returns path to the fixtures directory
    */
    std::string fixture_path()
    {
        return m_fixtures.native();
    }
    /**
    * Returns path to the fixtures directory
    */
    std::string fixturesDirPath()
    {
        return m_fixtures.native();
    }
    /**
    * Returns path to files directly under the fixtures directory
    */
    std::string fixturesFilePath(std::string fileName)
    {
        return (m_fixtures / fileName).native();
    }

    /**
    * Returns path to the test ca config file
    */
    std::string caConfigFilePath()
    {
        return m_ca_config_file_path.string();
    }
    /**
    * Returns path to the root of the certificate store under neath the fixtures dir
    */
    std::string certStoreRoot()
    {
        auto temp = m_fixtures / "CA";
        return temp.string();
    }
    /**
    * Returns path to the tests directory
    */
    std::string certTestDirPath()
    {
        return (m_test_directory).native();
    }
    std::string reqTestDirPath()
    {
        return ( m_project_root / "req_test").native();
    }
    /**
    * Returns path to the test CA directory - typically tests/fixtures/CA/private
    */
    std::string caPrivateDirPath()
    {
        return ( m_ca_root / "private" ).native();
    }
    /**
    * Returns path to the test CA directory - typically tests/fixtures/CA/private
    */
    std::string caKeyPassword()
    {
        assert(false);
        return "blackwellapps";
    }
    /**
    * Returns path to the test CA provate key file - typically tests/fixtures/CA/private/cakey.pem
    */
    std::string caKeyPath()
    {
        return ( m_ca_root / "private" / "cakey.pem").native();
    }
    /**
    * Returns path to the test CA provate key file - typically tests/fixtures/CA/private/cacert.pem
    */
    std::string caCertPath()
    {
        return (m_ca_root / "private" / "cacert.pem").native();
    }
    /**
    * Returns path to the project root
    */
    std::string projectRoot()
    {
        return m_project_root.native();
    }
    /**
    * returns the file path of the file holding real/original certificate for a specific host
    */
    std::string realCertForHostPath(std::string host)
    {
        return (m_ca_root / "hosts" / host / "real_certificate.pem").native();
    }
    /**
    * returns the file path of the file holding real/original certificate chain for a specific host
    */
    std::string realCertChainForHostPath(std::string host)
    {
        return (m_ca_root / "hosts" / host / "real_certificate_chain.pem").native();
    }
    /**
    * returns the file path of the file holding forged/intercepting certificate for a specific host
    */
    std::string interceptCertForHostPath(std::string host)
    {
        return (m_ca_root / "hosts" / host / "certificate.pem").native();
    }
    
    std::string rootCertStore()
    {
        return (m_ca_root / "root_certs" / "combined-cacert.pem").native();
    }
    /**
    * Returns path to the file containing the active root cert bundle
    */
    std::string rootActive()
    {
        return (m_ca_root  / "root_certs" / "active_roots.pem").native();
    }

    /**
    * Returns path to the file containing the root cert bundle formed by combining
    * the exported from the osx keychain with our local CA
    */
    std::string rootCertStoreOsxCombined()
    {
        return (m_ca_root  / "root_certs" / "osx_ext.pem").native();
    }
    /**
    * Returns path to the file containing the root cert bundle formed by combining
    * the download from mozilla with our local CA
    */
    std::string rootCertStoreMozCombined()
    {
        return (m_ca_root  / "root_certs" / "mozilla_ext.pem").native();
    }
    /**
    * Returns path to the file containing the root cert bundle exported from the osx keychain
    */
    std::string rootCertStoreOsx()
    {
        return (m_ca_root  / "root_certs" / "osx.pem").native();
    }
    /**
    * Returns path to the file containing the downloaded mozilla  root cert bundle
    */
    std::string rootCertStoreMoz()
    {
        return (m_ca_root  / "root_certs" / "mozilla.pem").native();
    }

    std::string ssltestCert()
    {
        return (m_ca_root  / "sites" / "ssltest" / "ssltest.crt.pem").native();
    }
    std::string withWithoutDirPath()
    {
        return (m_fixtures / "with_without").native();
    }
    std::string withWithoutCertRootStore(std::string with_without)
    {
        return (m_fixtures / "with_without" / (with_without + ".pem") ).native();
    }
    std::vector<std::string> initialHosts()
    {
        return {
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
    }
    std::string hostForWithWithoutTests()
    {
        return "bankofamerica.com"; // has multiple certs in its chain
    }
    std::string hostForBundleTests()
    {
        return "badssl.com"; // requires SNI done correctly
    }
    std::string hostForForgeTest()
    {
        return "badssl.com"; // requires SNI done correctly
    }
    std::string hostForBuildTest()
    {
        return "badssl.com"; // requires SNI done correctly
    }
    std::vector<std::string> badssl_SubDomians()
    {
        return {};
    }
    std::string testHostA()
    {
        return (m_fixtures / "host_a").native();
    }
    std::string testHostB()
    {
        return (m_fixtures / "host_b").native();
    }

};
#endif /* test_helpers_hpp */
