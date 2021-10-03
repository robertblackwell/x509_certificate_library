
// dummy .cpp just to force cmake to see this lib as a target

// #include <stdio.h>
// #include <boost/filesystem.hpp>
// #include <boost/format.hpp>
// #include <iostream>
// #include <map>
// #include <sstream>

// #include <cert/cert.hpp>
// #include <cert/cert_chain.hpp>
// #include <cert/cert_store.hpp>

#include "test_fixture_new.hpp"

using namespace boost::filesystem;
using namespace Cert;
using namespace Cert::x509;
using namespace Cert::Helpers;
using namespace Cert::Store;
// changed in test_x509
static std::string without_header = R"HDR(
##
## This file contains roots certificates from Mozilla
##
## EXCEPT THAT the certificates for
##
## %1%
##
## has been removed
## diff against the one called with.pem to find out what is missng
##
)HDR";
static std::string with_header    = R"HDR(
##
## This file contains roots certificates from Mozilla
##
)HDR";


/**
* @brief A class that is a "test fixture" in the sense of Catch2 - a class that is derived from
* to make a TEST_CASE_METHOD. This one is common across all tests and really only provides location information
* about data in the "fixtures" or "test data" directory under ....tests.
* NOTE - it tests for the existence of the resource files associated with testing
* and hence should not be instanciated unless all resources have previously been
* put in place, with for example, test_data_init
*
*/
TestFixtureNew::TestFixtureNew() {
    m_ca_dir_basename  = "CA";
    m_this_file_path   = boost::filesystem::canonical(__FILE__);
    m_this_dir_path    = m_this_file_path.parent_path();
    m_test_dir_path    = m_this_file_path.parent_path();
    m_project_dir_path = m_test_dir_path.parent_path();
    m_fixture_dir_path = m_test_dir_path / "fixture";

    m_hosts_for_handshake = {
        "bankofamerica.com",
        "paypal.com",
        "www.google.com",
        "www.httpsnow.org",
        "yahoo.com",
        "www.wellsfargo.com",
        "www.digicert.com",
        "badssl.com",
        "www.godaddy.com"};

    m_host_for_wwo_test    = "bankofamerica.com";  // has multiple certs in its chain
    m_host_for_bundle_test = "badssl.com";
    m_host_for_forge_test  = "badssl.com";
}
// std::string             m_ca_dir_basename;
// boost::filesystem::path m_this_file_path;
// boost::filesystem::path m_this_dir_path;
// boost::filesystem::path m_test_dir_path;
// boost::filesystem::path m_project_dir_path;
// boost::filesystem::path m_fixture_dir_path;

// std::vector<std::string> m_hosts_for_handshake;
// Cert::Store::StoreSPtr   m_store_sptr;
// Cert::Store::LocatorSPtr m_locator_sptr;
// Cert::AuthoritySPtr      m_authority_sptr;
// std::string              m_host_for_wwo_test;
// std::string              m_host_for_bundle_test;
// std::string              m_host_for_forge_test;

path TestFixtureNew::projectDirPath() {
    return m_project_dir_path;
}
path TestFixtureNew::testsDirPath() {
    return (m_test_dir_path);
}
path TestFixtureNew::preExistingTestDataDir() {
    return (testsDirPath() / "preexisting_test_data");
}
path TestFixtureNew::preExistingTestFilePath(std::string filename) {
    return (testsDirPath() / "preexisting_test_data" / filename);
}

path TestFixtureNew::TestFixtureNew::preExistingCaConfigFilePath() {
    return preExistingTestFilePath("ca_config.json");
}

path TestFixtureNew::preExistingHostADirPath() {
    return preExistingTestFilePath("host_a");
}

path TestFixtureNew::preExistingHostARealCertFilePath() {
    return (preExistingHostADirPath() / "real_certificate.pem");
}

path TestFixtureNew::preExistingHostBDirPath() {
    return preExistingTestFilePath("host_b");
}

path TestFixtureNew::preExistingHostBRealCertFilePath() {
    return (preExistingHostBDirPath() / "real_certificate.pem");
}

path TestFixtureNew::fixtureDirPath() {
    return (testsDirPath() / "fixture");
}

path TestFixtureNew::fixturesFilePath(std::string fileName) {
    return (fixtureDirPath() / fileName);
}
path TestFixtureNew::nonDefaultRootCertificateBundleFilePath() {
//        return "/usr/local/ssl/cert.pem";
    return activeRootCertificateBundleFilePath();
}

path TestFixtureNew::storeRootDirPath() {
    return (fixtureDirPath() / m_ca_dir_basename);
}

path TestFixtureNew::caPrivateDirPath() {
    return (storeRootDirPath() / "private");
}

path TestFixtureNew::caSaveDirPath() {
    return caPrivateDirPath();
}

path TestFixtureNew::caConfigFilePath() {
    return (fixtureDirPath() / "ca_config.json");
}

path TestFixtureNew::certStoreRoot() {
    return storeRootDirPath();
}

path TestFixtureNew::reqTestDirPath() {
    return (projectDirPath() / "req_test");
}

std::string TestFixtureNew::caKeyPassword() {
    assert(false);
    return "blackwellapps";
}

path TestFixtureNew::caPrivateKeyFilePath() {
    assert(false);
    return (caPrivateDirPath() / "cakey.pem");
}

path TestFixtureNew::caCertPath() {
    assert(false);
    return (caPrivateDirPath() / "cacert.pem");
}

path TestFixtureNew::hostsDirPath() {
    return (storeRootDirPath() / "hosts");
}

path TestFixtureNew::hostCertificateDirPath(std::string host) {
    return (hostsDirPath() / host);
}

path TestFixtureNew::realCertFilePathForHost(std::string host) {
    return (hostCertificateDirPath(host) / "real_certificate.pem");
}

path TestFixtureNew::realCertChainFilePathForHost(std::string host) {
    return (hostCertificateDirPath(host) / "real_certificate_chain.pem");
}

path TestFixtureNew::interceptCertForHostPath(std::string host) {
    return (hostCertificateDirPath(host) / "certificate.pem");
}

path TestFixtureNew::rootCertificateBundleDirPath() {
    return (storeRootDirPath() / "root_certs");
}

path TestFixtureNew::combinedRootCertificateBundleFilePath() {
    return (rootCertificateBundleDirPath() / "combined-cacert.pem");
}

path TestFixtureNew::activeRootCertificateBundleFilePath() {
    return (rootCertificateBundleDirPath() / "active_roots.pem");
}

path TestFixtureNew::osxCombinedRootCertificateBundleFilePath() {
    return (rootCertificateBundleDirPath() / "osx_ext.pem");
}

path TestFixtureNew::mozCombinedRootCertificateBundleFilePath() {
    return (rootCertificateBundleDirPath() / "mozilla_ext.pem");
}

path TestFixtureNew::osxRootCertificateBundleFilePath() {
    return (rootCertificateBundleDirPath() / "osx.pem");
}

path TestFixtureNew::mozRootCertificateBundleFilePath() {
    return (rootCertificateBundleDirPath() / "mozilla.pem");
}

path TestFixtureNew::ssltestCertificateFilePath() {
    return (storeRootDirPath() / "sites" / "ssltest" / "ssltest.crt.pem");
}

path TestFixtureNew::withWithoutDirPath() {
    return (fixtureDirPath() / "with_without");
}

path TestFixtureNew::withWithoutRootCertificateBundleFilePath(std::string with_without) {
    return (withWithoutDirPath() / (with_without + ".pem"));
}

std::vector<std::string> TestFixtureNew::initialHosts() {
    return m_hosts_for_handshake;
}

std::string TestFixtureNew::hostForWithWithoutTests() {
    return "bankofamerica.com";  // has multiple certs in its chain
}

std::string TestFixtureNew::hostForBundleTests() {
    return "badssl.com";  // requires SNI done correctly
}

std::string TestFixtureNew::hostForForgeTest() {
    return "badssl.com";  // requires SNI done correctly
}

std::string TestFixtureNew::hostForBuildTest() {
    return "badssl.com";  // requires SNI done correctly
}

std::string TestFixtureNew::hostForWWWGeekTest() {
    return "www.geeksforgeeks.org";  // requires SNI done correctly
}

std::string TestFixtureNew::hostForGeekTest() {
    return "geeksforgeeks.org";  // requires SNI done correctly
}

std::vector<std::string> TestFixtureNew::badssl_SubDomians() {
    return {};
}

path TestFixtureNew::testHostADirPath() {
    return (hostCertificateDirPath("host_a"));
}

path TestFixtureNew::testHostBDirPath() {
    return (hostCertificateDirPath("host_b"));
}
void TestFixtureNew::assignPaths() {
    m_ca_dir_basename  = "CA";
    m_this_file_path   = boost::filesystem::canonical(__FILE__);
    m_this_dir_path    = m_this_file_path.parent_path();
    m_test_dir_path    = m_this_file_path.parent_path();
    m_project_dir_path = m_test_dir_path.parent_path();
    m_fixture_dir_path = m_test_dir_path / "fixture";

    m_hosts_for_handshake = {
        "www.geeksforgeeks.org",
        "geeksforgeeks.org",
        "bankofamerica.com",
        "paypal.com",
        "www.google.com",
        "www.httpsnow.org",
        "yahoo.com",
        "www.wellsfargo.com",
        "www.digicert.com",
        "badssl.com",
        "www.godaddy.com"};

    m_host_for_wwo_test    = "bankofamerica.com";  // has multiple certs in its chain
    m_host_for_bundle_test = "badssl.com";
    m_host_for_forge_test  = "badssl.com";
    m_geek_for_test        = "geeksforgeeks.org";
    m_www_geeks_for_test    = "www.geeksforgeeks.org";

}
void TestFixtureNew::clean() {
    /// clean out the fixtureCert Store pointed at by the test fixture
    /// are we building the "fixture" directory in a dummy place for testing this
    /// function. Or are we building it in the real locations
    /// use the default root for the fixture
    path fixture_root = m_fixture_dir_path;  // h.fixture_path();
    path store_root   = storeRootDirPath();  //path(h.certStoreRoot());
    path caSaveDir    = caPrivateDirPath();
    /// now clean out the "fixture" directory (or its proxy) in prep
    /// for building/copying in all the test data
    remove_all(fixtureDirPath());
    create_directories(fixtureDirPath());
}
void TestFixtureNew::createNewCAAndStore() {
    /**
            * Initialize the fixtures dir with a store that has a new CA derived from
            * config data in tests/preexisting_test_data/test_config.json file
     */
    boost::filesystem::path config_from = preExistingCaConfigFilePath();
    boost::filesystem::path config_to   = caConfigFilePath();
    copy_file(config_from, config_to);

    m_store_sptr     = Cert::Store::Store::makeWithCA(storeRootDirPath(), config_to);
    m_locator_sptr   = m_store_sptr->getLocator();
    m_authority_sptr = m_store_sptr->getAuthority();
}
void TestFixtureNew::copyExistingCAAndStore() {
    /**
            * Initialize the fixtures dir with the already existing CA data .. only
            * for when testing on my private development machine
     */
#if 0
// TODO - need to fix this
    m_store_sptr = Cert::Store::Store::makeEmpty(store_root);
    m_locator_sptr = m_store_sptr->m_locator_sptr;
    // now copy the ca into the test fixture cet store
    copy_file(original_ca_dir_path / "private" / "cakey.pem", m_locator_sptr->ca_key_pem_path);
    copy_file(original_ca_dir_path / "private" / "cacert.pem", m_locator_sptr->ca_cert_pem_file_path);
    copy_file(original_ca_dir_path / "private" / "ca.p12", m_locator_sptr->ca_pk12_file_path);
    copy_file(original_ca_dir_path / "private" / "caroot.cnf", m_locator_sptr->ca_cnf_file_path);
    copy_file(original_ca_dir_path / "config.json", m_locator_sptr->config_file_path );
#endif
}
void TestFixtureNew::getAndSaveCertsForTestHosts() {
    std::vector<std::string> hosts = m_hosts_for_handshake;
    for (const std::string& h : hosts) {
        Host::create(*m_store_sptr, h);
    }
}
void TestFixtureNew::setupDataForHostAHostBTest()
{
    /// copy over predefined test data for two hosts that will be used
    /// to test certificate verification failure
    /// nned to think about how this works if the two candidate hosts
    /// have changed their certificates since I last setup this test data
    boost::filesystem::create_directories(hostCertificateDirPath("host_a"));
    copy_file(
        preExistingHostARealCertFilePath(),
        realCertFilePathForHost("host_a"));
    boost::filesystem::create_directories(hostCertificateDirPath("host_b"));
    copy_file(
        preExistingHostBRealCertFilePath(),
        realCertFilePathForHost("host_b"));
    assert(filesystem::is_directory(testHostADirPath()));
    assert(filesystem::is_directory(testHostBDirPath()));
}
void TestFixtureNew::setupDataForWithWithoutTest()
{
    /// HACK - this is a kack as it relies on inside knowledge of
    /// the issuer of the wwo_host and will not update if the wwo_host changes certificate
    create_directories(withWithoutDirPath());
    ///
    /// slightly reformat and then copy the mozilla bundle to the withwithout/with.pem - file
    ///
    Cert::Chain moz_chain(m_locator_sptr->mozilla_root_certs);
    moz_chain.writePEM(withWithoutRootCertificateBundleFilePath("with"));
    ///
    /// Now create the withwithout/without.pem bundle
    /// by filtering out of the "with" bundle the root certificates from
    /// the mozilla bundle that is the issuer of the final certificate
    /// in the certificate chain of the helper.withWithoutHost().
    /// Thus the helper.withWithoutHost() should FAIL to verify
    /// agsin the without.pem bundle
    ///
    std::string wwohost = m_host_for_wwo_test;
    Cert::Chain hostchain(m_locator_sptr->hostRealCertificateChainPath(wwohost));
    // auto        c1               = hostchain.toPEMString();
    std::string issuer_to_remove = hostchain.lastIssuer();
    std::string wwoh_header_text = str(boost::format(without_header) % issuer_to_remove);
    // NOTE: this is a hack. Based on knowledge that the root cert for bankofamerica
    // is issued by Entrust
    auto new_bundle = moz_chain.removeAllSubjectsMatching(".*Entrust.*");
    new_bundle.writeAnnotated(withWithoutRootCertificateBundleFilePath("without"), wwoh_header_text);
    assert(filesystem::is_regular(withWithoutRootCertificateBundleFilePath("with")));
    assert(filesystem::is_regular(withWithoutRootCertificateBundleFilePath("without")));
}
/**
* This function builds or refreshes the tests/fixtures directory in preparartion for
* running the test suite. Values used in the building of fixtures are taken from
* a file ${project_dir}/tests/test_config.json
*
* In order to test this function it is possible to have this function build the "fixtures"
* directory in a different place with a diffeerent name.
*/
void TestFixtureNew::setup() {
    std::cout << __func__ << " entered\n";
    assignPaths();
    clean();
    createNewCAAndStore();
    m_store_sptr->rootCertsFromMozilla();  // download Mozilla root certificate bundle
    m_store_sptr->rootCertsMozillaActive();// make the mozilla bundle the active bundle
    getAndSaveCertsForTestHosts();         // get the real certificate for each of the test hosts and store in CertStore
                                           // will verify each host certificate against the active certificate bundle
    setupDataForHostAHostBTest();
    setupDataForWithWithoutTest();
    std::cout << __func__ << " exit\n";
}
void TestFixtureNew::loadExisting()
{
    std::cout << __func__ << " entered" << "\n";
    auto x = storeRootDirPath();
    m_store_sptr     = Cert::Store::Store::load(storeRootDirPath());
    m_locator_sptr   = m_store_sptr->getLocator();
    m_authority_sptr = m_store_sptr->getAuthority();
}
