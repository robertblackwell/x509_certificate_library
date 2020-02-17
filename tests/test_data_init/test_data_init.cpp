#include <iostream>
#include <map>
#include <sstream>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <catch2/catch.hpp>

#include <cert/cert.hpp>
#include <cert/cert_store.hpp>
#include <cert/cert_chain.hpp>

#include "test_helpers.hpp"
#include "test_fixtures.hpp"

using namespace boost::filesystem;
using namespace Cert;
using namespace Cert::x509;
using namespace Cert::Helpers;
using namespace Cert::Store;

namespace {
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
static std::string with_header = R"HDR(
##
## This file contains roots certificates from Mozilla
##
)HDR";

} // anonymous namespace

/**
* This function builds or refreshes the tests/fixtures directory in preparartion for
* running the test suite. Values used in the building of fixtures are taken from
* a file ${project_dir}/tests/test_config.json
*
* In order to test this function it is possible to have this function build the "fixtures"
* directory in a different place with a diffeerent name.
*/
void initTestData()
{
    typedef std::shared_ptr<TestFixture> TestFixtureSPtr;
    TestFixtureSPtr fixture_sptr;
    
    path fixture_root;
    path store_root;
    path caSaveDir;
    /// get the path of the dir holding this file
    path this_dir = path(canonical(__FILE__)).parent_path();
    
    /// path to a dir holding the original ca
    path original_ca_dir_path = this_dir / "original_ca";
  
    /// clean out the fixtureCert Store pointed at by the test fixture
    /// are we building the "fixture" directory in a dummy place for testing this
    /// function. Or are we building it in the real locations
    bool use_dummy_fixture = false;
    if(use_dummy_fixture) {
        /// use a dummp root for the fixture
        fixture_root = this_dir / "xfix";
        store_root = this_dir / "xfix" / "CA" ;

    } else{
        /// use the default root for the fixture
        TestHelper h;
        fixture_root = h.fixture_path();
        store_root = path(h.certStoreRoot());
        caSaveDir = path(h.caPrivateDirPath());
//        fixture_sptr = std::make_shared<TestFixture>();
//        path store_root = fixture_sptr->store_root_path;

    }
    /// now clean out the "fixture" directory (or its proxy) in prep
    /// for building/copying in all the test data
    remove_all(fixture_root);
    create_directories(fixture_root);
//    create_directories(caSaveDir);
    
    StoreSPtr store_sptr;
    LocatorSPtr locator_sptr;
    ::Cert::AuthoritySPtr authSPtr;
    
    /// are we building the fixture directory with a new CA whose details come from
    /// preexisting_test_data/ca_spec.json. Or are we copying in a CA already built.
    ///
    /// The default and correct is new CA - the option will be removed before release
    ///
    if( true) {
        /**
        * Initialize the fixtures dir with a store that has a new CA derived from
        * config data in tests/preexisting_test_data/test_config.json.
        */
        TestHelper h;
        boost::filesystem::path config_from =  h.preExistingTestFile("ca_config.json");
        boost::filesystem::path config_to = h.caConfigFilePath();
        copy_file(config_from, config_to);
        // TODO: lets do this without Store objects

//        authSPtr = Cert::Authority::create(caSaveDir, h.caConfigFilePath());
        store_sptr = Cert::Store::Store::makeWithCA(store_root, h.caConfigFilePath());
        locator_sptr = store_sptr->m_locator_sptr;
        authSPtr = store_sptr->getAuthority();
    } else {
        /**
        * Initialize the fixtures dir with the already existing CA data .. only
        * for when testing on my private development machine
        */
        store_sptr = Cert::Store::Store::makeEmpty(store_root);
        locator_sptr = store_sptr->m_locator_sptr;
        // now copy the ca into the test fixture cet store
        copy_file(original_ca_dir_path / "private" / "cakey.pem", locator_sptr->ca_key_pem_path);
        copy_file(original_ca_dir_path / "private" / "cacert.pem", locator_sptr->ca_cert_pem_file_path);
        copy_file(original_ca_dir_path / "private" / "ca.p12", locator_sptr->ca_pk12_file_path);
        copy_file(original_ca_dir_path / "private" / "caroot.cnf", locator_sptr->ca_cnf_file_path);
        copy_file(original_ca_dir_path / "config.json", locator_sptr->config_file_path );
    }
    TestHelper helper(fixture_root);
    /// now set up the various bundles of root certificates
    // TODO: lets do this without Store object
    store_sptr->rootCertsFromMozilla();
    store_sptr->rootCertsFromKeychain();

    store_sptr->rootCertsMozillaActive();
    /// copy over predefined test data

    Host::createFolder(*store_sptr, "host_a");
    copy_file(
        helper.preExistingTestFile("host_a/real_certificate.pem"),
        helper.realCertForHostPath("host_a")
    );
    Host::createFolder(*store_sptr, "host_b");
    copy_file(
        helper.preExistingTestFile("host_b/real_certificate.pem"),
        helper.realCertForHostPath("host_b")
    );

    ///
    /// download certificates and certificate chains for a selection of hosts
    ///
    std::vector<std::string> hosts = helper.initialHosts();
    for(const std::string& h : hosts) {
//        std::cout << h << std::endl;
        Host::create(*store_sptr, h);
    }

    ///
    ///  now prepares the with_without_with and with_without_without bundles for forcing a verification failure
    //   when handshaking with the host specified by helper.withWithoutHost()
    path fix_path(helper.fixture_path());
    remove_all(helper.withWithoutDirPath());
    create_directories(helper.withWithoutDirPath());
    
    ///
    /// slightly reformat and then write the mozilla bundle to the withwithout/with.pem - file
    ///
    Cert::Chain moz_chain(locator_sptr->mozilla_root_certs);
    moz_chain.writePEM(helper.withWithoutCertRootStore("with"));
    ///
    /// Now create the withwithout/without.pem bundle
    /// by filtering out of the "with" bundle the root certificates from
    /// the mozilla bundle that is the issuer of the final certificate
    /// in the certificate chain of the helper.withWithoutHost().
    /// Thus the helper.withWithoutHost() should FAIL to verify
    /// agsin the without.pem bundle
    ///
    std::string wwohost = helper.hostForWithWithoutTests();
    Cert::Chain hostchain(locator_sptr->hostRealCertificateChainPath(wwohost));
    auto c1 = hostchain.toPEMString();
    std::string issuer_to_remove = hostchain.lastIssuer();
    std::string woh = str(boost::format(without_header) % issuer_to_remove);
    // NOTE: this is a hack. Based on knowledge that the root cert for bankofamerica
    // is issued by Entrust
    auto new_bundle = moz_chain.removeAllSubjectsMatching(".*Entrust.*");
    new_bundle.writeAnnotated(helper.withWithoutCertRootStore("without"), woh);

    /**
    * At this point - we have all directories created, a CA and various bundles of root
    * certificates and we have copied over all predefined test data. This is enough
    * to let us create a fixture object. Remember the TestFixture class checks
    * for the existence of various files and hence this creation is in part of verification
    * that we have done everything right
    */
    TestFixture fixture(fixture_root); // this verifies that all the files needed for testing exist
    TestHelper h2;
    TestFixture f2;
    std::cout << "hello" << std::endl;

}

