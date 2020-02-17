#include <boost/filesystem.hpp>
#include <boost/algorithm/string/replace.hpp>
#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include <cert/x509.hpp>
#include <cert/cert_helpers.hpp>
#include <cert/cert_store.hpp>
//#include "cert_store_authority.hpp"
#include <cert/cert_store_host.hpp>
#include <cert/cert_builder.hpp>
#include "test_helpers.hpp"
using namespace Cert::Store;

int main( int argc, char* argv[] )
{
    
    // global setup...

    char* t_argv[2] = {argv[0], (char*)"*"}; // change the filter to restrict the tests that are executed
    int t_argc = 2;
    int result = Catch::Session().run( t_argc, t_argv );

    // global clean-up...

    return result;
}

TEST_CASE("locator properties","")
{
    TestHelper helper;
    auto r = helper.certStoreRoot();
    Cert::Store::Locator loc(r);
    std::cout << std::endl;
    std::string output = boost::replace_all_copy(loc.hosts_dir_path.string(), helper.projectRoot(), "");

    CHECK(boost::replace_all_copy(loc.ca_dir_path.string(), helper.projectRoot(), "") == "/tests/fixtures/CA/private");
    CHECK(boost::replace_all_copy(loc.ca_key_pem_path.string(), helper.projectRoot(), "") == "/tests/fixtures/CA/private/cakey.pem");
    CHECK(boost::replace_all_copy(loc.ca_cert_pem_file_path.string(), helper.projectRoot(), "") == "/tests/fixtures/CA/private/cacert.pem");

    CHECK(boost::replace_all_copy(loc.hosts_dir_path.string(), helper.projectRoot(), "") == "/tests/fixtures/CA/hosts");
    CHECK(boost::replace_all_copy(loc.hostFolder("ahost").string(), helper.projectRoot(), "") == "/tests/fixtures/CA/hosts/ahost");

    CHECK(boost::replace_all_copy(loc.sites_dir_path.string(), helper.projectRoot(), "") == "/tests/fixtures/CA/sites");

    CHECK(boost::replace_all_copy(loc.mozilla_root_certs.string(), helper.projectRoot(), "") == "/tests/fixtures/CA/root_certs/mozilla.pem");
    CHECK(boost::replace_all_copy(loc.osx_root_certs.string(), helper.projectRoot(), "") == "/tests/fixtures/CA/root_certs/osx.pem");

}

TEST_CASE("demonstrate_process_for_using","")
{
    // create a new Store with a CA
    std::string dot = __FILE__;
    boost::filesystem::path p(dot);
    boost::filesystem::path dirp = p.parent_path() / "test_store";
    Cert::Helpers::fs::remove_dir(dirp);
    // test test_store dir removed
    CHECK(!Cert::Helpers::fs::is_directory(dirp));

    TestHelper helper;
    auto cf = helper.caConfigFilePath();
    auto bx = Cert::Helpers::fs::is_regular_file(cf);
    REQUIRE(bx);
    auto store = Cert::Store::Store::makeWithCA(dirp, cf);
    //
    // check test_store dir was created and also check a few of the subdirs
    //
    CHECK(Cert::Helpers::fs::is_directory(dirp));
    CHECK(Cert::Helpers::fs::is_directory(store->getLocator()->sites_dir_path));
    CHECK(Cert::Helpers::fs::is_directory(store->getLocator()->ca_dir_path));
    // how to test that the store is empty ?
    // test loading root certificate bundle from mozilla and osx keychain
    CHECK(!Cert::Helpers::fs::is_regular_file(store->getLocator()->mozilla_root_certs));
    store->rootCertsFromMozilla();
    auto f1 = store->getLocator()->mozilla_root_certs;
    CHECK(Cert::Helpers::fs::is_regular_file(store->getLocator()->mozilla_root_certs));

    CHECK(!Cert::Helpers::fs::is_regular_file(store->getLocator()->osx_root_certs));
    store->rootCertsFromKeychain();
    CHECK(Cert::Helpers::fs::is_regular_file(store->getLocator()->osx_root_certs));

    CHECK(!Cert::Helpers::fs::is_regular_file(store->getLocator()->root_certs_bundle_file_path));
    store->rootCertsMozillaActive();
    CHECK(Cert::Helpers::fs::is_regular_file(store->getLocator()->root_certs_bundle_file_path));

    SECTION("with the new store get an original certificate from google") {
        HostId h = HostId("google.com");
        CHECK(!Cert::Helpers::fs::is_directory(store->getLocator()->hostFolder(h)));
        Cert::Store::Host::getRealCertificate(*store, "google.com");
        CHECK(Cert::Helpers::fs::is_directory(store->getLocator()->hostFolder(h)));
        auto f2 = store->getLocator()->hostRealCertificatePath(h);
        CHECK(Cert::Helpers::fs::is_regular_file(store->getLocator()->hostRealCertificatePath(h)));
        auto f3 = store->getLocator()->hostRealCertificateChainPath(h);
        CHECK(Cert::Helpers::fs::is_regular_file(store->getLocator()->hostRealCertificateChainPath(h)));
    }
    SECTION("after the new store is created load it and test the load worked") {
        StoreSPtr store = ::Cert::Store::Store::load(dirp);
        LocatorSPtr loc = store->getLocator();
        CHECK(Locator::verify(loc));
        CHECK(Cert::Helpers::fs::is_directory(dirp));
        CHECK(Cert::Helpers::fs::is_directory(store->getLocator()->sites_dir_path));
        CHECK(Cert::Helpers::fs::is_directory(store->getLocator()->ca_dir_path));
        // how to test that the store is empty ?
        // test loading root certificate bundle from mozilla and osx keychain
        auto f1 = store->getLocator()->mozilla_root_certs;
        CHECK(Cert::Helpers::fs::is_regular_file(store->getLocator()->mozilla_root_certs));
        CHECK(Cert::Helpers::fs::is_regular_file(store->getLocator()->osx_root_certs));
        CHECK(Cert::Helpers::fs::is_regular_file(store->getLocator()->root_certs_bundle_file_path));
    }
    SECTION("demonstrate how to use an existing store to create a Mitm certificate") {
        /**
         * This next blod would be executed at program startup so that a valid instance
         * of Store and Authority existed throughout the life of an Mitm proxy
         */
        StoreSPtr store = ::Cert::Store::Store::load(dirp);
        LocatorSPtr loc = store->getLocator();
        AuthoritySPtr ca_sptr = store->m_cert_auth_sptr;
        ::Cert::Builder builder(*ca_sptr);
        
        /**
         * The next two blocks get an X509* - in a network application this would be
         * obtained by the proxy acting in a client mode communicating with
         * a server.
         *
         * In the handshake completion handler of the folowing boost::asio call below
         *
         *  ssl_socket.async_handshake(
         *      boost::asio::ssl::stream_base::client,
         *      completion_handler)
         *
         * do the following
         *
         *      X509* cert = SSL_get_peer_certificate(m_socket.native_handle());
         *
         */
        HostId h = HostId("google.com");
        CHECK(!Cert::Helpers::fs::is_directory(store->getLocator()->hostFolder(h)));
        Cert::Store::Host::getRealCertificate(*store, "google.com");
        CHECK(Cert::Helpers::fs::is_directory(store->getLocator()->hostFolder(h)));
        auto f2 = store->getLocator()->hostRealCertificatePath(h);
        CHECK(Cert::Helpers::fs::is_regular_file(store->getLocator()->hostRealCertificatePath(h)));
        auto f3 = store->getLocator()->hostRealCertificateChainPath(h);
        CHECK(Cert::Helpers::fs::is_regular_file(store->getLocator()->hostRealCertificateChainPath(h)));

        X509* x = ::Cert::x509::Cert_ReadFromFile(f2.string());

        /**
         * Then the create the Mitm identity as follows
         */
        Cert::Certificate originalCertificate(x);
        Identity identity = builder.buildMitmIdentity(originalCertificate);

        /**
         * This identity is then used by a proxy in a server mode to add the certificate and private key
         * to the boost::asio ssl_context. This is best done by switching from boost::asio world to
         * Openssl world and making the following 2 calls
         *
         * SSL_CTX_use_certificate(SSL_CTX ssl_ctx*, X509* certificate)
         *
         * where
         *      ssl_context is an variable of type boost::asio::ssl_context that was used in the above mentioned ssl handshake process
         *      SSL_CTX* ssl_ctx = ssl_context.native_handle()
         *      X509* certificate = identity.getX509()
         * SSL_CTX_use_PrivateKey(SSL_CTX ssl_ctx*, EVP_PKEY* pkey)
         *
         * where
         *      ssl_context is an variable of type boost::asio::ssl_context that was used in the above mentioned ssl handshake process
         *      SSL_CTX* ssl_ctx = ssl_context.native_handle()
         *      EVP_PKEY* pkey = identity.getEVP_PKEY()
         *
         * NOTE: both the SSL calls up the reference count on the X509* and the EVP_PKEY* respectively
         * so that after these calls let the Identity destructor handle their references to these objects
         */

        /** This stuff is just cleaning up the test*/
        std::cout << "got an identity" << std::endl;
        X509_free(x);
    }
}
