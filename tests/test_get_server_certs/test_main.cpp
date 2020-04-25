
#include <cstdlib>
#include <iostream>
#include <set>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/unordered_set.hpp>
#include <boost/filesystem.hpp>

#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>
#include <cert/cert.hpp>

#include "test_fixture_new.hpp"
#include "list.cpp"
bool mitmWorked(X509* original_cert_X509, std::string host, Cert::Identity id)
{
    Cert::Certificate org_cert(original_cert_X509);

    auto orig_spec = Cert_GetSubjectNameAsSpec(original_cert_X509);
    auto orig_cn = (*orig_spec.find(NameNid_commonName)).second;
    
    auto new_spec = Cert_GetSubjectNameAsSpec(id.getX509());
    auto new_cn = (*new_spec.find(NameNid_commonName)).second;

    /// if the host the common name ? - possibly not
    bool b1 = (new_cn == host);

    boost::optional<std::string> orig_san = Cert_GetSubjectAlternativeNamesAsString(original_cert_X509);
    std::string orig_san2 = org_cert.getSubjectAlternativeNamesAsString();
    boost::optional<std::string> new_san = Cert_GetSubjectAlternativeNamesAsString(id.getX509());
    std::string orig_san_string {(orig_san) ? orig_san.get(): "NOVALUE"};
    std::string orig_san2_string {orig_san2};
    std::string new_san_string  {(new_san) ? new_san.get(): "NOVALUE"};

    bool b2;
    if (orig_san && new_san) {
        /// both have a value
        b2 = (orig_san.get() == new_san.get()); 
    } else if ((!orig_san)&&(!new_san)) {
        // both dont have a value
        b2 = true;
    } else {
        b2 = false;
    }
    bool b3 = new_san_string.find(host);
    return (b1||b3)&&b2;
}

class ContactServer: public TestFixtureNew
{
    public:
    ContactServer()
    {
        this->loadExisting();
    }

    void buildMitmCert(std::string host, X509* original_cert_X509)
    {
        path store_root = this->storeRootDirPath();
        Cert::Store::LocatorSPtr locator_sptr = std::make_shared<Cert::Store::Locator>(store_root);
        Cert::AuthoritySPtr cert_auth = Cert::Authority::load(locator_sptr->ca_dir_path);

            // call the genuine forger function
        Cert::Certificate cert(original_cert_X509);
        Cert::Builder builder(*cert_auth);
        Cert::Identity id = builder.buildMitmIdentity(host, cert);
        bool b0 = mitmWorked(original_cert_X509, host, id);
        
        if(b0) {
            std::cout << "OK : " << host << std::endl; 
        } else {
            std::cout << "Failed : " << host << std::endl; 
        }
    }
    void contactServer(std::string server)
    {
        std::string moz_only = this->mozRootCertificateBundleFilePath().string();
        std::string cert_bundle_path = moz_only;
        boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
    #define XTURN_OFF_VERIFY
    #ifdef TURN_OFF_VERIFY
        ctx.set_verify_mode(boost::asio::ssl::verify_none);
    #else
        ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    #endif
        //
        // use a non default root certificate location, AND load them into a custom X509_STORE
        //
        X509_STORE *store = X509_STORE_new();
        X509_STORE_load_locations(store, (const char*)cert_bundle_path.c_str(), NULL);
        // attach X509_STORE to boost ssl context
        SSL_CTX_set_cert_store(ctx.native_handle(), store);

        boost::asio::io_service io;
        Handshaker::client c("https", server, ctx, io);
        c.handshake([this, server, &c](boost::system::error_code err) {
            if (err.failed()) {
                std::cout << "handshake callback : " << server << " err: [" << err.message() << "]" << std::endl;
            } else {
                std::cout << "OK : " << server << std::endl; 

            }
        });
        io.run();
    }
    void workTheList(std::vector<std::string>& list)
    {
        for(int i = 0; i < list.size(); i++) {
            contactServer(list[i]);
            std::cout << i << "  ";
        }
    }
};

int main( int argc, char* argv[] ) {
    // global setup...
    std::cout << "Starting" << std::endl;
    OpenSSL_add_all_algorithms ();
    ERR_load_crypto_strings ();
    ERR_load_BIO_strings();
    ERR_load_ERR_strings();
    std::vector<std::string>& list = makeList();
    ContactServer cs{};
    cs.workTheList(list);


    // global clean-up...
    int result = 0;
    return result;
}


