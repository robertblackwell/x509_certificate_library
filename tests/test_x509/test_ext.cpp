
#include <catch2/catch.hpp>
#include <boost/filesystem.hpp>

#include <cert/cert_helpers.hpp>
#include <cert/x509.hpp>

#include "test_fixture_new.hpp"

/**
* Tests NID GetDescriptor - get correct details and also fails as expected
*/
TEST_CASE("ext", "")
{
    TestFixtureNew fixture{};
    fixture.loadExisting();
    std::string cert_file_name = fixture.realCertFilePathForHost("host_a").string();
    boost::filesystem::path p3 = cert_file_name;
    if(   ! Cert::Helpers::fs::exists(p3) ) {
        std::cout << "WARNING - certificate used for testing does not exist" << std::endl;
    }
    REQUIRE( Cert::Helpers::fs::exists(p3) );

    SECTION("get")
    {
        BIO* out_bio;
        out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

//        auto original_cert_file = helper.realCertForHostPath("play.google.com");
//        auto google_cert_file_name = helper.realCertForHostPath("play.google.com");
        X509* cert = Cert::x509::Cert_ReadFromFile(cert_file_name);
    //    auto exts = Cert::x509::Cert_GetExtensions(google_cert);
    //    int numexts = sk_X509_EXTENSION_num(exts);
    //    int num = X509_get_ext_count(google_cert);
    //    X509_EXTENSION* xt2 = x509Extension_create(x509ExtNid_subjectAltName, "DNS:one.com,DNS:two.com");
        auto exts_spec = Cert::x509::Cert_extensionsAsDescription(cert);
        X509_free(cert);
        return;

    #if 0
        for( int j = 0; j < numexts ; j++ ) {
            auto entry = sk_X509_EXTENSION_value(exts, j);
    //        auto xx = (X509_EXTENSION*)X509V3_EXT_d2i(entry);
            auto ss = x509Extension_ValueAsString(entry);
            
            std::vector<std::string> values;
            boost::split(values, ss,boost::is_any_of(","));
    //        std::cout << ss << std::endl;
            auto method = X509V3_EXT_get(entry);
            auto e2 = X509_get_ext(google_cert, j);
            ASN1_OBJECT* obj1 = e2->object;
            ASN1_OBJECT* obj = X509_EXTENSION_get_object(entry);
            
            auto v1 = entry->value;
            ASN1_OCTET_STRING* v2 = X509_EXTENSION_get_data(entry);

            unsigned nid = OBJ_obj2nid(obj);
            if (nid == NID_undef) {
                // no lookup found for the provided OID so nid came back as undefined.
                char extname[10000];
                OBJ_obj2txt(extname, 100000, (const ASN1_OBJECT *) obj, 1);
                BIO_printf(out_bio, "[%s] = ", extname);
            } else {
                // the OID translated to a NID which implies that the OID has a known sn/ln
                const char *c_ext_name = OBJ_nid2ln(nid);
                if (c_ext_name == nullptr) {
                    X509_TRIGGER_ERROR("could not find name for NID");
                }
                BIO_printf(out_bio, "[%s] = ", c_ext_name);
            }
            BIO_printf(out_bio, "%s\n", ss.c_str());
        }
        for(int i = 0; i < num; i++) {
            auto ext = X509_get_ext(google_cert, i);
            auto obj = ext->object;
            auto nid = OBJ_obj2nid(obj);
            auto desc = x509Nid_GetDescriptor(nid);
            auto value = ext->value;
            unsigned char* buffer;
            int len;
            len = ASN1_STRING_to_UTF8(&buffer, value);
            std::string s((char*)buffer, len);
            OPENSSL_free(buffer);
            std::cout << s << std::endl;
        
        }
    #endif
    }
}
