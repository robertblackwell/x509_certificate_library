/**
* Contains tests for Cert::x509::Cert getter and setter function. IN particular the tests demonstrate which
* getters/setters are based on references and which make copies of the data. This is related to
* whether the caller has responsibility to free any data obtained with a getter.
*
* @todo have not yet written tests for extensions
*/

#include <catch2/catch.hpp>
#include <boost/filesystem.hpp>

#include <cert/cert_helpers.hpp>
#include <cert/x509.hpp>
#include <cert/x509_cert_impl.hpp>

#include "test_fixture_new.hpp"

//
// Demonstrates that Cert::x509::Cert_Get/SetPublicKey work with VALUES/COPIES not references
//
// The returned EVP_PKEY is owned by the caller and must be freed
//
TEST_CASE("cert_get_set")
{
    TestFixtureNew fixture{};
    fixture.loadExisting();
    std::string host_b_cert_file_name = fixture.realCertFilePathForHost("host_b").string();
    std::string paypal_cert_file_name = fixture.realCertFilePathForHost("host_a").string();
    boost::filesystem::path paypal_path = paypal_cert_file_name;
    boost::filesystem::path p3 = host_b_cert_file_name;
    
    if(   ! Cert::Helpers::fs::exists(p3) ) {
        std::cout << "WARNING - host_b == google certificate used for testing does not exist" << std::endl;
    }
    if(   ! Cert::Helpers::fs::exists(paypal_path) ) {
        std::cout << "WARNING - host_a == paypal certificate used for testing does not exist" << std::endl;
    }
    REQUIRE( Cert::Helpers::fs::exists(p3) );
    REQUIRE( Cert::Helpers::fs::exists(paypal_path) );

    SECTION("PubKey_GettersNotAReferenceOnlyTest")
    {
        BIO* out_bio;
        out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

        X509* cert = Cert::x509::Cert_ReadFromFile(host_b_cert_file_name);

        X509* paypal_cert = Cert::x509::Cert_ReadFromFile(paypal_cert_file_name);

        auto pk_google = Cert::x509::Cert_GetPublicKey(cert);
        auto s1 = Cert::x509::PKey_PublicKeyAsPEMString(pk_google);
        auto pk_paypal = Cert::x509::Cert_GetPublicKey(paypal_cert);
        auto s2 = Cert::x509::PKey_PublicKeyAsPEMString(pk_paypal);
        Cert::x509::Cert_SetPublicKey(cert, pk_paypal);
        auto s3 = Cert::x509::PKey_PublicKeyAsPEMString(pk_google);
        auto pk_google2 = Cert::x509::Cert_GetPublicKey(cert);
        auto s4 = Cert::x509::PKey_PublicKeyAsPEMString(pk_google2);
        REQUIRE(s1 != s2); // the certs have different public keys
        REQUIRE(s1 == s3); //after googles key is changed in the cert pk_google has NOT changed - hence not a reference
        REQUIRE(s1 != s4); //the pub key in googles cert HAS changed
        REQUIRE(s2 == s4); // googles key has changed to be paypals key
    //    std::cout << "help" << std::endl;
        EVP_PKEY_free(pk_google);
        EVP_PKEY_free(pk_google2);
        EVP_PKEY_free(pk_paypal);
        X509_free(cert);
        X509_free(paypal_cert);
        BIO_free(out_bio);
    }
    //
    // Demonstrates that Cert::x509::Cert_Get/SetVersion work with COPIES not references
    //
    SECTION("Version_GettersNotReferenceOnlyTest")
    {
        BIO* out_bio;
        out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        X509* original_cert = Cert::x509::Cert_ReadFromFile(host_b_cert_file_name);
        long v1 = Cert::x509::Cert_GetVersion(original_cert);
        Cert::x509::Cert_SetVersion(original_cert, 5);
        long v2 = Cert::x509::Cert_GetVersion(original_cert);
        REQUIRE(v2 == 5L);
        REQUIRE(v1 != v2);
    #if 0
        Cert::x509::Cert_Print(original_cert, out_bio);
    #endif
        X509_free(original_cert);
        BIO_free(out_bio);
    }

    //
    // Demonstrates that Cert::x509::Cert_GetSrial only gets a reference not a copy of the serial number
    //
    SECTION("Serial_GettersReferenceOnlyTest")
    {
        BIO* out_bio;
        out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        X509* original_cert = Cert::x509::Cert_ReadFromFile(host_b_cert_file_name);
        //
        // get the issuer name and save it in as asingle line in a string
        //
        auto serial = Cert::x509::Cert_GetSerialNumber(original_cert);
        auto s1 = Cert::x509::Serial_AsString(serial);
        Cert::x509::Cert_SetSerialNumber(original_cert, 15L);
        auto serial2 = Cert::x509::Cert_GetSerialNumber(original_cert);
        auto s12 = Cert::x509::Serial_AsString(serial);
        auto s2 = Cert::x509::Serial_AsString(serial2);
        REQUIRE(s12 == s2);
        REQUIRE(s12 == std::string("0x0F"));
        REQUIRE(s1 != s2);
    #if 0
        Cert::x509::Cert_Print(original_cert, out_bio);
    #endif
        X509_free(original_cert);
        BIO_free(out_bio);

    }

    /**
    ** Demonstrates that Cert::x509::Cert_GetIssuerName - does not make a copy
    ** but returns a pointer to the live name stack - hence the caller
    ** of Cert::x509::Cert_GetIssuerName DOES NOT OWN the X509_NAME object.
    **
    ** Same should be true for Cert::x509::Cert_GetSubjectName
    */
    SECTION("Name_GetterIsNotReferenceOnlyTest")
    {
        BIO* out_bio;
        out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        X509* original_cert = Cert::x509::Cert_ReadFromFile(host_b_cert_file_name);
        //
        // get the issuer name and save it in as asingle line in a string
        //
        auto name = Cert::x509::Cert_GetIssuerName(original_cert);
        auto s1 = Cert::x509::Name_AsOneLine(name);
        //
        // change the extracted issuername
        //
        Cert::x509::Name_AddEntryByNID(name, NID_organizationalUnitName, "this-is-an-organizational-unit-name");
        //
        // get the issuer name and sabve it in a string
        //
        auto name2 = Cert::x509::Cert_GetIssuerName(original_cert);
        auto s2 = Cert::x509::Name_AsOneLine(name2);
        //
        // the two strings are NOT equal showing that name and name2 are just references to the same data structure
        //
        REQUIRE(s1 != s2);
    #if 0
        Cert::x509::Cert_Print(original_cert, out_bio);
    #endif
        X509_free(original_cert);
        BIO_free(out_bio);
    }
    /**
    * Demonstrates how to create a X509_NAME as a stack of X509_NAME_ENTRY. Tests that we set the values correctly
    * redundant see test_name.cpp
    */
    SECTION("Name_CreateTest")
    {
        BIO* out_bio;
        out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        X509_NAME* name = X509_NAME_new();
        Cert::x509::Name_AddEntryByNID(name, NID_countryName, "US");
        Cert::x509::Name_AddEntryByNID(name, NID_organizationName, "this-is-an-organization-name");
    //    std::cout << Cert::x509::Name_AsOneLine(name) << std::endl;
    //    std::cout << Cert::x509::Name_AsMultiLine(name) << std::endl;
        auto s1 = Cert::x509::Name_AsOneLine(name);
        auto s2 = Cert::x509::Name_AsMultiLine(name);
        REQUIRE(Cert::x509::Name_AsOneLine(name) == "C=US, O=this-is-an-organization-name");
        REQUIRE(Cert::x509::Name_AsMultiLine(name) == "countryName               = US\norganizationName          = this-is-an-organization-name");
        BIO_free(out_bio);
    }
    /**
    * Demonstrates how to get contents of X509_NAME as either a single line
    * or multi-line string and tests that we extract the values correctly
    */
    SECTION("Name_GetAsStringTest")
    {
        BIO* out_bio;
        out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        X509* original_cert = Cert::x509::Cert_ReadFromFile(host_b_cert_file_name);
        auto name = Cert::x509::Cert_GetIssuerName(original_cert);
        
    #if 0 //loop over the stack of entries - not ready for that yet
        auto l = sk_X509_NAME_ENTRY_num(name->entries);
        auto xx = {OBJ_localityName};
        for( int i = 0; i < l ; i++) {
            auto ne=sk_X509_NAME_ENTRY_value(name->entries,i);
    // These next 5 lines corrupt the OBJ so that the NID is not found
    //  hence we get to see how an invalid NID prints
    //        if (i ==0) {
    //            unsigned char* pp = (unsigned char*)(ne->object->data);
    //            pp[1] = 0x07;
    //            pp[2] = 0x07;
    //        }
            auto n=OBJ_obj2nid(ne->object);
            if ((n == NID_undef) || ((s=OBJ_nid2sn(n)) == NULL))
            {
                const char* ss = OBJ_nid2ln(n);
                i2t_ASN1_OBJECT(tmp_buf,sizeof(tmp_buf),ne->object);
                s=tmp_buf;
            }
            const char* ss = OBJ_nid2ln(n);
            printf("%s\n", ss);

        }
    #endif

        auto s1 = Cert::x509::Name_AsOneLine(name);
        auto s2 = Cert::x509::Name_AsMultiLine(name);
    #if 0
        std::cout << Cert::x509::Name_AsOneLine(name) << std::endl;
        std::cout << Cert::x509::Name_AsMultiLine(name) << std::endl;
    #endif
        REQUIRE(Cert::x509::Name_AsOneLine(name) ==
                  "C=US, O=Google Trust Services, CN=Google Internet Authority G3");
        REQUIRE(Cert::x509::Name_AsMultiLine(name) ==
                  "countryName               = US\norganizationName          = Google Trust Services\ncommonName                = Google Internet Authority G3");

        BIO_printf(out_bio, "\n");
        X509_free(original_cert);
        BIO_free(out_bio);
    }
    //
    // Demonstrates thet Cert::x509::Cert_GetNotBefore and Cert::x509::Cert_GetNotAfter return
    // references to NOT COPIES of
    // an ASN1_TIME object embedded inside the X509 object
    //
    // Hence the ASN1_TIME objects are not owned by the caller of Cert::x509::Cert_GetNotBefore/Cert::x509::Cert_GetNotAfter
    //
    //
    SECTION("Time_GetNotBeforeISReferenceOnly")
    {
        X509* original_cert = Cert::x509::Cert_ReadFromFile(host_b_cert_file_name);
        ASN1_TIME* t_1 = Cert::x509::Cert_GetNotBefore(original_cert);
        auto s1 = Cert::x509::TimeAsString(t_1);

//        auto s1 = x509Time_AsString(t_1);
        X509_time_adj(t_1, 60*60*24*365, nullptr);
        auto s2 = Cert::x509::TimeAsString(t_1);
//        auto s2 = x509Time_AsString(t_1);
        ASN1_TIME* t_2 = Cert::x509::Cert_GetNotBefore(original_cert);
        auto s3 = Cert::x509::TimeAsString(t_2);
        // these assertions demonstrates that t_1 and T-2 are references to the same ASN1_TIME object
        REQUIRE(s2 == s3);
        REQUIRE(s1 != s3);
        X509_free(original_cert);
    }
    
    /**
    ** Tests setting a time value in NotBefore
    */
    SECTION("TimeSetGetNotBefore")
    {
        X509* original_cert = Cert::x509::Cert_ReadFromFile(host_b_cert_file_name);
        X509* cert = X509_new();
        ASN1_TIME* t_original = Cert::x509::Cert_GetNotBefore(original_cert);
        ASN1_TIME* t_new = Cert::x509::Cert_GetNotBefore(cert);
        ASN1_STRING* s_original = (ASN1_STRING*) t_original;
        ASN1_STRING* s_new = (ASN1_STRING*) t_new;
        auto r1 = ASN1_STRING_cmp(s_original, s_new);
        REQUIRE(r1 != 0); // << "first comparison should be NE" << std::endl;;
        Cert::x509::Cert_SetNotBefore(cert, t_original);
        // there is no comparison function for ASN1_TIME so cast them to ASN1_STRING and use ASN1_STRING_cmp()
        auto r2 = ASN1_STRING_cmp(s_original, s_new);
        REQUIRE(r2 == 0); // << "second comparisons should be equal" << std::endl;
        X509_free(original_cert);
        X509_free(cert);
    }
    /**
    ** Tests setting a time value in NotBefore
    */
    SECTION("TimeSetGetNotAfter")
    {
        X509* original_cert = Cert::x509::Cert_ReadFromFile(host_b_cert_file_name);
        X509* cert = X509_new();
        ASN1_TIME* t_original = Cert::x509::Cert_GetNotAfter(original_cert);
        ASN1_TIME* t_new = Cert::x509::Cert_GetNotAfter(cert);
        ASN1_STRING* s_original = (ASN1_STRING*) t_original;
        ASN1_STRING* s_new = (ASN1_STRING*) t_new;
        auto r1 = ASN1_STRING_cmp(s_original, s_new);
        REQUIRE(r1 != 0);// << "first comparison should be NE" << std::endl;;
        Cert::x509::Cert_SetNotAfter(cert, t_original);
        auto r2 = ASN1_STRING_cmp(s_original, s_new);
        REQUIRE(r2 == 0);// << "second comparisons should be equal" << std::endl;
        X509_free(original_cert);
        X509_free(cert);
    }

    //std::map<int, std::string> x509ExtensionStack_simpleUnpack(STACK_OF(X509_EXTENSION)* stack)
    //{
    //    std::map<int, std::string> ret;
    //    auto vec1 = x509ExtensionStack_unpack(stack);
    //    for(auto const& ext : vec1) {
    //        ret[ext.nid_desc.nid] = ext.value;
    //    }
    //    return ret;
    //}
    //void Cert::x509::Cert_SetExtensions(X509* cert, STACK_OF(X509_EXTENSION)* exts)
    //{
    //    auto tmp = cert->cert_info->extensions;
    //    STACK_OF(X509_EXTENSION)* ext_new = sk_X509_EXTENSION_dup(exts);
    //    cert->cert_info->extensions = ext_new;
    //    sk_X509_EXTENSION_free(tmp);
    //}
    //bool x509ExtensionStack_equal(STACK_OF(X509_EXTENSION)* stack1, STACK_OF(X509_EXTENSION)* stack2)
    //{
    //    auto v1 = x509ExtensionStack_simpleUnpack(stack1);
    //    auto v2 = x509ExtensionStack_simpleUnpack(stack2);
    //    return (v1 == v2);
    //}
} // TEST_CASE
#if 0
void x509ExtensionStack_makeEmpty(STACK_OF(X509_EXTENSION)* stack)
{
    int num = sk_X509_EXTENSION_num(stack);
    for(int i = num - 1; i >= 0 ; i--) {
        X509_EXTENSION* x = sk_X509_EXTENSION_delete(stack, i);
        X509_EXTENSION_free(x);
    }
    num = sk_X509_EXTENSION_num(stack);
}
void x509Cert_something(X509* cert, std::map<int, std::string> map)
{
    X509V3_CTX ctx;
    X509V3_set_ctx (&ctx, (X509*)nullptr, cert, NULL, NULL, 0);
    for( auto & x : map) {
        int nid = x.first;
        Cert::x509::NidDescriptor d = Cert::x509::Nid_GetDescriptor(nid);
        auto v = (char*)x.second.c_str();
        X509_EXTENSION *ext;
//        if(nid == 103)
//            continue;
        ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, v);
        if (!ext )
        {
//            fprintf (stderr, "Error on \"%d = %s\"\n", nid, v);
            X509_TRIGGER_ERROR ("Error creating X509 extension object");
        }
        //
        // this call DOES NT take ownership of the ext (it copies it) so we have to dispose
        //
        if (!X509_add_ext (cert, ext, -1))
        {
            fprintf (stderr, "Error on \"%d = %s\"\n",  nid, v);
            X509_TRIGGER_ERROR ("Error adding X509 extension to certificate");
        }
        X509_EXTENSION_free (ext);
    }
}
#endif
