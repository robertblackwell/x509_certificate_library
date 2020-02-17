//
//  main.cpp
//  verify
//
//  Created by ROBERT BLACKWELL on 11/17/17.
//  Copyright © 2017 ROBERT BLACKWELL. All rights reserved.
//

#include <iostream>

/* ------------------------------------------------------------ *
 * file:        certverify.c                                    *
 * purpose:     Example code for OpenSSL certificate validation *
 * author:      06/12/2012 Frank4DD                             *
 *                                                              *
 * gcc -o certverify certverify.c -lssl -lcrypto                *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "test_helpers.hpp"
#include "cert/x509.hpp"
/**---------------------------------------------------------------- *
*
* Verify a certificate against a store of root certificates
*
---------------------------------------------------------------- ***/
void test_verify(std::string ca_store_path, std::string cert_path)
{
    
//    TestHelper helper;
//
//    auto ca_key_path = helper.caKeyPath();
//    auto ca_cert_path = helper.caCertPath();
//    auto cert_path = helper.ssltestCert();
    auto root_cert_store_path = ca_store_path;
    
//    const char ca_bundlestr[] = "./ca-bundle.pem";
//    const char cert_filestr[] = "./cert-file.pem";
    
    const char* ca_bundlestr = root_cert_store_path.c_str();
    const char* cert_filestr= cert_path.c_str();
    

    BIO              *certbio = NULL;
    BIO               *outbio = NULL;
    X509          *error_cert = NULL;
    X509                *cert = NULL;
    X509_NAME    *certsubject  = NULL;
    X509_STORE         *store  = NULL;
    X509_STORE_CTX  *vrfy_ctx  = NULL;
    int ret;
    const char* dir = X509_get_default_cert_dir();

    /* ---------------------------------------------------------- *
     * These function calls initialize openssl for correct work.  *
     * ----------------------------------------------------------
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    */
    /* ---------------------------------------------------------- *
     * Create the Input/Output BIO's.                             *
     * ---------------------------------------------------------- */
    certbio = BIO_new(BIO_s_file());
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
    
    /* ---------------------------------------------------------- *
     * Initialize the global certificate validation store object. *
     * ---------------------------------------------------------- */
    if (!(store=X509_STORE_new()))
        BIO_printf(outbio, "Error creating X509_STORE_CTX object\n");
    
    /* ---------------------------------------------------------- *
     * Create the context structure for the validation operation. *
     * ---------------------------------------------------------- */
    vrfy_ctx = X509_STORE_CTX_new();
    
    /* ---------------------------------------------------------- *
     * Load the certificate and cacert chain from file (PEM).     *
     * ---------------------------------------------------------- */
//    ret = x5zero::Cert_ReadFromFile(ca_cert_path);
    
    ret = (int)BIO_read_filename(certbio, cert_filestr);
    if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        BIO_printf(outbio, "Error loading cert into memory\n");
        exit(-1);
    }
    ret = X509_STORE_load_locations(store, ca_bundlestr, NULL);
    if (ret != 1)
        BIO_printf(outbio, "Error loading CA cert or chain file\n");
    
    /* ---------------------------------------------------------- *
     * Initialize the ctx structure for a verification operation: *
     * Set the trusted cert store, the unvalidated cert, and any  *
     * potential certs that could be needed (here we set it NULL) *
     * ---------------------------------------------------------- */
    X509_STORE_CTX_init(vrfy_ctx, store, cert, NULL);
    
    /* ---------------------------------------------------------- *
     * Check the complete cert chain can be build and validated.  *
     * Returns 1 on success, 0 on verification failures, and -1   *
     * for trouble with the ctx object (i.e. missing certificate) *
     * ---------------------------------------------------------- */
    ret = X509_verify_cert(vrfy_ctx);
    BIO_printf(outbio, "Verification return code: %d\n", ret);
    
    if(ret == 0 || ret == 1)
        BIO_printf(outbio, "Verification result text: %s\n",
                   X509_verify_cert_error_string(vrfy_ctx->error));
    
    /// note - if this fails read the details at http://fm4dd.com/openssl/certverify.htm
    
    /* ---------------------------------------------------------- *
     * The error handling below shows how to get failure details  *
     * from the offending certificate.                            *
     * ---------------------------------------------------------- */
    if(ret == 0) {
        /*  get the offending certificate causing the failure */
        error_cert  = X509_STORE_CTX_get_current_cert(vrfy_ctx);
        certsubject = X509_NAME_new();
        certsubject = X509_get_subject_name(error_cert);
        BIO_printf(outbio, "Verification failed cert:\n");
        X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
        BIO_printf(outbio, "\n");
    }
    
    /* ---------------------------------------------------------- *
     * Free up all structures                                     *
     * ---------------------------------------------------------- */
    X509_STORE_CTX_free(vrfy_ctx);
    X509_STORE_free(store);
    X509_free(cert);
    BIO_free_all(certbio);
    BIO_free_all(outbio);
}
int main(int argc, char *argv[])
{
//    char* a1 = argv[0];
//    char* a2 = argv[1];
    char* _argv[2] = {argv[0], (char*)"--gtest_filter=*.*"}; // change the filter to restrict the tests that are executed
    int _argc = 2;
    OpenSSL_add_all_algorithms ();
    ERR_load_crypto_strings ();
    ERR_load_BIO_strings();
    ERR_load_ERR_strings();
    
        TestHelper helper;
    
    auto ca_key_path = helper.caKeyPath();
    auto ca_cert_path = helper.caCertPath();
    auto cert_path = helper.ssltestCert();
    auto root_cert_store_path = helper.caCertPath();
    
    // test with one ca cert and a server know to be signed by this ca cert
    test_verify(helper.caCertPath(), helper.ssltestCert());
    
    // now test some server against the comnbined store of root certificates
    // combined being all mozilla + our local CA
    test_verify(helper.rootCertStore(), helper.ssltestCert());
    
    // test some other server () against the combined store of root certificates
    // combined being all mozilla + our local CA
    
    // THIS NEXT ONE DOES NOT WORK - BECAUSE we did not capture the full chain
    // of certificates that the server sent when we collected its certificate
    // and the real certificate is signed by a subordinate CA
    // and we need all the CA;s above that.
    // the reason the previous two worked
    
    test_verify(helper.rootCertStore(), helper.realCertForHostPath("httpsnow.org"));
    

//    testing::InitGoogleTest(&_argc, _argv);
//    return RUN_ALL_TESTS();
//    test1();
}

