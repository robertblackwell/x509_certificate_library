//
//  x509_cert.cpp
//  openssl_10_6
//
//  Created by ROBERT BLACKWELL on 10/26/17.
//  Copyright © 2017 Blackwellapps. All rights reserved.
//
#include <boost/filesystem.hpp>
#include <cert/x509.hpp>

#pragma mark - Cert::x509::Cert read/write

using namespace Cert;

namespace Cert{
namespace x509{

CertChain CertChain_FromString(std::string pem_string)
{
    x509::CertChain res;
    BIO *bio;
    X509 *x;

    const char *chain_buffer = pem_string.c_str();
    bio = BIO_new_mem_buf((void*)chain_buffer, -1);

//    bio = BIO_new_file(filename.c_str(), "r");
    if (bio == NULL) {
        X509_TRIGGER_ERROR ("Error reading certificate bundle from string ");
    }

    ERR_set_mark();
    do {
        x = PEM_read_bio_X509(bio, NULL, 0, NULL);
        if( x != NULL) {
            std::string pem = Cert::x509::Cert_PEMString(x);
            res.push_back(pem);
            X509_free(x);
        } else {
            
        }
    } while (x != NULL);
    
    ERR_pop_to_mark();
    BIO_free(bio);
    return res;

}


CertChain CertChain_FromFile(std::string filename)
{
    using namespace boost::filesystem;
    x509::CertChain res;
    BIO *bio;
    X509 *x;

    bio = BIO_new_file(filename.c_str(), "r");
    boost::filesystem::path p(filename);
    bool b =  exists(p);
    std::string note = (b) ? "boost found file" : " boost DID NOT find file";
    std::cout 
    << "XXXXXX " << note << " ["
    << __PRETTY_FUNCTION__ << "](bio:"
    << std::hex << bio << ") filename: /" 
    << filename << "/" <<std::endl;
    if (bio == NULL) {
        X509_TRIGGER_ERROR ("Error reading certificate bundle file " + filename);
    }

    ERR_set_mark();
    do {
        x = PEM_read_bio_X509(bio, NULL, 0, NULL);
        if( x != NULL) {
            std::string pem = Cert::x509::Cert_PEMString(x);
            res.push_back(pem);
            X509_free(x);
        } else {
            
        }
    } while (x != NULL);
    
    ERR_pop_to_mark();
    BIO_free(bio);
    return res;

}


void
CertChain_WriteToFile(STACK_OF(X509)* cert_chain, std::string fileName)
{
    FILE* fp;
    char* fn = (char*) fileName.c_str();
    if (!(fp = fopen (fn, "w")))
        X509_TRIGGER_ERROR ("Error writing to certificate file");
    int num = sk_X509_num(cert_chain);
    for(int i = 0; i < num; i++) {
        X509* cert = sk_X509_value(cert_chain, i);
        if (PEM_write_X509 (fp, cert) != 1)
            X509_TRIGGER_ERROR ("Error while writing certificate");
    }
    fclose (fp);
}

void
CertChain_WriteToFile(CertChain& cert_chain, std::string fileName)
{
    std::string s = CertChain_ToString(cert_chain);
    std::ofstream outfile(fileName);
    outfile << s;
    outfile.close();
}


CertChain
CertChain_FromStack(STACK_OF(X509)* cert_chain)
{
    CertChain res;
    int num = sk_X509_num(cert_chain);
    for(int i = 0; i < num; i++) {
        X509* cert = sk_X509_value(cert_chain, i);
        res.push_back(Cert_PEMString(cert));
        //X509_free(cert);
    }
    return res;
}


std::string
CertChain_ToString(CertChain& cert_chain)
{
    std::stringstream outs ;
    for(const std::string& pem: cert_chain) {
        X509* x = Cert::x509::Cert_FromPEMString(pem);
        std::string sn1l = Cert::x509::Cert_GetSubjectNameAsOneLine(x);
        std::string snml = Cert::x509::Cert_GetSubjectNameAsMultiLine(x);
        auto sn_spec = Cert::x509::Cert_GetSubjectNameAsSpec(x);
//        auto sn = Cert::x509::Cert_GetSubjectName(x);
//        auto sn1l = Cert::x509::Name_AsOneLine(sn);
//        auto snml = Cert::x509::Name_AsMultiLine(sn);
//        auto sn_spec = Cert::x509::Name_getSpec(sn);
        std::string cert_common_name = sn_spec[NID_commonName];
        
        outs << cert_common_name << std::endl;
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunused-variable"
        for(auto const c : cert_common_name) {
            outs << "=";
        }
        #pragma clang diagnostic pop
        outs << std::endl;
        outs << pem << std::endl;
    }
    return outs.str();
}

/**
* Writes a CertBundle to a file, adds a block of header text and annotates each
* certificate with the subject common name
* @param header - string to print at top of file
* @param filename - of file to write to, full path
* @param bundle - a CertBundle instance containing the certificates to write
* @return void
*/
void CertBundle_writeAnnotated(std::string header, std::string filename, x509::CertBundle bundle)
{
    std::stringstream outs ;
    outs << header << std::endl;
    for(const std::string& pem: bundle) {
        X509* x = Cert::x509::Cert_FromPEMString(pem);
        std::string sn1l = Cert::x509::Cert_GetSubjectNameAsOneLine(x);
        std::string snml = Cert::x509::Cert_GetSubjectNameAsMultiLine(x);
        auto sn_spec = Cert::x509::Cert_GetSubjectNameAsSpec(x);
//        auto sn = Cert::x509::Cert_GetSubjectName(x);
//        auto sn1l = Cert::x509::Name_AsOneLine(sn);
//        auto snml = Cert::x509::Name_AsMultiLine(sn);
//        auto sn_spec = Cert::x509::Name_getSpec(sn);
        std::string cert_common_name = sn_spec[NID_commonName];
        
        outs << "subject CN: " << cert_common_name << std::endl;
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunused-variable"
        for(auto const c : cert_common_name) {
            outs << "=";
        }
        #pragma clang diagnostic pop
        outs << std::endl;
        outs << pem << std::endl << "XXX";
    }
    std::ofstream outfile(filename);
    outfile << outs.str();
    outfile.close();

}


void CertChain_Print(CertChain& cert_chain, BIO* out_bio)
{
//    X509_print(out_bio, cert);
}
void CertChain_Print(CertChain& cert_chain)
{
//    BIO* out_bio  = BIO_new_fp(stdout, BIO_NOCLOSE);
//    X509_print(out_bio, cert);
//    BIO_free(out_bio);
}
} // namespace x509
} // namespace Cert
