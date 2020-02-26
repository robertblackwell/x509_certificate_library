//
//  error.cpp
//  openssl_10_6
//
//  Created by ROBERT BLACKWELL on 10/26/17.
//  Copyright © 2017 Blackwellapps. All rights reserved.
//


#include <sstream>
#include <openssl/bio.h>
#include <exception>
#include <openssl/err.h>

#include <cert/error.hpp>
/**
* Erro handler for Cert functions
*/
void Cert::errorHandler (std::string func, std::string file, int lineno, std::string msg)
{
    std::string message(msg);
    std::stringstream messageStream;
    messageStream <<  "Error in function: " << func << " file: " << file << " at lineNo: " << lineno << std::endl << "Message: [" << message << "]" ;
    throw Cert::Exception(messageStream.str());
}

/**
* Erro handler for Cert::x509 functions
*/
void Cert::x509::errorHandler (std::string func, std::string file, int lineno, std::string msg)
{
    char buf[100001];
    std::string message(msg);
    std::stringstream messageStream;
    
    messageStream <<  "Error in function: " << func << " file: " << file << " at lineNo: " << lineno << std::endl << "Message: [" << message << "]" ;
    
    BIO* errBio = BIO_new(BIO_s_mem());
    ERR_print_errors(errBio);

    int count2 = BIO_read(errBio, buf, 10000);
    buf[count2] = (char)0;
    messageStream << std::endl << "OpenSSL error message is : [" << buf <<"]" << std::endl;
//    ERR_print_errors_fp (stderr);
    throw Cert::Exception(messageStream.str());
}
using namespace Cert;
    Cert::Exception::Exception(std::string aMessage) : x509_ErrMessage(aMessage){}
    const char* Cert::Exception::what() const noexcept{ return x509_ErrMessage.c_str(); }


