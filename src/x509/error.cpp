//
//  error.cpp
//  openssl_10_6
//
//  Created by ROBERT BLACKWELL on 10/26/17.
//  Copyright © 2017 Blackwellapps. All rights reserved.
//

#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <malloc.h>
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
    // char buf[100001];
    std::string message(msg);
    std::stringstream messageStream;
    
    messageStream <<  "Error in function: " << func << " file: " << file << " at lineNo: " << lineno << std::endl << "Message: [" << message << "]" ;
    
    long e = ERR_peek_last_error();
    const char* err_str = ERR_reason_error_string(e);
    std::string open_ssl_message = "NO OPENSSL ERROR";
    if (err_str == NULL) {

    } else {
        open_ssl_message = std::string(err_str);
    }
    messageStream << std::endl << "OpenSSL error message is : [" << open_ssl_message <<"]" << std::endl;
//    ERR_print_errors_fp (stderr);
    throw Cert::Exception(messageStream.str());
}
using namespace Cert;
    Cert::Exception::Exception(std::string aMessage) : x509_ErrMessage(aMessage){}
    const char* Cert::Exception::what() const noexcept{ return x509_ErrMessage.c_str(); }


