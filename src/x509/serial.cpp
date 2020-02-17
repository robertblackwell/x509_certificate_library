//
//  x509_serial.cpp
//  x509
//
//  Created by ROBERT BLACKWELL on 11/8/17.
//  Copyright © 2017 ROBERT BLACKWELL. All rights reserved.
//

#include "x509.hpp"

std::string Cert::x509::Serial_AsString(ASN1_INTEGER* serial)
{
    BIO* out_bio = BIO_new(BIO_s_mem());
    TS_ASN1_INTEGER_print_bio(out_bio, serial);
    char* ret = (char *) malloc(BIO_mem_length(out_bio) + 1);
    if (NULL == ret) {
        BIO_free(out_bio);
        X509_TRIGGER_ERROR("malloc failed in x509Time_AsString");
    }

    memset(ret, 0, BIO_mem_length(out_bio) + 1);
    BIO_read(out_bio, ret, (int)BIO_mem_length(out_bio));
    std::string s(ret);
    BIO_free(out_bio);
    return s;
}
