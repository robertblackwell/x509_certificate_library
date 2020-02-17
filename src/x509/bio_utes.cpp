//
//  bio_utes.cpp
//  x509
//
//  Created by Robert BLACKWELL on 2/8/20.
//  Copyright © 2020 ROBERT BLACKWELL. All rights reserved.
//
#include <string>
#include "x509.hpp"

std::string BIO_to_string(BIO* bio) {
    BUF_MEM* bmp;
    BIO_get_mem_ptr(bio, &bmp);
    std::string result(bmp->data, bmp->length);
    return result;
}
size_t BIO_mem_length(BIO* bio) {
    BUF_MEM* bmp;
    BIO_get_mem_ptr(bio, &bmp);
    return bmp->length;
}
