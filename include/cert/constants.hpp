#ifndef cert_constants_include_hpp
#define cert_constants_include_hpp
#include <openssl/opensslconf.h>

#ifdef __linux__
    #define CERTLIB_DEFAULT_CERT_FILE_PATH "/etc/ssl/cert.pem" //OPENSSLDIR/cert.pem
#elif __APPLE__
    #define CERTLIB_DEFAULT_CERT_FILE_PATH "/usr/local/etc/openssl@1.1/cert.pem" //OPENSSLDIR/cert.pem
#else
    #error platform not supported
#endif

#include <cert/macros.hpp>
#endif
