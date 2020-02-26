#ifndef cert_x509_x509_include_hpp
#define cert_x509_x509_include_hpp

/**
 * A common header file for all x509 cpp files.
 */

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <map>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <boost/unordered_set.hpp>

#include <cert/version_check.hpp>
#include <cert/constants.hpp>


#include <cert/x509_types.hpp>
#include <cert/x509_nid.hpp>

#include <cert/x509_cert.hpp>
#include <cert/x509_error.hpp>
#include <cert/x509_pkey.hpp>
#include <cert/x509_ext.hpp>
#include <cert/x509_name.hpp>
#include <cert/x509_serial.hpp>
#include <cert/x509_time.hpp>
#include <cert/x509_conf.hpp>
#include <cert/x509_req.hpp>
#include <cert/x509_identity.hpp>


#endif /* x509_pkey_hpp */
