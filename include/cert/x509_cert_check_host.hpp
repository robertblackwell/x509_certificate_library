#ifndef cert_guard_x509_cert_check_host_hpp
#define cert_guard_x509_cert_check_host_hpp
#include <cstdlib>
#include <string>
#include <cert/x509.hpp>
namespace Cert {
namespace x509 { 
///
/// tess a host name such as "google.com" against a string of names like
/// "DNS:*.google.com, DNS: *.another.google.com"
///
bool Cert_checkHostInAltnameString(std::string host, std::string altNames);

///
/// a group of functions that check the host name against 
/// the CN and DNS names in the subjectAltName extension
/// NOT a replacement for openssl's host verify - informational purposes only
///
bool Cert_checkHost(X509* cert_x509, std::string& host);
} // namespace
} // namespace

#endif