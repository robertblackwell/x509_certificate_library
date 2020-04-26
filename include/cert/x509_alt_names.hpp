#ifndef cert_x509_alt_names_hpp
#define cert_x509_alt_names_hpp
#include <string>
#include <vector>
#include <boost/optional.hpp>
#include <cert/x509.hpp>

namespace Cert {
namespace x509 {

boost::optional<std::vector<std::string>> Cert_altNames(X509* server_cert); 
} // namespace
} // namespace

#endif