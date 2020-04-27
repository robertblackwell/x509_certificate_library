#include <string>
#include <vector>
#include <boost/optional.hpp>
#include <cert/x509.hpp>

///
/// gets the DNS alt names from a certificate as a list std::strings 
///
boost::optional<std::vector<std::string>> Cert::x509::Cert_altNames(X509* server_cert) {
    int i;
    int san_names_nb = -1;
    STACK_OF(GENERAL_NAME) *san_names = NULL;
    std::vector<std::string> res;
    // Try to extract the names within the SAN extension from the certificate
    auto temp = X509_get_ext_d2i((X509 *) server_cert, NID_subject_alt_name, NULL, NULL);
    san_names = (STACK_OF(GENERAL_NAME) *)temp;
    if (san_names == NULL) {
        return boost::none;
    }
    san_names_nb = sk_GENERAL_NAME_num(san_names);

    // Check each name within the extension
    for (i=0; i<san_names_nb; i++) {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

        if (current_name->type == GEN_DNS) {
            // Current name is a DNS name, let's check it
            char *dns_name = (char *) ASN1_STRING_get0_data(current_name->d.dNSName);

            // Make sure there isn't an embedded NUL character in the DNS name
            if ((size_t)ASN1_STRING_length(current_name->d.dNSName) != strlen(dns_name)) {
                throw "MalformedCertificate";
                break;
            } else { // Compare expected hostname with the DNS name
                res.push_back(std::string(dns_name));
            }
        }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    return res;
}
