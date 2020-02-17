#include <cstdlib>
#include <iostream>
#include <map>
#include <vector>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <boost/filesystem/path.hpp>
#include "x509_error.hpp"
#include "x509_pkey.hpp"
#include "x509_req.hpp"
#include "x509_extension.hpp"

#define PKEY_FILE "privkey.pem"
#define REQ_FILE "newreq.pem"
#define ENTRY_COUNT 6

const std::string fixtures_directory = "/Users/rob/MyCurrentProjects/Pixie/MarvinCpp/experiments/openssl-exs/fixtures";
const std::string pkey_file = fixtures_directory + "/" + "ex5-pkey.pem";
const std::string req_file = fixtures_directory + "/" + "ex5-req.pem";
const std::string pkeyPassphrase("blackwellapps");
struct entry
{
  char *key;
  char *value;
};

typedef struct key_value {
    std::string key;
    std::string value;
} KeyValue;

KeyValue makeEntry(std::string key, std::string value)
{
    KeyValue ent;
    ent.key = key;
    ent.value = value;
    return ent;
}
std::map<std::string, std::string> subjectValues = {
  {"countryName", "US"},
  {"stateOrProvinceName", "VA"},
  {"localityName", "Fairfax"},
  {"organizationName", "Zork.org"},
  {"organizationalUnitName", "Server Division"},
  {"commonName", "Server 36, Engineering"},
};

std::vector<std::string> subjectKeys = {
  "countryName",
  "stateOrProvinceName",
  "localityName",
  "organizationName",
  "organizationalUnitName",
  "commonName",
};

KeyValue keyValues[] = {
  {"countryName", "US"},
  {"stateOrProvinceName", "VA"},
  {"localityName", "Fairfax"},
  {"organizationName", "Zork.org"},
  {"organizationalUnitName", "Server Division"},
  {"commonName", "Server 36, Engineering"},
};

struct entry entries[ENTRY_COUNT] = {
  {"countryName", "US"},
  {"stateOrProvinceName", "VA"},
  {"localityName", "Fairfax"},
  {"organizationName", "Zork.org"},
  {"organizationalUnitName", "Server Division"},
  {"commonName", "Server 36, Engineering"},
};

std::map<std::string, std::string> extensionValues = {
    {SN_subject_alt_name,"DNS:another.blackwell.com,DNS:another2.blackwell.com" }
};

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, std::string value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, (char*)value.c_str());
    if (!ex)
        return 0;
    sk_X509_EXTENSION_push(sk, ex);

    return 1;
}
/**
* making a certificate signing request
*   -   generate a public/private key pair unique to this request
*   -   create an empty request object and set the following values
*       -   the requests public key
*       -   the requestors subjectName
*       -   extensions, as required - more on this latter
*   -   select digest algorithm
*   -   sign request with selected digest and requests PRIVATE key
*   -   write to files
*       -   the request data
*       -   the request's private key, possibly with a password or passphrase
*/

X509_REQ* buildRequest(EVP_PKEY* pkey, std::map<std::string, std::string> subjectName, std::map<std::string, std::string> extensions)
{
    X509_REQ *req;
    EVP_MD *digest = nullptr;


    req = x509Req_New();
    x509Req_SetPublicKey(req, pkey);
    x509Req_SetSubjectName(req, subjectValues);
    ExtensionStack stk = x509ExtensionStack_New();

#ifdef SN_EXT
    x509ExtensionStack_AddBySN(stk, SN_subject_alt_name, std::string("DNS:another.blackwell.com,DNS:another2.blackwell.com") );
#else
    x509ExtensionStack_AddByNID(stk, NID_subject_alt_name, std::string("DNS:another.blackwell.com,DNS:another2.blackwell.com"));
#endif

    x508Req_AddExtensions(req, stk);

    digest = (EVP_MD*)EVP_sha256();
   
    x509Req_Sign(req, pkey, digest);
    return req;
}

int
main (int argc, char *argv[])
{
    X509_REQ *req;
    EVP_PKEY *pkey;
    std::string password("blackwellapps");
    auto pkey_file = (boost::filesystem::path(__FILE__).parent_path() / "pkey.pem").native();
    auto req_file = (boost::filesystem::path(__FILE__).parent_path() / "req.pem").native();
//    std::string req_file = req_path.native();
    
    OpenSSL_add_all_algorithms ();
    ERR_load_crypto_strings ();
    ERR_load_BIO_strings();
    ERR_load_ERR_strings();

    pkey = x509Rsa_Generate();
    req = buildRequest(pkey, subjectValues, extensionValues);
    
    x509Req_WriteToFile(req, req_file);
    x509PKey_WritePrivateKey(pkey,  pkey_file, password);

    EVP_PKEY_free (pkey);
    X509_REQ_free (req);
    return 0;
}
