#include <string>
#include <cert/x509.hpp>

using namespace Cert;
using namespace x509;

X509_REQ* x509Req_New();

X509_REQ* x509Req_ReadFromFile(std::string fileName);
X509_NAME* x509Req_GetSubjectName(X509_REQ* req);

X509_EXTENSION* x509Req_GetSubjectAltName(X509_REQ* req);
//=====================================

X509* Cert_ReadFromFile(std::string fileName);
std::string Cert_PrintToStrin();
std::string Cert_GetIssuerNameAsOneLine(X509* cert);
std::string Cert_GetSubjectNameAsOneLine(X509* cert);
boost::optional<std::string> Cert_GetSubjectAlternativeNamesAsString(X509* cert);

Version Cert_GetVersion(X509* cert);


NameSpecification Cert_GetIssuerNameAsSpec(X509* cert);
X509_NAME* Cert_GetIssuerName(X509* cert);

NameSpecification Cert_GetSubjectNameAsSpec(X509* cert);
X509_NAME* Cert_GetSubjectName(X509* cert);
X509_EXTENSION* Cert_GetSubjectAltName(X509* cert);
STACK_OF(X509_EXTENSION)* Cert_GetExtensions(X509* cert);


ASN1_INTEGER* Cert_GetSerialNumber(X509* cert);
ASN1_TIME* Cert_GetNotBefore(X509* cert);
ASN1_TIME* Cert_GetNotAfter(X509* cert);


EVP_PKEY* Cert_GetPublicKey(X509* cert);
X509* Cert_FromPEMString(std::string pem);


X509* getCACert();

EVP_PKEY* getCAPKey();

X509_EXTENSION* Extension_create(X509* cacert, X509* cert, ::Cert::x509::ExtNid nid, std::string specification);
ExtDescriptions Cert_extensionsAsDescription(X509* cert);

EVP_PKEY* Rsa_Generate();

EVP_PKEY* PKey_ReadPrivateKeyFrom(std::string fileName, std::string password);

EVP_PKEY* PKey_ReadPrivateKeyFrom(std::string fileName);

EVP_PKEY* PKeyPrivate_FromPEMString(std::string pem);

//====================================================================================================


ExtDescriptions ExtensionStack_asDescriptions(STACK_OF(X509_EXTENSION)* stack);

NidDescriptor Nid_GetDescriptor(::Cert::x509::ExtNid nid);

NidDescriptor Nid_DescriptorFromObject(ASN1_OBJECT* obj);



AlternativeDNSNameSet Cert_GetSubjectAlternativeDNSNames(X509* cert);

ExtDescriptions Cert_extensionsAsDescription(X509* cert);

AlternativeDNSNameSet intersection(const AlternativeDNSNameSet &set1, const AlternativeDNSNameSet &set2);
AlternativeDNSNameSet Cert_GetSubjectAlternativeDNSNames(X509* cert);
std::string PKey_PublicKeyAsPEMString(EVP_PKEY* pkey);













static bool verifyInterceptorCert(Store& store, HostId host);
 * @param new_pkey_pair     EVP_PKEY*               generated from EVP_PKEY* new_pkey = x509Rsa_Generate();
 );

X509_NAME* Cert_GetSubjectName(X509* cert);

X509_NAME* Cert_GetIssuerName(X509* cert);

ASN1_INTEGER* Cert_GetSerialNumber(X509* cert);
ASN1_TIME* Cert_GetNotBefore(X509* cert);

ASN1_TIME* Cert_GetNotAfter(X509* cert);

STACK_OF(X509_EXTENSION)* Cert_GetExtensions(X509* cert);

boost::optional<X509_EXTENSION*> Cert_GetSubjectAltName(X509* cert);

size_t BIO_mem_length(BIO* bio);
Certificate();
Certificate(boost::filesystem::path pem_file);
Certificate(std::string pem_string);
Certificate(X509* x509_cert);
~Certificate();
X509* native();

::Cert::x509::NameSpecification getSubjectNameAsSpec();



::Cert::x509::NameSpecification getIssuerNameAsSpec();



::Cert::x509::Version getVersion();



EvpPKey getPublicKey();




AlternativeDNSNameSet getSubjectAlternativeDNSNames();
::Cert::x509::ExtDescriptions getExtensionsAsDescription();






Identity();
~Identity();
Identity(X509* certificate, EVP_PKEY* keyptr);
Identity(const Cert::Certificate& certificate, const Cert::EvpPKey& keyPair);
Cert::Certificate getCertificate();
// std::string getCertificatePEM();
Cert::EvpPKey getEvpPKey();
// std::string getEvpKeyPEM();
X509* getX509();
EVP_PKEY* getEVP_PKEY();


NameSpecification  Name_getSpec(X509_NAME* name);
X509_NAME*  Name_fromSpec(NameSpecification entries);

static StoreSPtr makeEmpty(Path storeDirPath);
static StoreSPtr makeWithCA(Path storeDirPath, Path jsonSpecificationFile);
static StoreSPtr load(Path storeDirPath);





LocatorSPtr getLocator();
AuthoritySPtr getAuthority();
Cert::Identity forgeHostIdentity(HostId host);
Cert::Identity forgeHostIdentity(X509* original_certificate);
Store(Path dirPath);








Exception(std::string message);

Builder(Authority& certAuth);
~Builder();
::Cert::Identity buildMitmIdentity(std::string required_common_name, Cert::Certificate& original_cert);
CertBundle CertChain_FromString(std::string pem_string);
CertBundle CertChain_FromFile(std::string filename);
CertChain CertChain_FromStack(STACK_OF(X509)* cert_stack);
CertChain CertChain_empty();














Chain();
~Chain();
Chain(std::vector<std::string>& vec);
Chain(boost::filesystem::path pem);
Chain(std::string pem);
push_back(std::string pem);

Chain removeAllSubjectsMatching(std::string name_to_remove);
Chain removeSubject(std::string subName);






EvpPKey();
EvpPKey(boost::filesystem::path filePath, std::string password);
EvpPKey(std::string pem);
EvpPKey(EVP_PKEY* pkey);
~EvpPKey();
EVP_PKEY* Rsa_Generate();
EVP_PKEY* native();





