#include <ostream>
#include <regex>

#include <cert/cert.hpp>
#include <cert/cert_chain.hpp>

namespace Cert {

class Chain::Impl
{
public:
    std::vector<std::string>    m_certs;
    Impl(std::vector<std::string> certs)
    {
        m_certs = certs;
    }
    ~Impl()
    {
    }
};
Chain::Chain()
{

}

Chain::~Chain()
{

}
Chain::Chain(std::vector<std::string>& vec)
{
    m_impl_sptr = std::make_shared<Impl>(vec);
}
Chain::Chain(boost::filesystem::path pem)
{
    m_impl_sptr = std::make_shared<Impl>(x509::CertChain_FromFile(pem.native()));
}
Chain::Chain(std::string pem)
{
    m_impl_sptr = std::make_shared<Impl>(x509::CertChain_FromString(pem));
}

void
Chain::push_back(std::string pem)
{
    m_impl_sptr->m_certs.push_back(pem);
}
std::string
Chain::lastIssuer()
{
    std::string pem = m_impl_sptr->m_certs.back();
    X509* chain_last_cert = Cert::x509::Cert_FromPEMString(pem);
    auto spec = Cert::x509::Cert_GetIssuerNameAsSpec(chain_last_cert);
    std::string last_issuer_name = spec[NID_commonName];
    X509_free(chain_last_cert);
    return last_issuer_name;
}

Chain
Chain::removeAllSubjectsMatching(std::string pattern)
{
    std::vector<std::string> res;
    #if 0
    std::string pem =host_chain.back();
    X509* chain_last_cert = Cert::x509::Cert_FromPEMString(pem);
    auto chain_last_cert_issuer_name = Cert::x509::Cert_GetIssuerName(chain_last_cert);
    auto spec = Cert::x509::Name_getSpec(chain_last_cert_issuer_name);
    std::string chain_last_cert_common_name = spec[NID_commonName];
    #endif
    std::cout << "host_chain last issuer" << pattern << std::endl;
    
    for(const std::string& pem: m_impl_sptr->m_certs) {
        X509* x = Cert::x509::Cert_FromPEMString(pem);
        // std::string sn1l = Cert::x509::Cert_GetSubjectNameAsOneLine(x);
        // std::string snml = Cert::x509::Cert_GetSubjectNameAsMultiLine(x);
        auto spec = Cert::x509::Cert_GetSubjectNameAsSpec(x);
        std::string subject_common_name = spec[NID_commonName];
        if (std::regex_match (subject_common_name, std::regex(pattern))) {
            std::cout << "\t bundle cert subj name: " << subject_common_name << " omitted" << std::endl;
        } else {
            res.push_back(std::string(pem));
        }
//        std::cout << pattern << "  " << subject_common_name << std::endl;
        X509_free(x);
    }
    Cert::Chain ch(res);
    return ch;

}


Chain
Chain::removeSubject(std::string name_to_remove)
{
    std::vector<std::string> res;
    #if 0
    std::string pem =host_chain.back();
    X509* chain_last_cert = Cert::x509::Cert_FromPEMString(pem);
    auto chain_last_cert_issuer_name = Cert::x509::Cert_GetIssuerName(chain_last_cert);
    auto spec = Cert::x509::Name_getSpec(chain_last_cert_issuer_name);
    std::string chain_last_cert_common_name = spec[NID_commonName];
    #endif
    std::cout << "host_chain last issuer" << name_to_remove << std::endl;
    
    for(const std::string& pem: m_impl_sptr->m_certs) {
        X509* x = Cert::x509::Cert_FromPEMString(pem);
        std::string sn1l = Cert::x509::Cert_GetSubjectNameAsOneLine(x);
        std::string snml = Cert::x509::Cert_GetSubjectNameAsMultiLine(x);
        auto spec = Cert::x509::Cert_GetSubjectNameAsSpec(x);
        std::string subject_common_name = spec[NID_commonName];
        if (name_to_remove == subject_common_name) {
            std::cout << "\t bundle cert subj name: " << subject_common_name << " omitted" << std::endl;

        } else {
            res.push_back(std::string(pem));
        }
        std::cout << name_to_remove << "  " << subject_common_name << std::endl;
    }
    Cert::Chain ch(res);
    return ch;

}
void Chain::writeAnnotated(boost::filesystem::path filePath, std::string header)
{
    std::ofstream outfile(filePath.native());
    outfile << header << std::endl;
    outfile << toPEMString() << std::endl;
    outfile.close();

}
void Chain::writePEM(boost::filesystem::path filePath)
{
    std::ofstream outfile(filePath.native());
    outfile << toPEMString();
    outfile.close();
}
std::string Chain::toPEMString()
{
    std::stringstream outs ;
    for(const std::string& pem: m_impl_sptr->m_certs) {
        X509* x = Cert::x509::Cert_FromPEMString(pem);
        // std::string sn1l = Cert::x509::Cert_GetSubjectNameAsOneLine(x);
        // std::string snml = Cert::x509::Cert_GetSubjectNameAsMultiLine(x);
        auto sn_spec = Cert::x509::Cert_GetSubjectNameAsSpec(x);
        std::string cert_common_name = sn_spec[NID_commonName];
        
        outs << cert_common_name << std::endl;
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunused-variable"
        for(auto const c : cert_common_name) {
            outs << "=";
        }
        #pragma clang diagnostic pop
        outs << std::endl;
        outs << pem << std::endl;
        X509_free(x);
    }
    return outs.str();
}

void
Chain::print(boost::filesystem::path filePath)
{
    std::ofstream outfile(filePath.native());
    outfile << printToString() << std::endl;
    outfile.close();
}
void
Chain::print()
{
    std::cout << printToString() << std::endl;
}
/**
* Writes a CertBundle to a string, adds a block of header text that annotates each
* certificate with the subject common name
* @param filename - of file to write to, full path
* @param bundle - a CertBundle instance containing the certificates to write
* @return void
*/
std::string Chain::printToString()
{
    std::stringstream outs ;
    for(const std::string& pem: m_impl_sptr->m_certs) {
        X509* x = Cert::x509::Cert_FromPEMString(pem);
        std::string sn1l = Cert::x509::Cert_GetSubjectNameAsOneLine(x);
        std::string snml = Cert::x509::Cert_GetSubjectNameAsMultiLine(x);
        auto sn_spec = Cert::x509::Cert_GetSubjectNameAsSpec(x);
        std::string cert_common_name = sn_spec[NID_commonName];
        
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunused-variable"
        outs << cert_common_name << std::endl;
        for(auto const c : cert_common_name) {
            outs << "=";
        }
        #pragma clang diagnostic pop

        outs << std::endl;
        std::string s = x509::Cert_PrintToString(x);
        X509_free(x);
//        outs << pem << std::endl;
    }
    return outs.str();
}
} //namespace Cert

