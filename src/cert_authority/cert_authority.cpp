//
//  CertificateAuthority.cpp
//  MarvinCpp
//
//  Created by ROBERT BLACKWELL on 10/25/17.
//  Copyright © 2017 Blackwellapps. All rights reserved.
//
#include <boost/filesystem.hpp>
#include <cert/x509.hpp>
#include <cert/cert_helpers.hpp>
#include <cert/cert_auth_helper.hpp>
#include <cert/cert_authority.hpp>

using namespace Cert;
using namespace Cert::Helpers;

using namespace boost;

//filesystem::path caCertPemFilePath(filesystem::path caDirPath) { return (caDirPath / "cacert.pem"); }
//filesystem::path caPrivateKeyPemPath(filesystem::path caDirPath) { return (caDirPath / "cakey.pem");}
//filesystem::path caPk12FilePath(filesystem::path caDirPath) { return (caDirPath  / "ca.p12");}
//filesystem::path caSelfSignRootCnfPath (filesystem::path caDirPath) { return (caDirPath / "caroot.cnf");}
//filesystem::path caKeyPasswordFilePath(filesystem::path caDirPath) {return (caDirPath / "password.txt");}
//filesystem::path caSerialNumberFilePath(filesystem::path caDirPath) {return (caDirPath / "serial_number.txt");}
//filesystem::path caCnfFilePath (filesystem::path caDirPath) {return (caDirPath / "caroot.cnf");}



AuthoritySPtr Authority::load(boost::filesystem::path caDirPath)
{
    return std::make_shared<Authority>(caDirPath);
}
AuthoritySPtr Authority::create(filesystem::path caDirPath, boost::filesystem::path jsonConfigFilePath)
{
    // This call runs console commands using system() to construct the CA
    // and writes the result into files.
    Cert::AuthHelpers::createCertAuthority(caDirPath, jsonConfigFilePath);
    /// now load the cert authority
    AuthoritySPtr res = Authority::load(caDirPath);
    return res;
}


Cert::Authority::Authority(filesystem::path ca_dir_path) :
    m_ca_dir_path(ca_dir_path.string()),
    m_ca_cert_file_path(caCertPemFilePath(ca_dir_path).string()),
    m_ca_pkey_file_path(caPrivateKeyPemPath(ca_dir_path).string()),
    m_serial_number_file_path(caSerialNumberFilePath(ca_dir_path).string()),
    m_password_file_path(caKeyPasswordFilePath(ca_dir_path).string())
{
    std::string  t_ca_key_password;
    std::ifstream password_file;
    if ( ! Cert::Helpers::fs::is_regular_file(m_password_file_path) ) {
        std::cout << " password file : " << m_password_file_path << std::endl;
        assert(false);
    }
    password_file.open(m_password_file_path);
    password_file >> t_ca_key_password;
    password_file.close();

    m_ca_cert = Cert::x509::Cert_ReadFromFile(m_ca_cert_file_path);
    m_ca_pkey = Cert::x509::PKey_ReadPrivateKeyFrom(m_ca_pkey_file_path, t_ca_key_password);
    
    std::ifstream serialNumberFile;
    serialNumberFile.open(m_serial_number_file_path);
    serialNumberFile >> m_next_serial_number;
    serialNumberFile.close();

}

Cert::Authority::~Authority()
{
    if( m_ca_cert != nullptr) X509_free(m_ca_cert);
    if( m_ca_pkey != nullptr) EVP_PKEY_free(m_ca_pkey);
}
/**
* Get an X509* referencing the Certificate Authorities X509 certificate.
* The object referenced is owned by this instance of CertificateAuthority
* and should not be freed by the caller
*/
X509* Cert::Authority::getCACert()
{
    return m_ca_cert;
}
std::string Cert::Authority::getCaCertPath()
{
    return m_ca_cert_file_path;
}
/**
* Get an EVP_PKEY* referencing the Certificate Authorities private key.
* The object referenced is owned by this instance of CertificateAuthority
* and should not be freed by the caller
*/
EVP_PKEY* Cert::Authority::getCAPKey()
{
    return m_ca_pkey;
}

int Cert::Authority::getNextSerialNumber()
{
    int nxt = m_next_serial_number++;
    return nxt;
}

