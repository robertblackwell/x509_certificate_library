//
//  handshake_result.cpp
//  x509
//
//  Created by ROBERT BLACKWELL on 11/19/17.
//  Copyright © 2017 ROBERT BLACKWELL. All rights reserved.
//

#include <iostream>
#include <set>
#include <boost/unordered_set.hpp>

#include "cert_handshaker.hpp"

void report_fail(std::string msg, const char* file, int line)
{
    std::cout << "FAILED " << msg  << " in file: " << file << " at line:" << line  << std::endl;
}
void report_success(std::string msg)
{
//    std::cout <<  msg << std::endl;
}
using namespace Cert;
using namespace Handshaker::Result;

#define REPORT_SUCCESS(msg) \
    report_success(msg)

#define REPORT_FAIL(msg) \
    report_fail(msg, __FILE__, __LINE__)
//
// Results from tests are encapsulated in Handshaker::Result::value and are inspected  for the correct
// result by a function of the form
//
//      Handshaker::Result::validateXXXXX(TestResult::value res, ....)
//
    Handshaker::Result::Value Handshaker::Result::makeValue(
        bool b,
        std::string s,
        Handshaker::Result::NameSet altnames,
        std::string pem,
        std::vector<std::string> pem_chain
        ) {
        Handshaker::Result::Value x;
        x.m_success = b;
        x.m_failed_where = s;
        x.m_altNames = altnames;
        x.m_pem = pem;
        x.m_pem_chain = pem_chain;
        return x;
    }
    
    bool Handshaker::Result::validateSuccess( Handshaker::Result::Value res, std::string msg)
    {
        if (! res.m_success ) {
            REPORT_FAIL("expectSuccess failed " + msg );
            return false;
        } else {
            REPORT_SUCCESS("Test Passed - success " + msg);
            return true;
        }
    }
    bool Handshaker::Result::validateFailInHandshake( Value res, std::string msg)
    {
        if ( res.m_success ) {
            REPORT_FAIL("expectFailInHandshake failed got success " + msg);
            return false;
        } else if ( !res.m_success && (res.m_failed_where != where_handshake) ) {
            REPORT_FAIL("expectFailInHandshake failed not in handshake but in  " + res.m_failed_where + " "  + msg);
            return false;
        } else {
            REPORT_SUCCESS("Test Passed - failed handshake " + msg);
            return true;
        }
    }
    
    Handshaker::Result::NameSet Handshaker::Result::intersection(const Handshaker::Result::NameSet &set1, const Handshaker::Result::NameSet &set2)
    {
        if(set1.size() <= set2.size())
        {
            Handshaker::Result::NameSet iSet;
            boost::unordered_set<std::string>::iterator it;
            for(it = set1.begin(); it != set1.end();++it){
                if(set2.find(*it) != set2.end()){
                    iSet.insert(*it);
                }
            }
            return iSet;
        }
        else
        {
            return intersection(set2,set1);
        }
    }
    
    bool Handshaker::Result::validateSubjectAltNames( Handshaker::Result::Value res, Handshaker::Result::NameSet names, std::string msg)
    {
        if( ! res.m_success ) {
            REPORT_FAIL ("verifySubjectAltNames failed " + msg);
            return false;
        }
        else if( res.m_altNames.size() != names.size() ) {
            REPORT_FAIL ("verifySubjectAltNames names mismatch(size) " + msg);
            return false;
        }
        else if( res.m_altNames != names) {
            REPORT_FAIL ("verifySubjectAltNames names mismatch(== test) " + msg);
            return false;
        }
        else {
            auto tmpSet = intersection(res.m_altNames, names);
//        if( res._altNames.size() != tmpSet.size() )
//            throw "verifySubjectAltNames names mismatch(intersection) " + msg;
            REPORT_SUCCESS("Test Passed - subject alternate names " + msg);
            return true;
        }
    }

    std::string Handshaker::Result::getPem(Handshaker::Result::Value res)
    {
        return res.m_pem;
    }
