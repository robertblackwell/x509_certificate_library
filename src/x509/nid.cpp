//
//  x509_nid.cpp
//  cert_test
//
//  Created by ROBERT BLACKWELL on 11/9/17.
//  Copyright © 2017 ROBERT BLACKWELL. All rights reserved.
//

#include "x509.hpp"

bool Cert::x509::NidDescriptor::operator !()
{
    return !valid;
}
Cert::x509::NidDescriptor
Cert::x509::Nid_DescriptorFromObject(ASN1_OBJECT* obj)
{
    std::string obj_name;
    Cert::x509::NidDescriptor desc;
    unsigned nid = OBJ_obj2nid(obj);
    if (nid == NID_undef) {
        // make a Cert::x509::NidDescriptor for an NID_undef
        // no lookup found for the provided OID so nid came back as undefined.
        char extname[10000];
        OBJ_obj2txt(extname, 100000, (const ASN1_OBJECT *) obj, 1);
        obj_name = std::string(extname);
        desc.nid = nid;
        desc.short_name = obj_name;
        desc.long_name  = obj_name;
        desc.valid = true;
    } else {
        desc = Cert::x509::Nid_GetDescriptor(nid);
    }
    return desc;
}
Cert::x509::NidDescriptor
Cert::x509::Nid_GetDescriptor(Cert::x509::ExtNid nid)
{
    Cert::x509::NidDescriptor tmp;
    int nid_int = static_cast<int>(nid);//redundant it already is an int
    auto obj = OBJ_nid2obj(nid_int);
    if (obj == nullptr) {
        tmp.valid = false;
        X509_TRIGGER_ERROR("Cert::x509::Nid_GetDescriptor - invalid nid");
    } else {
        tmp.valid = true;
        tmp.nid = nid_int;
        tmp.short_name = std::string(OBJ_nid2sn(nid_int));
        tmp.long_name = std::string(OBJ_nid2ln(nid_int));
        int max_buffer = 80; // based on comments in the docs for 1.1.1d
        char buffer[max_buffer];
        int len = OBJ_obj2txt(buffer, max_buffer, obj, 1);
        tmp.oid_numeric = std::string(buffer, len);
        assert(len < 80);
        #ifdef NOT_111d
        const unsigned char* p = obj->data;
        char* mem = (char*)malloc(len + 1);
        memcpy(mem, p, len);
        char* ptr = buffer;
        int hex_len = 0;
        for(int i = 0; i< len; i++) {
            const char* s = (i == 0) ? "{" : ",";
            int c = (int)mem[i];
            int new_len = sprintf(ptr, "%s 0x%2x", s, c);
            ptr += new_len;
            hex_len  += new_len;
        }
        tmp.oid_hex = std::string(buffer) + "}";
        #else
        tmp.oid_hex = std::string("xxx:aaa:bbb:ccc - 1.1.1d makes this hard");
        #endif
    }
    return tmp;
}
