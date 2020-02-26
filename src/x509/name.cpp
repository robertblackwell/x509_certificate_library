//
//  x509_name.cpp
//  x509
//
//  Created by ROBERT BLACKWELL on 11/8/17.
//  Copyright © 2017 ROBERT BLACKWELL. All rights reserved.
//
#include <cert/x509.hpp>

std::string Cert::x509::Name_AsOneLine(X509_NAME* name)
{
    BIO* out_bio = BIO_new(BIO_s_mem());
    X509_NAME_print(out_bio, name, 0);
    char* ret = (char *) malloc(BIO_mem_length(out_bio) + 1);
    if (NULL == ret) {
        BIO_free(out_bio);
        X509_TRIGGER_ERROR("malloc failed in Cert::x509::Name_asOneLine");
    }

    memset(ret, 0, BIO_mem_length(out_bio) + 1);
    BIO_read(out_bio, ret, (int)BIO_mem_length(out_bio));
    std::string s(ret);
    BIO_free(out_bio);
    return s;
}

std::string Cert::x509::Name_AsMultiLine(X509_NAME* name)
{
    BIO* out_bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(out_bio, name, 0, XN_FLAG_MULTILINE);
    char* ret = (char *) malloc(BIO_mem_length(out_bio) + 1);
    if (NULL == ret) {
        BIO_free(out_bio);
        X509_TRIGGER_ERROR("malloc failed in Cert::x509::Name_asOneLine");
    }
    memset(ret, 0, BIO_mem_length(out_bio) + 1);
    BIO_read(out_bio, ret, (int)BIO_mem_length(out_bio));
    std::string s(ret);
    BIO_free(out_bio);
    return s;
}
Cert::x509::NameSpecification
Cert::x509::Name_getSpec(X509_NAME* name)
{
    Cert::x509::NameSpecification ret;
    #ifdef NOT_111d
    int num = sk_X509_NAME_ENTRY_num(name->entries);
    for( int i = 0; i < num; i++) {
        auto entry = sk_X509_NAME_ENTRY_value(name->entries, i);
        Cert::x509::NidDescriptor desc = Cert::x509::Nid_GetDescriptor(OBJ_obj2nid(entry->object));
        unsigned char* out;
        int len = ASN1_STRING_to_UTF8(&out, entry->value);
        std::string s((char*)out, len);
        ret[desc.nid] = s;
    }
    #else
    int num = X509_NAME_entry_count(name);
    for( int i = 0; i < num; i++) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
        auto asn1_obj = X509_NAME_ENTRY_get_object(entry);
        auto nid = OBJ_obj2nid(asn1_obj);
        Cert::x509::NidDescriptor desc = Cert::x509::Nid_GetDescriptor(nid);
        auto asn1_string = X509_NAME_ENTRY_get_data(entry);
        unsigned char* out;
        int len = ASN1_STRING_to_UTF8(&out, asn1_string);
        std::string s((char*)out, len);
        ret[desc.nid] = s;
    }
    #endif
    return ret;
}


void Cert::x509::Name_AddEntryByNID(X509_NAME* name, int nid, std::string value)
{
    X509_NAME_ENTRY *ent;
    auto sn = OBJ_nid2sn(nid);
    if (sn == nullptr) {
        X509_TRIGGER_ERROR("Cert::x509::Name_AddEntryByNID - undefined nid");
    }
    unsigned char* v = (unsigned char*) value.c_str();
    ent = X509_NAME_ENTRY_create_by_NID ((X509_NAME_ENTRY**)NULL, nid, MBSTRING_ASC, v, -1);

    if (! ent )
        X509_TRIGGER_ERROR("Error creating Name entry from NID");
    
    if (X509_NAME_add_entry (name, ent, -1, 0) != 1)
        X509_TRIGGER_ERROR("Error adding entry to Name");

}

X509_NAME* Cert::x509::Name_fromSpec(Cert::x509::NameSpecification entries)
{
    X509_NAME* name = X509_NAME_new();
    for (auto const& x : entries) {
        int nid = x.first;
        unsigned char* v = (unsigned char*) x.second.c_str();
        X509_NAME_ENTRY* ent = X509_NAME_ENTRY_create_by_NID((X509_NAME_ENTRY**)nullptr, nid, MBSTRING_ASC, v, -1);
        if (! ent )
            X509_TRIGGER_ERROR("Error creating Name entry from NID");
        
        if (X509_NAME_add_entry (name, ent, -1, 0) != 1)
            X509_TRIGGER_ERROR("Error adding entry to Name");
        }
    return name;
}

