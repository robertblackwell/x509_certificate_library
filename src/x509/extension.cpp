//
//  x509_extension.cpp
//  req_test
//
//  Created by ROBERT BLACKWELL on 10/26/17.
//  Copyright © 2017 Blackwellapps. All rights reserved.
//
#include <regex>
#include <cert/x509.hpp>


void Cert::x509::ExtensionStack_AddByNID(STACK_OF(X509_EXTENSION) *sk, Cert::x509::ExtNid extid, std::string value)
{
    X509_EXTENSION *ex;
    int nid = static_cast<int>(extid); //redundant it already is an int
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, (char*)value.c_str());
    if (!ex)
        X509_TRIGGER_ERROR("could not create extensions with NID");
    sk_X509_EXTENSION_push(sk, ex);
}

std::string Cert::x509::Extension_ValueAsString(X509_EXTENSION* ext)
{
    BIO* out_bio = BIO_new(BIO_s_mem());
    X509V3_EXT_print(out_bio, ext, 0, 0);
    char* ret = (char *) malloc(BIO_mem_length(out_bio) + 1);
    if (NULL == ret) {
        BIO_free(out_bio);
        X509_TRIGGER_ERROR("malloc failed in Cert::x509::Name_asOneLine");
    }
    memset(ret, 0, BIO_mem_length(out_bio) + 1);
    BIO_read(out_bio, ret, (int)BIO_mem_length(out_bio));
    std::string s(ret);
    std::replace( s.begin(), s.end(), '\n', ',');
    if(s.back() == ',')
        s.erase(s.size()-1);
    if(s[0] == ',')
        s.erase(0,1);
    s = std::regex_replace(s, std::regex(":,"), ":");
    BIO_free(out_bio);
    return s;
}

X509_EXTENSION* Cert::x509::Extension_create(X509* cacert, X509* cert, Cert::x509::ExtNid nid, std::string specification)
{
    X509V3_CTX ctx;
    X509V3_set_ctx (&ctx, cacert, cert, NULL, NULL, 0);
    int nid_int = nid;
    const char* v = specification.c_str();
    X509_EXTENSION* xt = X509V3_EXT_nconf_nid((CONF*)nullptr, (X509V3_CTX*)&ctx, nid_int, (char*)v);
    if (xt == nullptr) {
        X509_TRIGGER_ERROR("createExtension failed");
    }
    return xt;
}

Cert::x509::ExtDescriptions Cert::x509::ExtensionStack_asDescriptions(STACK_OF(X509_EXTENSION)* stack)
{
    Cert::x509::ExtDescriptions ret;
    auto exts = stack;
    int numexts = sk_X509_EXTENSION_num(exts);

    for( int j = 0; j < numexts ; j++ ) {
        auto entry = sk_X509_EXTENSION_value(exts, j);
        auto ss = Cert::x509::Extension_ValueAsString(entry);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(entry);
        Cert::x509::NidDescriptor desc;
        desc = Cert::x509::Nid_DescriptorFromObject(obj);
        ret[desc.nid] = ss;
    }
    return ret;
}
#pragma mark - not being used
#if 0

std::string Cert::x509::ExtNid_getSN(Cert::x509::ExtNid nid)
{
    int nid_int = static_cast<int>(nid);//redundant it already is an int
    auto res = OBJ_nid2sn(nid_int);
    if (! res)
        X509_TRIGGER_ERROR("Cert::x509::ExtensionId_getSN failed");
    return std::string(res);
}
std::string Cert::x509::ExtNid_getLN(Cert::x509::ExtNid nid)
{
    int nid_int = static_cast<int>(nid);//redundant it already is an int
    auto res = OBJ_nid2ln(nid_int);
    if (! res)
        X509_TRIGGER_ERROR("Cert::x509::ExtensionId_getLN failed");
    return std::string(res);
}
std::string Cert::x509::ExtNid_getOBJ(Cert::x509::ExtNid nid)
{
    return std::string("");
}

void Cert::x509::ExtensionStack_AddBySN(STACK_OF(X509_EXTENSION)* stack, std::string sn_string, std::string inValue)
{
    char* name_cstr = (char*)sn_string.c_str();

    char* value_cstr = (char*) inValue.c_str();

    X509_EXTENSION* ext;
//    char *name = (char*) std::string("subjectAltName").c_str();
//    char *value = (char*) std::string("DNS:splat.zork.org").c_str();
//    if (!(ext = X509V3_EXT_conf (NULL, NULL, name, value)))
//        X509_TRIGGER_ERROR("Error creating subjectAltName extension");

    //
    // please note : is sn_string = "subjectAltName" then value MUST be of the form "DNS:xxxxxx" or
    // some other acceptable for -- see openssl/
    //
    if (!(ext = X509V3_EXT_conf (NULL, NULL, name_cstr, value_cstr)))
        X509_TRIGGER_ERROR("Error creating extension name : " + sn_string + " value: " + value_cstr);

    sk_X509_EXTENSION_push (stack, ext);
}
#endif
#if 0
std::vector<Cert::x509::ExtensionDescriptor>
Cert::x509::ExtensionStack_unpack(STACK_OF(X509_EXTENSION)* stack)
{
    std::vector<Cert::x509::ExtensionDescriptor> ret;
    auto exts = stack;
    int numexts = sk_X509_EXTENSION_num(exts);

    for( int j = 0; j < numexts ; j++ ) {
        auto entry = sk_X509_EXTENSION_value(exts, j);
        auto ss = Cert::x509::Extension_ValueAsString(entry);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(entry);
//        std::string extensionName;
        Cert::x509::NidDescriptor desc;
        desc = Cert::x509::Nid_DescriptorFromObject(obj);
//        unsigned nid = OBJ_obj2nid(obj);
//        if (nid == NID_undef) {
//            // make a Cert::x509::NidDescriptor for an NID_undef
//            // no lookup found for the provided OID so nid came back as undefined.
//            char extname[10000];
//            OBJ_obj2txt(extname, 100000, (const ASN1_OBJECT *) obj, 1);
//            extensionName = std::string(extname);
//            desc.nid = nid;
//            desc.short_name = extensionName;
//            desc.long_name  = extensionName;
//            desc.valid = true;
//        } else {
//            desc = Cert::x509::Nid_GetDescriptor(nid);
//        }
        Cert::x509::ExtensionDescriptor st;
        st.nid_desc = desc;
        st.value = ss;
        ret.push_back(st);
    }
    return ret;
}
#endif
