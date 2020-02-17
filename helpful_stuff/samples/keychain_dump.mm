+ (NSURL *)createCertsFileInDirectory:(NSURL *)directory {
    NSString *outPath = [directory path];
    if (!outPath) {
        return nil;
    }
    outPath = [outPath stringByAppendingPathComponent:@"allcerts.pem"];
    NSURL * outURL = [NSURL fileURLWithPath:outPath];
    SecKeychainRef keychain;
    if (SecKeychainOpen("/System/Library/Keychains/SystemCACertificates.keychain", &keychain) != errSecSuccess) {
        return nil;
    }
    CFMutableArrayRef searchList = CFArrayCreateMutable(kCFAllocatorDefault, 1, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(searchList, keychain);
    CFTypeRef keys[] = { kSecClass, kSecMatchLimit, kSecAttrCanVerify, kSecMatchSearchList };
    CFTypeRef values[] = { kSecClassCertificate, kSecMatchLimitAll, kCFBooleanTrue, searchList };
    CFDictionaryRef dict = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef results;
    OSStatus status = SecItemCopyMatching(dict, &results);
    CFArrayRef arr = results;
    NSLog(@"total item count = %ld", CFArrayGetCount(arr));
    CFRelease(dict);
    CFRelease(searchList);
    CFRelease(keychain);
    if (status != errSecSuccess) {
        return nil;
    }
    CFDataRef certsData;
    status = SecItemExport(results, kSecFormatPEMSequence, kSecItemPemArmour, NULL, &certsData);
    CFRelease(results);
    if (status != errSecSuccess) {
        return nil;
    }
    NSData *topLevelData = (NSData *) CFBridgingRelease(certsData);
    if (![topLevelData writeToURL:outURL atomically:YES]) {
        return nil;
    }
    return outURL;
}