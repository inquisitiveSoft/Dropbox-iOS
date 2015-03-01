//
//  DBKeychain.m
//  DropboxSDK
//
//  Created by Brian Smith on 4/5/12.
//  Copyright (c) 2012 Dropbox, Inc. All rights reserved.
//

#import "DBKeychain.h"

#import "DBLog.h"

static NSDictionary *kDBKeychainDict;


@implementation DBKeychain

+ (void)initialize {
	if ([self class] != [DBKeychain class]) return;
	NSString *keychainId = [NSString stringWithFormat:@"%@.dropbox.auth", [[NSBundle mainBundle] bundleIdentifier]];
	kDBKeychainDict = [[NSDictionary alloc] initWithObjectsAndKeys:
					   CFBridgingRelease(kSecClassGenericPassword), (__bridge id)kSecClass,
					   keychainId, (__bridge id)kSecAttrService,
					   nil];
}

+ (NSDictionary *)credentials {
	NSMutableDictionary *searchDict = [NSMutableDictionary dictionaryWithDictionary:kDBKeychainDict];
	[searchDict setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
	[searchDict setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnAttributes];
	[searchDict setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];

	CFTypeRef attrCFDict = nil;
	OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)searchDict, (CFTypeRef *)&attrCFDict);
	
	NSDictionary *attrDict = CFBridgingRelease(attrCFDict);
	NSData *foundValue = [attrDict objectForKey:(__bridge id)kSecValueData];
	
	if (status == noErr && foundValue) {
		return [NSKeyedUnarchiver unarchiveObjectWithData:foundValue];
	} else {
		if (status != errSecItemNotFound) {
			DBLogWarning(@"DropboxSDK: error reading stored credentials (%i)", (int32_t)status);
		}
		return nil;
	}
}

+ (void)setCredentials:(NSDictionary *)credentials {
	NSData *credentialData = [NSKeyedArchiver archivedDataWithRootObject:credentials];

	NSMutableDictionary *attrDict = [NSMutableDictionary dictionaryWithDictionary:kDBKeychainDict];
	[attrDict setObject:credentialData forKey:(__bridge id)kSecValueData];

	NSArray *version = [[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."];
    if ([[version objectAtIndex:0] intValue] >= 4) {
        [attrDict setObject:(__bridge id)kSecAttrAccessibleAfterFirstUnlock forKey:(__bridge id)kSecAttrAccessible];
    }

	OSStatus status = noErr;

	if ([self credentials]) {
		[attrDict removeObjectForKey:(__bridge id)kSecClass];
		status = SecItemUpdate((__bridge CFDictionaryRef)kDBKeychainDict, (__bridge CFDictionaryRef)attrDict);
	} else {
		status = SecItemAdd((__bridge CFDictionaryRef)attrDict, NULL);
	}

	if (status != noErr) {
		DBLogWarning(@"DropboxSDK: error saving credentials (%i)", (int32_t)status);
	}
}

+ (void)deleteCredentials {
	OSStatus status = SecItemDelete((__bridge CFDictionaryRef)kDBKeychainDict);

	if (status != noErr) {
		DBLogWarning(@"DropboxSDK: error deleting credentials (%i)", (int32_t)status);
	}
}

@end
