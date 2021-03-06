//
//  DBAccountInfo.m
//  DropboxSDK
//
//  Created by Brian Smith on 5/3/10.
//  Copyright 2010 Dropbox, Inc. All rights reserved.
//

#import "DBAccountInfo.h"


@implementation DBAccountInfo

- (id)initWithDictionary:(NSDictionary*)dict {
	self = [super init];
	
    if(self) {
        country = [dict objectForKey:@"country"];
        displayName = [dict objectForKey:@"display_name"];
        if ([dict objectForKey:@"quota_info"]) {
            quota = [[DBQuota alloc] initWithDictionary:[dict objectForKey:@"quota_info"]];
        }
        userId = [[dict objectForKey:@"uid"] stringValue];
        referralLink = [dict objectForKey:@"referral_link"];
        original = dict;
    }
	
    return self;
}


@synthesize country;
@synthesize displayName;
@synthesize quota;
@synthesize userId;
@synthesize referralLink;


#pragma mark NSCoding methods

- (void)encodeWithCoder:(NSCoder*)coder {
    [coder encodeObject:original forKey:@"original"];
}

- (id)initWithCoder:(NSCoder*)coder {
    if ([coder containsValueForKey:@"original"]) {
        return [self initWithDictionary:[coder decodeObjectForKey:@"original"]];
    } else {
        NSMutableDictionary *mDict = [NSMutableDictionary dictionary];

        [mDict setObject:[coder decodeObjectForKey:@"country"] forKey:@"country"];
        [mDict setObject:[coder decodeObjectForKey:@"displayName"] forKey:@"display_name"];

        DBQuota *tempQuota = [coder decodeObjectForKey:@"quota"];
        NSDictionary *quotaDict =
            [NSDictionary dictionaryWithObjectsAndKeys:
             [NSNumber numberWithLongLong:tempQuota.normalConsumedBytes], @"normal",
             [NSNumber numberWithLongLong:tempQuota.sharedConsumedBytes], @"shared",
             [NSNumber numberWithLongLong:tempQuota.totalBytes], @"quota", nil];
        [mDict setObject:quotaDict forKey:@"quota_info"];

        NSNumber *uid = [NSNumber numberWithLongLong:[[coder decodeObjectForKey:@"userId"] longLongValue]];
        [mDict setObject:uid forKey:@"uid"];
        [mDict setObject:[coder decodeObjectForKey:@"referralLink"] forKey:@"referral_link"];
        if ([coder containsValueForKey:@"email"]) {
            [mDict setObject:[coder decodeObjectForKey:@"email"] forKey:@"email"];
        }

        return [self initWithDictionary:mDict];
    }
}

@end
