//
//  KBPGPUtil.h
//  KBPGP
//
//  Created by Gabriel on 10/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface KBPGPUtil : NSObject

+ (NSString *)loadFile:(NSString *)file;
+ (NSData *)loadData:(NSString *)file;

@end
