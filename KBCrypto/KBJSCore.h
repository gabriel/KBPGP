//
//  KBJSCore.h
//  KBCrypto
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <JavaScriptCore/JavaScriptCore.h>

@interface KBJSCore : NSObject

@property (readonly) JSContext *context;
@property dispatch_queue_t completionQueue;

- (NSString *)randomHexString:(NSUInteger)numBytes;

- (BOOL)exists:(NSString *)path;

- (id)exec:(NSString *)js;

- (NSString *)readFile:(NSString *)path digest:(NSString *)digest;

- (void)load:(NSString *)path digest:(NSString *)digest;

@end
