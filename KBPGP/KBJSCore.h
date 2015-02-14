//
//  KBJSCore.h
//  KBPGP
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <JavaScriptCore/JavaScriptCore.h>

typedef void(^KBJSCoreExceptionHandler)(JSContext *context, JSValue *exception);

@interface KBJSCore : NSObject

@property (readonly) JSContext *context;
@property dispatch_queue_t queue;

- (instancetype)initWithQueue:(dispatch_queue_t)queue exceptionHandler:(KBJSCoreExceptionHandler)exceptionHandler;

- (NSString *)randomHexString:(NSUInteger)numBytes;

- (BOOL)exists:(NSString *)path;

- (id)exec:(NSString *)js;

- (NSString *)readFile:(NSString *)path;

- (void)load:(NSString *)path;

@end
