//
//  KBJSCore.h
//  KBCrypto
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <JavaScriptCore/JavaScriptCore.h>

@protocol KBJSCore <JSExport>
- (BOOL)exists:(NSString *)path;
- (NSString *)readFile:(NSString *)path;
- (id)exec:(NSString *)js;
- (void)load:(NSString *)URLString;
@end


@interface KBJSCore : NSObject <KBJSCore>

@property (readonly) JSContext *context;

- (NSString *)randomHexString:(NSUInteger)numBytes;

@end
