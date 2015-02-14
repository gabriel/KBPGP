//
//  KBPGPUtil.m
//  KBPGP
//
//  Created by Gabriel on 10/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBPGPUtil.h"

@implementation KBPGPUtil

+ (NSString *)loadFile:(NSString *)file {
  NSString *path = [[NSBundle mainBundle] pathForResource:[file stringByDeletingPathExtension] ofType:[file pathExtension]];
  NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
  NSAssert(contents, @"No contents at file: %@", file);
  return contents;
}

+ (NSData *)loadData:(NSString *)file {
  NSString *path = [[NSBundle mainBundle] pathForResource:[file stringByDeletingPathExtension] ofType:[file pathExtension]];
  NSData *contents = [NSData dataWithContentsOfFile:path];
  NSAssert(contents, @"No contents at file: %@", file);
  return contents;
}

@end
