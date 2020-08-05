//
//  AESCrypt.m
//  Gurpartap Singh
//
//  Created by Gurpartap Singh on 06/05/12.
//  Copyright (c) 2012 Gurpartap Singh
// 
// 	MIT License
// 
// 	Permission is hereby granted, free of charge, to any person obtaining
// 	a copy of this software and associated documentation files (the
// 	"Software"), to deal in the Software without restriction, including
// 	without limitation the rights to use, copy, modify, merge, publish,
// 	distribute, sublicense, and/or sell copies of the Software, and to
// 	permit persons to whom the Software is furnished to do so, subject to
// 	the following conditions:
// 
// 	The above copyright notice and this permission notice shall be
// 	included in all copies or substantial portions of the Software.
// 
// 	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// 	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// 	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// 	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// 	LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// 	OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// 	WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#import "AESCrypt.h"

#import "NSData+Base64.h"
#import "NSString+Base64.h"
#import "NSData+CommonCrypto.h"

@implementation AESCrypt

+ (NSString *)encrypt:(NSString *)message password:(NSString *)password {
  NSData *encryptedData = [[message dataUsingEncoding:NSUTF8StringEncoding] AES256EncryptedDataUsingKey:[[password dataUsingEncoding:NSUTF8StringEncoding] SHA256Hash] error:nil];
  NSString *base64EncodedString = [NSString base64StringFromData:encryptedData length:[encryptedData length]];
  return base64EncodedString;
}

+ (NSString *)decrypt:(NSString *)base64EncodedString password:(NSString *)password {
  NSData *encryptedData = [NSData base64DataFromString:base64EncodedString];
  NSData *decryptedData = [encryptedData decryptedAES256DataUsingKey:[[password dataUsingEncoding:NSUTF8StringEncoding] SHA256Hash] error:nil];
  return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

+ (NSData*) decryptData:(NSData*)data password:(NSString *)password chunkSize:(NSUInteger)chunkSize
{
    return [self decryptData:data password:password chunkSize:chunkSize offsetBlock:0 countBlock:0 iv:nil];
}
+ (NSData*) decryptData:(NSData*)data password:(NSString *)password chunkSize:(NSUInteger)chunkSize iv: (id) iv
{
    return [self decryptData:data password:password chunkSize:chunkSize offsetBlock:0 countBlock:0 iv:iv];
}

+ (NSData*) decryptData:(NSData*)data
               password:(NSString *)password
              chunkSize:(NSUInteger)chunkSize
            offsetBlock:(NSUInteger)offsetBlock
             countBlock:(NSUInteger)countBlock
                     iv: (id) iv
{
    NSUInteger length = [data length];
    if (chunkSize > length) {
        chunkSize = floor(length/16)*16;
    }
    if(countBlock > 0){
        length = (offsetBlock+countBlock)*chunkSize;
    }
    if(length > [data length]){
        length = [data length];
    }
    NSUInteger offset = offsetBlock * chunkSize;
    NSMutableData *decryptedData = [NSMutableData alloc];
    NSData* encryptedPartOfData;
    do {
        NSUInteger thisChunkSize = length - offset > chunkSize ? chunkSize : length - offset;
        NSData* partOfData = [data subdataWithRange:NSMakeRange(offset, thisChunkSize)];
        if(iv == nil){
            encryptedPartOfData = [partOfData decryptedAES256DataUsingKey:[[password dataUsingEncoding:NSUTF8StringEncoding] SHA256Hash] error:nil];
        } else {
//            encryptedPartOfData = [partOfData decryptedAES256DataUsingKey:[password dataUsingEncoding:NSUTF8StringEncoding] initializationVector:iv error:nil];
        }
        [decryptedData appendData:encryptedPartOfData];
        offset += thisChunkSize;
    } while (offset < length);
    return decryptedData;
}

@end
