//  MIT License
//
//  Copyright (c) 2021 Alkenso (Vladimir Vashurkin)
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

import Foundation
import SwiftConvenience

// MARK: - LocalConstructible

protocol LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws
    mutating func decode(from reader: inout BinaryReader) throws
    func freeInternals()
}

extension LocalConstructible {
    init(from reader: inout BinaryReader) throws {
        let tmp = try UnsafeMutablePointer<Self>.allocate(from: &reader)
        self = tmp.pointee
        tmp.deallocate()
    }
}

extension UnsafeMutablePointer where Pointee: LocalConstructible {
    static func allocate(from reader: inout BinaryReader) throws -> UnsafeMutablePointer<Pointee> {
        let ptr = UnsafeMutablePointer<Pointee>.allocate(capacity: 1)
        ptr.bzero()
        do {
            try ptr.pointee.decode(from: &reader)
        } catch {
            ptr.deallocate()
            throw error
        }
        return ptr
    }
    
    func freeAndDeallocate() {
        if let ptr = nullable {
            ptr.pointee.freeInternals()
            ptr.deallocate()
        }
    }
}

extension Optional {
    func encode<T: LocalConstructible>(with writer: inout BinaryWriter) throws where Wrapped == UnsafeMutablePointer<T> {
        try writer.append(UInt8(self != nil ? 1 : 0)) // field precense
        if let value = self {
            try value.pointee.encode(with: &writer)
        }
    }
    
    static func allocate<T: LocalConstructible>(from reader: inout BinaryReader) throws -> UnsafeMutablePointer<T>? {
        if try reader.read() as UInt8 == 1 {
            return try UnsafeMutablePointer<T>.allocate(from: &reader)
        } else {
            return nil
        }
    }
}

// MARK: - DataReader/Writer userInfo

extension Dictionary where Key == String, Value == Any {
    private static let messageVersionKey = "MessageVersion"
    
    mutating func setMessageVersion(_ version: UInt32) {
        self[Self.messageVersionKey] = version
    }
    
    func messageVersion() throws -> UInt32 {
        guard let version = self[Self.messageVersionKey] as? UInt32 else {
            fatalError()
        }
        return version
    }
}
