//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 13.09.2021.
//

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
