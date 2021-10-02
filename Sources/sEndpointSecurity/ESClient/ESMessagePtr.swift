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

import EndpointSecurity
import Foundation
import SwiftConvenience


@dynamicMemberLookup
public class ESMessagePtr {
    private enum Ownership {
        case retained
        case unowned
        case allocated
    }
    
    public let unsafeRawMessage: UnsafePointer<es_message_t>
    private let ownership: Ownership
    
    
    /// Initializes with message, retaining it and releasing when deallocated.
    public init(message: UnsafePointer<es_message_t>) {
        if #available(macOS 11.0, *) {
            es_retain_message(message)
            self.unsafeRawMessage = message
        } else {
            self.unsafeRawMessage = UnsafePointer(es_copy_message(message)!)
        }
        ownership = .retained
    }
    
    /// Initializes with message without copying or retaining it.
    /// Use ONLY if you are sure that message outlives this instance.
    public init(unowned message: UnsafePointer<es_message_t>) {
        self.unsafeRawMessage = message
        ownership = .unowned
    }
    
    /// Creates message from data, obtained from 'serialize'.
    /// Do NOT use instances of messages created by this init with es_xxx API.
    public init(data: Data) throws {
        var reader = BinaryReader(data: data)
        unsafeRawMessage = UnsafePointer(try UnsafeMutablePointer<es_message_t>.allocate(from: &reader))
        ownership = .allocated
    }
    
    deinit {
        switch ownership {
        case .retained:
            if #available(macOS 11.0, *) {
                es_release_message(unsafeRawMessage)
            } else {
                es_free_message(UnsafeMutablePointer(mutating: unsafeRawMessage))
            }
        case .unowned:
            break
        case .allocated:
            UnsafeMutablePointer(mutating: unsafeRawMessage).freeAndDeallocate()
        }
    }
    
    /// Serializes the message, considering only public-accessignle fields.
    public func serialized() throws -> Data {
        let estimatedSize =
            MemoryLayout<es_message_t>.size +
            MemoryLayout<es_process_t>.size +
            MemoryLayout<es_thread_t>.size
        let destination = DataBinaryWriterOutput(data: Data(capacity: estimatedSize))
        var writer = BinaryWriter(destination)
        try withRawMessage { try $0.encode(with: &writer) }
        
        return destination.data
    }
    
    /// Converts raw message into ESMessage.
    public func converted() throws -> ESMessage {
        try withRawMessage(ESConverter.esMessage)
    }
}

public extension ESMessagePtr {
    func withRawMessagePtr<R>(_ body: (UnsafePointer<es_message_t>) throws -> R) rethrows -> R {
        try body(unsafeRawMessage)
    }
    
    func withRawMessage<R>(_ body: (es_message_t) throws -> R) rethrows -> R {
        try withRawMessagePtr { try body($0.pointee) }
    }
    
    subscript<Local>(dynamicMember keyPath: KeyPath<es_message_t, Local>) -> Local {
        unsafeRawMessage.pointee[keyPath: keyPath]
    }
}
