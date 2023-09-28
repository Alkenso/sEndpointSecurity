//  MIT License
//
//  Copyright (c) 2022 Alkenso (Vladimir Vashurkin)
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
public final class ESMessagePtr {
    private enum Ownership {
        case retained
        case unowned
    }
    
    public let rawMessage: UnsafePointer<es_message_t>
    private let shouldFree: Bool
    
    /// Initializes with message from `es_client` handler, retaining it and releasing when deallocated.
    public init(message: UnsafePointer<es_message_t>) {
        es_retain_message(message)
        self.rawMessage = message
        self.shouldFree = true
    }
    
    /// Initializes with message from `es_client` handler without copying or retaining it.
    /// Use ONLY if you are sure that message outlives created instance.
    public init(unowned message: UnsafePointer<es_message_t>) {
        self.rawMessage = message
        self.shouldFree = false
    }
    
    deinit {
        guard shouldFree else { return }
        es_release_message(rawMessage)
    }
    
    /// Converts raw message into ESMessage.
    public func converted(_ config: ESConverter.Config = .default) throws -> ESMessage {
        try ESConverter.esMessage(rawMessage.pointee, config: config)
    }
}

extension ESMessagePtr {
    public subscript<Local>(dynamicMember keyPath: KeyPath<es_message_t, Local>) -> Local {
        rawMessage.pointee[keyPath: keyPath]
    }
}
