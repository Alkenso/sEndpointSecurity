//  MIT License
//
//  Copyright (c) 2023 Alkenso (Vladimir Vashurkin)
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

public struct ESSubscription {
    internal let id = UUID()
    
    public init() {}
    
    /// Set of events to subscribe on.
    public var events: [es_event_type_t] = []
    
    /// Queue where `pathInterestHandler`, `authMessageHandler`
    /// and `notifyMessageHandler` handlers are called.
    /// Defaults to `nil` that means all handlers are called directly on underlying queue.
    public var queue: DispatchQueue?
    
    /// Perform process filtering, additionally to muting of path and processes.
    /// Filtering is based on `interest in process with particular executable path`.
    /// Designed to be used for granular process filtering by ignoring uninterest events.
    ///
    /// General idea is to mute or ignore processes we are not interested in using their binary paths.
    /// Usually the OS would not have more than ~1000 unique processes, so asking for interest in particular
    /// process path would occur very limited number of times.
    ///
    /// The process may be interested or ignored accoding to returned `ESInterest`.
    /// If the process is not interested, all related messages are skipped.
    /// More information on `ESInterest` see in related documentation.
    ///
    /// The final decision if the particular event is delivered or not relies on multiple sources.
    /// Sources considered:
    /// - `mutePath` rules
    /// - `muteProcess` rules
    /// - `pathInterestHandler` resolution
    /// - `pathInterestRules` rules
    ///
    /// - Note: Interest does NOT depend on `inversion` of `ESClient`.
    /// - Note: Returned resolutions are cached to avoid often handler calls.
    /// To reset cache, call `clearPathInterestCache`.
    /// - Note: When the handler is not set, it defaults to returning `ESInterest.listen()`.
    ///
    /// - Warning: Perfonamce-sensitive handler, called **synchronously** once for each process path on `queue`.
    /// Do here as minimum work as possible.
    public var pathInterestHandler: (ESProcess) -> ESInterest = { _ in .listen() }
    
    /// Handler invoked each time AUTH message is coming from EndpointSecurity.
    /// The message SHOULD be responded using the second parameter - reply block.
    public var authMessageHandler: (ESMessage, @escaping (ESAuthResolution) -> Void) -> Void = { $1(.allow) }
    
    /// Handler invoked each time NOTIFY message is coming from EndpointSecurity.
    public var notifyMessageHandler: (ESMessage) -> Void = { _ in }
}

public final class ESSubscriptionControl {
    let sharedState = SubscriptionState()
    
    init(subscribed: Bool) {
        sharedState.subscribed = subscribed ? 1 : 0
        sharedState.control = self
    }
    
    deinit {
        try? unsubscribe()
    }
    
    internal var _subscribe: () throws -> Void = {}
    internal var _unsubscribe: () throws -> Void = {}
    
    public var isSubscribed: Bool { sharedState.isSubscribed }
    
    /// Resume receiving ES events into `authMessageHandler` and `notifyMessageHandler`.
    public func subscribe() throws {
        try sharedState.lock.withLock {
            guard !sharedState.isSubscribed else { return }
            try _subscribe()
            OSAtomicCompareAndSwap64(0, 1, &sharedState.subscribed)
        }
    }
    
    /// Suspend receiving ES events into `authMessageHandler` and `notifyMessageHandler`.
    /// `pathInterestHandler` will be still called when needed.
    public func unsubscribe() throws {
        try sharedState.lock.withLock {
            guard sharedState.isSubscribed else { return }
            try _unsubscribe()
            OSAtomicCompareAndSwap64(1, 0, &sharedState.subscribed)
        }
    }
}

internal final class SubscriptionState {
    fileprivate var subscribed: Int64 = 0
    fileprivate weak var control: ESSubscriptionControl?
    fileprivate var lock = os_unfair_lock()
    
    var isSubscribed: Bool { OSAtomicAdd64(0, &subscribed) == 1 }
    var isAlive: Bool { control != nil }
}
