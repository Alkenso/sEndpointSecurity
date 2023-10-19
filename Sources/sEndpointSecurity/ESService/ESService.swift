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
import SpellbookFoundation

private let log = SpellbookLogger.internalLog(.service)

/// ESService provides muliclient support for dealing with EndpointSecurity events
/// without need of managing many native `es_client(s)` (at least there is OS limit for latter).
///
/// ESService would be convenient when the product has multiple features that
/// uses ES events internally.
///
/// There is a strict order of deating with `ESService`:
/// - create `ESService`, usually single instance for whole application.
/// - `register` all components within it.
/// - setup mutes, inversions, etc.
/// - `activate` the service.
///
/// There are some special cases in above scenario:
/// 1. `activate` may fail because of underlying ES.framework creation error.
/// That is normal scenario. Just fix error cause and `activate` again.
/// All subscriptions, mutes, etc. are kept.
/// 2. After `activate`, all subscriptions that are not suspended would receive ES events.
/// Suspended subscriptions would NOT receive events while they remain suspended.
public final class ESService: ESServiceRegistering {
    private typealias Client = any ESClientProtocol
    private let createES: (String, ESServiceSubscriptionStore) throws -> Client
    private let store = ESServiceSubscriptionStore()
    private var client: Client?
    private var isActivated = false
    private var activationLock = UnfairLock()
    
    public convenience init() {
        self.init(createES: ESClient.init)
    }
    
    public init<C: ESClientProtocol>(createES: @escaping (String) throws -> C) where C.Message == ESMessage {
        self.createES = { name, store in
            let client = try createES(name)
            client.authMessageHandler = store.handleAuthMessage
            client.notifyMessageHandler = store.handleNotifyMessage
            return client
        }
    }
    
    public init<C: ESClientProtocol>(createES: @escaping (String) throws -> C) where C.Message == ESMessagePtr {
        self.createES = { name, store in
            let client = try createES(name)
            client.authMessageHandler = store.handleAuthMessage
            client.notifyMessageHandler = store.handleNotifyMessage
            return client
        }
    }
    
    /// Perform service-level process filtering, additionally to muting of path and processes for all clients.
    /// Filtering is based on `interest in particular process executable path`.
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
    /// - `mute(path:)` rules
    /// - `mute(process:)` rules
    /// - `pathInterestHandler` resolution
    /// - subscriptions `pathInterestHandler` resolutions
    ///
    /// - Note: Interest does NOT depend on `inversion` of underlying `ESClient`.
    /// - Note: Returned resolutions are cached to avoid often handler calls.
    /// To reset cache, call `clearCaches`.
    /// - Note: When the handler is not set, it defaults to returning `ESInterest.listen()`.
    ///
    /// - Warning: Perfonamce-sensitive handler, called **synchronously** once for each process path.
    /// Do here as minimum work as possible.
    /// - Warning: The property MUST NOT be changed while the service is activated.
    public var pathInterestHandler: (ESProcess) -> ESInterest = { _ in .listen() }
    
    /// Registers the subscription. MUST be called before `activate`.
    /// At the moment registration is one-way operation.
    ///
    /// The caller must retain returned `ESSubscriptionControl` to keep events coming.
    public func register(_ subscription: ESSubscription) -> ESSubscriptionControl {
        let token = ESSubscriptionControl()
        guard !subscription.events.isEmpty else {
            assertionFailure("Registering subscription with no events is prohibited")
            return token
        }
        
        token._subscribe = { [weak self, events = subscription.events] in
            guard let self else { return }
            try self.activationLock.withLock {
                guard self.isActivated else { return }
                try self.client?.subscribe(events)
            }
        }
        token._unsubscribe = { [weak self, events = subscription.events, id = subscription.id] in
            guard let self else { return }
            
            try self.activationLock.withLock {
                guard self.isActivated else { return }
                
                let uniqueEvents = self.store.subscriptions
                    .filter { $0.state.isSubscribed && $0.subscription.id != id }
                    .reduce(into: Set(events)) { $0.subtract($1.subscription.events) }
                guard !uniqueEvents.isEmpty else { return }
                
                try self.client?.unsubscribe(Array(uniqueEvents))
            }
        }
        
        activationLock.withLock {
            store.addSubscription(subscription, state: token.sharedState)
        }
        
        if let client {
            try? client.clearCache()
            try? client.clearPathInterestCache()
        }
        
        return token
    }
    
    /// The handler is called in activation process: after ESClient is created but before any subscription is made.
    /// Good point to add service-wide mutes.
    /// - Warning: Do NOT call `activate` or `invalidate` routines from the handler.
    /// - Warning: The property MUST NOT be changed while the service is activated.
    public var preSubscriptionHandler: (() throws -> Void)?
    
    /// Activates the service. On success all subscriptions would start receiving ES events if subscibed.
    public func activate() throws {
        guard !activationLock.withLock({ isActivated }) else { return }
        
        let client = try createES("ESService_\(ObjectIdentifier(self))", store)
        
        /// `authMessageHandler` and `notifyMessageHandler` are set in `createES` function
        /// due to generic nature of underlying `Client` instance.
        client.pathInterestHandler = { [store, pathInterestHandler] in
            .combine(.restrictive, [store.pathInterest(in: $0), pathInterestHandler($0)]) ?? .listen()
        }
        client.queue = nil
        
        self.client = client
        
        do {
            try preSubscriptionHandler?()
            
            try activationLock.withLock {
                let events = store.subscriptions
                    .filter { $0.state.isSubscribed }
                    .reduce(into: Set()) { $0.formUnion($1.subscription.events) }
                if !events.isEmpty {
                    try client.subscribe(Array(events))
                }
                
                isActivated = true
            }
        } catch {
            self.client = nil
            throw error
        }
    }
    
    /// Invalidates the service. Discards underlying `es_client`, clears all mutes.
    /// Registrations are kept.
    public func invalidate() {
        activationLock.withLock {
            try? client?.unsubscribeAll()
            client = nil
            isActivated = false
        }
    }
    
    /// Config used to convert native `es_message_t` into `ESMessage`.
    /// - Warning: The property MUST NOT be changed while the service is activated.  
    public var converterConfig: ESConverter.Config {
        get { store.converterConfig }
        set { store.converterConfig = newValue }
    }
    
    /// Reference to `ESClient` used under the hood.
    /// DO NOT use it for modifyng any mutes/inversions/etc, the behaviour is undefined.
    /// You may want to use it for informational purposes (list of mutes, etc).
    public var unsafeClient: (any ESClientProtocol)? { client }
    
    /// Clear all cached results for all clients. Clears both `interest` and `auth` caches.
    public func clearCaches() throws {
        guard let client else { return }
        store.resetInterestCache()
        try client.clearPathInterestCache()
        try client.clearCache()
    }
    
    // MARK: Mute
    
    /// Suppress events from the process described by the given `mute` rule.
    /// - Parameters:
    ///     - mute: process to mute.
    ///     - events: set of events to mute.
    public func mute(process rule: ESMuteProcessRule, events: ESEventSet = .all) throws {
        try withActiveClient { try $0.mute(process: rule, events: events) }
    }
    
    /// Unmute events for the process described by the given `mute` rule.
    /// - Parameters:
    ///     - mute: process to unmute.
    ///     - events: set of events to mute.
    public func unmute(process rule: ESMuteProcessRule, events: ESEventSet = .all) throws {
        try withActiveClient { try $0.unmute(process: rule, events: events) }
    }
    
    /// Unmute all events for all processes. Clear the rules.
    public func unmuteAllProcesses() throws {
        try withActiveClient { try $0.unmuteAllProcesses() }
    }
    
    /// Suppress events for the the given at path and type.
    /// - Parameters:
    ///     - mute: process path to mute.
    ///     - type: path type.
    ///     - events: set of events to mute.
    public func mute(path: String, type: es_mute_path_type_t, events: ESEventSet = .all) throws {
        try withActiveClient { try $0.mute(path: path, type: type, events: events) }
    }
    
    /// Unmute events for the given at path and type.
    /// - Parameters:
    ///     - mute: process path to unmute.
    ///     - type: path type.
    ///     - events: set of events to unmute.
    @available(macOS 12.0, *)
    public func unmute(path: String, type: es_mute_path_type_t, events: ESEventSet = .all) throws {
        try withActiveClient { try $0.unmute(path: path, type: type, events: events) }
    }
    
    /// Unmute all events for all process paths.
    public func unmuteAllPaths() throws {
        try withActiveClient { try $0.unmuteAllPaths() }
    }
    
    /// Unmute all target paths. Works only for macOS 13.0+.
    @available(macOS 13.0, *)
    public func unmuteAllTargetPaths() throws {
        try withActiveClient { try $0.unmuteAllTargetPaths() }
    }
    
    /// Invert the mute state of a given mute dimension.
    @available(macOS 13.0, *)
    public func invertMuting(_ muteType: es_mute_inversion_type_t) throws {
        try withActiveClient { try $0.invertMuting(muteType) }
    }
    
    private func withActiveClient(_ function: String = #function, body: @escaping (Client) throws -> Void) throws {
        if let client {
            try body(client)
        } else {
            throw CommonError.unexpected("Trying to call \(function) on non-activated ESService")
        }
    }
}

public protocol ESServiceRegistering {
    func register(_ subscription: ESSubscription) -> ESSubscriptionControl
}
