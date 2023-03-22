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

private let log = SCLogger.internalLog(.service)

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
public final class ESService {
    private let createES: (inout es_new_client_result_t) -> ESClientProtocol?
    private let store = SubscriptionStore()
    private var client: ESClientProtocol?
    private var activationCache = Synchronized<[(ESClientProtocol) -> Void]>(.serial)
    
    public convenience init() {
        self.init(createES: ESClient.init(status:))
    }
    
    public init(createES: @escaping (inout es_new_client_result_t) -> ESClientProtocol?) {
        self.createES = createES
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
    public var pathInterestHandler: (ESProcess) -> (ESInterest) = { _ in .listen() }
    
    /// Registers the subscription. MUST be called before `activate`.
    /// At the moment registration is one-way operation.
    ///
    /// The caller must own returned `ESSubscriptionControl` to keep events coming.
    public func register(_ subscription: ESSubscription, suspended: Bool = false) -> ESSubscriptionControl {
        let token = ESSubscriptionControl(suspended: suspended)
        guard !subscription.events.isEmpty else {
            assertionFailure("Registering subscription with no events is prohibited")
            return token
        }
        
        token._resume = { [weak self, events = subscription.events] in
            guard let self else { return false }
            return self.client?.subscribe(events) == true
        }
        token._suspend = { [weak self, events = subscription.events] in
            guard let self else { return false }
            
            let uniqueEvents = self.store.subscriptions
                .reduce(into: Set(events)) { $0.subtract($1.subscription.events) }
            guard !uniqueEvents.isEmpty else { return true }
            
            return self.client?.unsubscribe(Array(uniqueEvents)) == true
        }
        
        store.addSubscription(subscription, state: token.sharedState)
        
        if let client {
            if !token.sharedState.isSuspended {
                _ = client.subscribe(subscription.events)
            }
            _ = client.clearCache()
            client.clearPathInterestCache()
        }
        
        return token
    }
    
    /// Activates the service. On success all resumed subscriptions would start receiving ES events.
    public func activate(config: ESClient.Config = ESClient.Config()) -> es_new_client_result_t {
        guard client == nil else { return ES_NEW_CLIENT_RESULT_SUCCESS }
        
        var status = ES_NEW_CLIENT_RESULT_ERR_INTERNAL
        guard let client = createES(&status) else { return status }
        defer { self.client = client }
        
        client.config = config
        
        client.pathInterestHandler = { [store, pathInterestHandler] in
            .combine(.restrictive, [store.pathInterest(in: $0), pathInterestHandler($0)]) ?? .listen()
        }
        client.authMessageHandler = store.handleAuthMessage
        client.notifyMessageHandler = store.handleNotifyMessage
        
        activationCache
            .write { updateSwap(&$0, []) }
            .forEach { $0(client) }
        
        let events = store.subscriptions
            .filter { !$0.state.isSuspended }
            .reduce(into: Set()) { $0.formUnion($1.subscription.events) }
        if !events.isEmpty {
            if !client.subscribe(Array(events)) {
                log.error("Failed to subscribe to \(events.count) events on activate")
            }
        }
        
        return status
    }
    
    /// Invalidates the service. Discards underlying `es_client`, clears all mutes.
    /// Registrations are kept.
    public func invalidate() {
        guard let client else { return }
        _ = client.unsubscribeAll()
        
        self.client = nil
    }
    
    /// Config used to convert native `es_message_t` into `ESMessage`.
    public var converterConfig: ESConverter.Config {
        get { store.converterConfig }
        set { store.converterConfig = newValue }
    }
    
    /// Reference to `ESClient` used under the hood.
    /// DO NOT use it for modifyng any mutes/inversions/etc, the behaviour is undefined.
    /// You may want to use it for informational purposes (list of mutes, etc).
    public var unsafeClient: ESClientProtocol? { client }
    
    /// Clear all cached results for all clients. Clears both `interest` and `auth` caches.
    public func clearCaches() {
        guard let client else { return }
        store.resetInterestCache()
        client.clearPathInterestCache()
        _ = client.clearCache()
    }
    
    // MARK: Mute
    
    /// Suppress events from the process described by the given `mute` rule.
    /// - Parameters:
    ///     - mute: process to mute.
    ///     - events: set of events to mute.
    public func mute(process rule: ESMuteProcessRule, events: ESEventSet = .all) {
        withActiveClient { $0.mute(process: rule, events: events) }
    }
    
    /// Unmute events for the process described by the given `mute` rule.
    /// - Parameters:
    ///     - mute: process to unmute.
    ///     - events: set of events to mute.
    public func unmute(process rule: ESMuteProcessRule, events: ESEventSet = .all) {
        withActiveClient { $0.unmute(process: rule, events: events) }
    }
    
    /// Unmute all events for all processes. Clear the rules.
    public func unmuteAllProcesses() {
        withActiveClient { $0.unmuteAllProcesses() }
    }
    
    /// Suppress events for the the given at path and type.
    /// - Parameters:
    ///     - mute: process path to mute.
    ///     - type: path type.
    ///     - events: set of events to mute.
    public func mute(path: String, type: es_mute_path_type_t, events: ESEventSet = .all) {
        withActiveClient { $0.mute(path: path, type: type, events: events) }
    }
    
    /// Unmute events for the given at path and type.
    /// - Parameters:
    ///     - mute: process path to unmute.
    ///     - type: path type.
    ///     - events: set of events to unmute.
    @available(macOS 12.0, *)
    public func unmute(path: String, type: es_mute_path_type_t, events: ESEventSet = .all) {
        withActiveClient { $0.unmute(path: path, type: type, events: events) }
    }
    
    /// Unmute all events for all process paths.
    public func unmuteAllPaths() {
        withActiveClient { $0.unmuteAllPaths() }
    }
    
    /// Unmute all target paths. Works only for macOS 13.0+.
    @available(macOS 13.0, *)
    public func unmuteAllTargetPaths() {
        withActiveClient { $0.unmuteAllTargetPaths() }
    }
    
    /// Invert the mute state of a given mute dimension.
    @available(macOS 13.0, *)
    public func invertMuting(_ muteType: es_mute_inversion_type_t) {
        withActiveClient { $0.invertMuting(muteType) }
    }
    
    private func withActiveClient<R>(_ name: String = #function, body: @escaping (ESClientProtocol) -> R) {
        func execute(_ client: ESClientProtocol) {
            if body(client) as? Bool == false {
                log.error("Failed to \(name)")
            }
        }
        
        if let client {
            execute(client)
        } else {
            activationCache.writeAsync { $0.append(execute) }
        }
    }
}

private class SubscriptionStore {
    final class Entry {
        var subscription: ESSubscription
        var state: SubscriptionState
        
        init(subscription: ESSubscription, state: SubscriptionState) {
            self.subscription = subscription
            self.state = state
        }
    }
    
    private var pathInterests: [String: [ObjectIdentifier: Set<es_event_type_t>]] = [:]
    private var pathInterestsActual = atomic_flag()
    internal private(set) var subscriptions: [Entry] = []
    private var subscriptionEvents: [es_event_type_t: [Entry]] = [:]
    
    var converterConfig: ESConverter.Config = .default
    
    // MARK: Managing subscriptions
    
    func addSubscription(_ subscription: ESSubscription, state: SubscriptionState) {
        let entry = Entry(subscription: subscription, state: state)
        subscriptions.append(entry)
        
        subscription.events.forEach {
            subscriptionEvents[$0, default: []].append(entry)
        }
    }
    
    func resetInterestCache() {
        atomic_flag_clear(&pathInterestsActual)
    }
    
    // MARK: Handling ES events
    
    func pathInterest(in process: ESProcess) -> ESInterest {
        if !atomic_flag_test_and_set(&pathInterestsActual) {
            pathInterests.removeAll(keepingCapacity: true)
        }
        
        var resolutions: [ESInterest] = []
        for entry in subscriptions {
            guard entry.state.isAlive else { continue }
            
            let interest = entry.subscription.pathInterestHandler(process)
            resolutions.append(interest)
            
            let identifier = ObjectIdentifier(entry)
            pathInterests[process.executable.path, default: [:]][identifier] = interest.events
        }
        
        return ESInterest.combine(.permissive, resolutions) ?? .listen()
    }
    
    func handleAuthMessage(_ rawMessage: ESMessagePtr, reply: @escaping (ESAuthResolution) -> Void) {
        let subscribers = subscription(for: rawMessage)
        guard !subscribers.isEmpty else {
            reply(.allowOnce)
            return
        }
        guard let message = rawMessage.convertedWithLog(converterConfig) else {
            reply(.allowOnce)
            return
        }
        
        let group = ESMultipleResolution(count: subscribers.count, reply: reply)
        subscribers.forEach { $0.subscription.authMessageHandler(message, group.resolve) }
    }
    
    func handleNotifyMessage(_ rawMessage: ESMessagePtr) {
        let subscribers = subscription(for: rawMessage)
        guard !subscribers.isEmpty else { return }
        guard let message = rawMessage.convertedWithLog(converterConfig) else { return }
        
        subscribers.forEach { $0.subscription.notifyMessageHandler(message) }
    }
    
    private func subscription(for message: ESMessagePtr) -> [Entry] {
        let event = message.event_type
        guard let eventSubscriptions = subscriptionEvents[event] else { return [] }
        let activeSubscriptions = eventSubscriptions.filter({ !$0.state.isSuspended })
        guard !activeSubscriptions.isEmpty else { return [] }
        
        let converter = ESConverter(version: message.version)
        let path = converter.esString(message.process.pointee.executable.pointee.path)
        
        return activeSubscriptions
            .filter { pathInterests[path]?[ObjectIdentifier($0)]?.contains(event) == true }
    }
}

internal class ESMultipleResolution {
    private var lock = os_unfair_lock()
    private var fulfilled = 0
    private var resolutions: [ESAuthResolution]
    private let reply: (ESAuthResolution) -> Void
    
    init(count: Int, reply: @escaping (ESAuthResolution) -> Void) {
        self.resolutions = .init(repeating: .allow, count: count)
        self.reply = reply
    }
    
    func resolve(_ resolution: ESAuthResolution) {
        lock.withLock {
            resolutions[fulfilled] = resolution
            fulfilled += 1
            
            if fulfilled == resolutions.count {
                let combined = ESAuthResolution.combine(resolutions)
                reply(combined)
            }
        }
    }
}

extension ESMessagePtr {
    @inline(__always)
    fileprivate func convertedWithLog(_ config: ESConverter.Config) -> ESMessage? {
        do {
            return try converted(config)
        } catch {
            log.error("Failed to decode message \(self.event_type). Error: \(error)")
            return nil
        }
    }
}
