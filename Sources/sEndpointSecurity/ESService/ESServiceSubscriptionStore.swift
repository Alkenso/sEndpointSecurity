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

internal final class ESServiceSubscriptionStore {
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
            
            let interest = entry.subscription.queue.sync { entry.subscription.pathInterestHandler(process) }
            resolutions.append(interest)
            
            let identifier = ObjectIdentifier(entry)
            pathInterests[process.executable.path, default: [:]][identifier] = interest.events
        }
        
        return ESInterest.combine(.permissive, resolutions) ?? .listen()
    }
    
    func handleAuthMessage(_ rawMessage: ESMessagePtr, reply: @escaping (ESAuthResolution) -> Void) {
        handleAuthMessage(
            event: rawMessage.event_type,
            path: rawMessage.executablePath,
            message: { rawMessage.convertedWithLog(converterConfig) },
            reply: reply
        )
    }
    
    func handleAuthMessage(_ message: ESMessage, reply: @escaping (ESAuthResolution) -> Void) {
        handleAuthMessage(
            event: message.eventType,
            path: message.process.executable.path,
            message: { message },
            reply: reply
        )
    }
    
    @inline(__always)
    private func handleAuthMessage(
        event: es_event_type_t,
        path: @autoclosure () -> String,
        message: () -> ESMessage?,
        reply: @escaping (ESAuthResolution) -> Void
    ) {
        let subscribers = subscriptions(for: event, path: path())
        guard !subscribers.isEmpty else {
            reply(.allowOnce)
            return
        }
        guard let message = message() else {
            reply(.allowOnce)
            return
        }
        
        let group = ESMultipleResolution(count: subscribers.count, reply: reply)
        subscribers.forEach { entry in
            entry.subscription.queue.async {
                entry.subscription.authMessageHandler(message, group.resolve)
            }
        }
    }
    
    func handleNotifyMessage(_ rawMessage: ESMessagePtr) {
        handleNotifyMessage(event: rawMessage.event_type, path: rawMessage.executablePath) {
            rawMessage.convertedWithLog(converterConfig)
        }
    }
    
    func handleNotifyMessage(_ message: ESMessage) {
        handleNotifyMessage(event: message.eventType, path: message.process.executable.path) { message }
    }
    
    @inline(__always)
    private func handleNotifyMessage(
        event: es_event_type_t,
        path: @autoclosure () -> String,
        message: () -> ESMessage?
    ) {
        let subscribers = subscriptions(for: event, path: path())
        guard !subscribers.isEmpty else { return }
        guard let message = message() else { return }
        
        subscribers.forEach { entry in
            entry.subscription.queue.async {
                entry.subscription.notifyMessageHandler(message)
            }
        }
    }
    
    @inline(__always)
    private func subscriptions(for event: es_event_type_t, path: @autoclosure () -> String) -> [Entry] {
        guard let eventSubscriptions = subscriptionEvents[event] else { return [] }
        let activeSubscriptions = eventSubscriptions.filter { $0.state.isSubscribed }
        guard !activeSubscriptions.isEmpty else { return [] }
        
        let path = path()
        return activeSubscriptions
            .filter { pathInterests[path]?[ObjectIdentifier($0)]?.contains(event) == true }
    }
}

internal final class ESMultipleResolution {
    private var lock = UnfairLock()
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
            log.error("Failed to decode message \(rawMessage.pointee.event_type). Error: \(error)")
            return nil
        }
    }
    
    @inline(__always)
    fileprivate var executablePath: String {
        ESConverter(version: rawMessage.pointee.version)
            .esString(rawMessage.pointee.process.pointee.executable.pointee.path)
    }
}
