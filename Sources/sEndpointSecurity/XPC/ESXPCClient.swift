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

private let log = SCLogger.internalLog(.xpc)

public class ESXPCClient {
    @Atomic private var connection: ESXPCConnection
    private let delegate: ESClientXPCDelegate
    private var subscribedEvents = Synchronized<Set<es_event_type_t>>(.serial)

    // MARK: - Initialization & Activation

    public init(_ createConnection: @escaping @autoclosure () -> NSXPCConnection) {
        let delegate = ESClientXPCDelegate()
        self.connection = ESXPCConnection(delegate: delegate, createConnection: createConnection)
        self.delegate = delegate
    }

    deinit {
        invalidate()
    }
    
    public var connectionStateHandler: ((Result<es_new_client_result_t, Error>) -> Void)?
    public var converterConfig: ESConverter.Config = .default

    public func activate(completion: @escaping (Result<es_new_client_result_t, Error>) -> Void) {
        activate(async: true, completion: completion)
    }

    public func activate() throws -> es_new_client_result_t {
        var result: Result<es_new_client_result_t, Error>!
        activate(async: false) { result = $0 }
        return try result.get()
    }

    public func invalidate() {
        connection.invalidate()
    }

    private func activate(async: Bool, completion: @escaping (Result<es_new_client_result_t, Error>) -> Void) {
        delegate.queue = queue
        delegate.pathInterestHandler = pathInterestHandler
        delegate.authMessageHandler = authMessageHandler
        delegate.notifyMessageHandler = notifyMessageHandler
        delegate.receiveCustomMessageHandler = receiveCustomMessageHandler

        connection.connectionStateHandler = { [weak self] in self?.handleConnectionStateChanged($0) }
        connection.converterConfig = converterConfig

        connection.connect(async: async, notify: completion)
    }
    
    private func handleConnectionStateChanged(_ result: Result<es_new_client_result_t, Error>) {
        let events = Array(subscribedEvents.read())
        if result.success == ES_NEW_CLIENT_RESULT_SUCCESS, !events.isEmpty {
            subscribe(events) { _ in }
        }
        
        connectionStateHandler?(result)
    }

    // MARK: - ES Client
    // MARK: Messages
    
    /// Handler invoked each time AUTH message is coming from EndpointSecurity.
    /// The message SHOULD be responded using the second parameter - reply block.
    public var authMessageHandler: ((ESMessage, @escaping (ESAuthResolution) -> Void) -> Void)?
    
    /// Handler invoked each time NOTIFY message is coming from EndpointSecurity.
    public var notifyMessageHandler: ((ESMessage) -> Void)?
    
    /// Queue where `pathInterestHandler`, `authMessageHandler`, `postAuthMessageHandler`
    /// and `notifyMessageHandler` handlers are called.
    public var queue: DispatchQueue?
    
    /// Subscribe to some set of events
    /// - Parameters:
    ///     - events: Array of es_event_type_t to subscribe to
    ///     - returns: Boolean indicating success or error
    /// - Note: Subscribing to new event types does not remove previous subscriptions
    public func subscribe(_ events: [es_event_type_t], completion: @escaping (Bool) -> Void) {
        subscribedEvents.writeAsync { $0.formUnion(events) }
        remoteObjectProxy(completion)?.subscribe(events.map { NSNumber(value: $0.rawValue) }, reply: completion)
    }
    
    /// Unsubscribe from some set of events
    /// - Parameters:
    ///     - events: Array of es_event_type_t to unsubscribe from
    ///     - returns: Boolean indicating success or error
    /// - Note: Events not included in the given `events` array that were previously subscribed to
    ///         will continue to be subscribed to
    public func unsubscribe(_ events: [es_event_type_t], completion: @escaping (Bool) -> Void) {
        subscribedEvents.writeAsync { $0.subtract(events) }
        remoteObjectProxy(completion)?.unsubscribe(events.map { NSNumber(value: $0.rawValue) }, reply: completion)
    }
    
    /// Unsubscribe from all events
    /// - Parameters:
    ///     - returns: Boolean indicating success or error
    public func unsubscribeAll(completion: @escaping (Bool) -> Void) {
        subscribedEvents.writeAsync { $0.removeAll() }
        remoteObjectProxy(completion)?.unsubscribeAll(reply: completion)
    }
    
    /// Clear all cached results for all clients.
    /// - Parameters:
    ///     - returns: es_clear_cache_result_t value indicating success or an error
    public func clearCache(completion: @escaping (es_clear_cache_result_t) -> Void) {
        remoteObjectProxy { _ in completion(ES_CLEAR_CACHE_RESULT_ERR_INTERNAL) }?.clearCache(reply: completion)
    }
    
    // MARK: Interest
    
    /// Perform process filtering, additionally to muting of path and processes.
    /// Filtering is based on `interest in particular process executable path`.
    /// Designed to be used for granular process filtering by ignoring uninterest events.
    ///
    /// General idea is to mute or ignore processes we are not interested in using their binary paths.
    /// Usually the OS would not have more than ~1000 unique processes, so asking for interest in particular
    /// process path would occur very limited number of times.
    ///
    /// The process may be interested or ignored accoding to returned `ESInterest`.
    /// If the process is not interested, all related messages are skipped.
    /// More information on `ESMuteResolution` see in related documentation.
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
    public var pathInterestHandler: ((ESProcess) -> ESInterest)?
    
    /// Clears the cache related to process interest by path.
    /// All processes will be re-evaluated against mute rules and `pathInterestHandler`.
    public func clearPathInterestCache(completion: @escaping (Bool) -> Void) {
        remoteObjectProxy(completion)?.clearPathInterestCache(reply: completion)
    }
    
    // MARK: Mute
    
    /// Suppress events from the process described by the given `mute` rule.
    /// - Parameters:
    ///     - mute: process to mute.
    ///     - events: set of events to mute.
    public func muteProcess(_ rule: ESMuteProcessRule, events: ESEventSet = .all, completion: @escaping (Bool) -> Void) {
        if let (proxy, encoded) = withEncoded(rule, actionName: "muteProcess", reply: completion) {
            proxy.muteProcess(encoded, events: events.asNumbers, reply: completion)
        }
    }
    
    /// Unmute events for the process described by the given `mute` rule.
    /// - Parameters:
    ///     - mute: process to unmute.
    ///     - events: set of events to mute.
    public func unmuteProcess(_ rule: ESMuteProcessRule, events: ESEventSet = .all, completion: @escaping (Bool) -> Void) {
        if let (proxy, encoded) = withEncoded(rule, actionName: "unmuteProcess", reply: completion) {
            proxy.muteProcess(encoded, events: events.asNumbers, reply: completion)
        }
    }
    
    /// Unmute all events for all processes. Clear the rules.
    public func unmuteAllProcesses(completion: @escaping (Bool) -> Void) {
        remoteObjectProxy(completion)?.unmuteAllProcesses(reply: completion)
    }
    
    /// Suppress events for the the given at path and type.
    /// - Parameters:
    ///     - mute: process path to mute.
    ///     - type: path type.
    ///     - events: set of events to mute.
    public func mutePath(_ path: String, type: es_mute_path_type_t, events: ESEventSet = .all, completion: @escaping (Bool) -> Void) {
        remoteObjectProxy(completion)?.mutePath(path, type: type, events: events.asNumbers, reply: completion)
    }
    
    /// Unmute events for the given at path and type.
    /// - Parameters:
    ///     - mute: process path to unmute.
    ///     - type: path type.
    ///     - events: set of events to unmute.
    @available(macOS 12.0, *)
    public func unmutePath(_ path: String, type: es_mute_path_type_t, events: ESEventSet = .all, completion: @escaping (Bool) -> Void) {
        remoteObjectProxy(completion)?.unmutePath(path, type: type, events: events.asNumbers, reply: completion)
    }
    
    /// Unmute all events for all process paths.
    public func unmuteAllPaths(completion: @escaping (Bool) -> Void) {
        remoteObjectProxy(completion)?.unmuteAllPaths(reply: completion)
    }
    
    /// Unmute all target paths. Works only for macOS 13.0+.
    @available(macOS 13.0, *)
    public func unmuteAllTargetPaths(completion: @escaping (Bool) -> Void) {
        remoteObjectProxy(completion)?.unmuteAllTargetPaths(reply: completion)
    }
    
    /// Invert the mute state of a given mute dimension.
    @available(macOS 13.0, *)
    public func invertMuting(_ muteType: es_mute_inversion_type_t, completion: @escaping (Bool) -> Void) {
        remoteObjectProxy(completion)?.invertMuting(muteType, reply: completion)
    }
    
    /// Mute state of a given mute dimension.
    @available(macOS 13.0, *)
    public func mutingInverted(_ muteType: es_mute_inversion_type_t, completion: @escaping (Bool) -> Void) {
        remoteObjectProxy(completion)?.mutingInverted(muteType, reply: completion)
    }
    
    // MARK: - Custom Messages
    
    public var receiveCustomMessageHandler: ((Data, @escaping (Result<Data, Error>) -> Void) -> Void)?
    
    public func sendCustomMessage(_ data: Data, completion: @escaping (Result<Data, Error>) -> Void) {
        if let proxy = connection.remoteObjectProxy({ completion(.failure($0)) }) {
            proxy.sendCustomMessage(data) { completion(Result(success: $0, failure: $1)) }
        } else {
            completion(.failure(CommonError.unexpected("ESXPCConnection not established")))
        }
    }
    
    // MARK: Utils
    
    private func remoteObjectProxy(_ errorHandler: @escaping (Bool) -> Void) -> ESClientXPCProtocol? {
        connection.remoteObjectProxy { _ in errorHandler(false) }
    }
    
    private func withEncoded(
        _ value: Encodable, actionName: String, reply: @escaping (Bool) -> Void
    ) -> (ESClientXPCProtocol, Data)? {
        guard let proxy = remoteObjectProxy(reply) else { return nil }
        do {
            let encoded = try xpcEncoder.encode(value)
            return (proxy, encoded)
        } catch {
            return nil
        }
    }
}

private class ESClientXPCDelegate: NSObject, ESClientXPCDelegateProtocol {
    var queue: DispatchQueue?
    var pathInterestHandler: ((ESProcess) -> ESInterest)?
    var authMessageHandler: ((ESMessage, @escaping (ESAuthResolution) -> Void) -> Void)?
    var notifyMessageHandler: ((ESMessage) -> Void)?
    var receiveCustomMessageHandler: ((Data, @escaping (Result<Data, Error>) -> Void) -> Void)?

    var errorLogHandler: ((Error) -> Void)?
    
    private static let fallback = ESAuthResolution.allowOnce

    func handlePathInterest(_ data: Data, reply: @escaping (Data?) -> Void) {
        guard let pathInterestHandler else {
            reply(nil); return
        }
        guard let process = decode(ESProcess.self, from: data, actionName: "handlePathInterest") else {
            reply(nil); return
        }
        
        queue.async {
            let interest = pathInterestHandler(process)
            let encoded = interest.encode(with: .json(encoder: xpcEncoder), log: log)
            reply(encoded)
        }
    }
    
    func handleAuth(_ message: Data, reply: @escaping (UInt32, Bool) -> Void) {
        guard let authMessageHandler else {
            reply(Self.fallback.result.rawValue, Self.fallback.cache)
            log.warning("Auth message came but no authMessageHandler installed")
            return
        }
        guard let decoded = decode(ESMessage.self, from: message, actionName: "handleAuth") else {
            return
        }
        queue.async { authMessageHandler(decoded) { reply($0.result.rawValue, $0.cache) } }
    }

    func handleNotify(_ message: Data) {
        guard let notifyMessageHandler = notifyMessageHandler else {
            log.warning("Notify message came but no notifyMessageHandler installed")
            return
        }
        guard let decoded = decode(ESMessage.self, from: message, actionName: "handleNotify") else {
            return
        }
        queue.async { notifyMessageHandler(decoded) }
    }

    func receiveCustomMessage(_ data: Data, completion: @escaping (Data?, Error?) -> Void) {
        if let receiveCustomMessageHandler {
            queue.async { receiveCustomMessageHandler(data) { completion($0.success, $0.failure) } }
        } else {
            completion(nil, CommonError.unexpected("receiveCustomMessageHandler not set"))
        }
    }
    
    private func decode<T: Decodable>(_ type: T.Type, from data: Data, actionName: String) -> T? {
        do {
            return try xpcDecoder.decode(T.self, from: data)
        } catch {
            log.error("Failed to decode \(type) for \(actionName). Error: \(error)")
            return nil
        }
    }
}

extension ESEventSet {
    fileprivate var asNumbers: [NSNumber] {
        events.map { NSNumber(value: $0.rawValue) }
    }
}
