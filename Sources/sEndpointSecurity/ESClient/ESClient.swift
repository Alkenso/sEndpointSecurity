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

import Combine
import EndpointSecurity
import Foundation
import SwiftConvenience

private let log = SCLogger.internalLog(.client)

public final class ESClient: ESClientProtocol {
    /// Initialise a new ESClient and connect to the ES subsystem. No-throw version
    /// Subscribe to some set of events
    /// - Parameters:
    ///     - status: Out parameter indicating status on initialization result
    public convenience init?(_ name: String? = nil, status: inout es_new_client_result_t) {
        do {
            try self.init(name)
            status = ES_NEW_CLIENT_RESULT_SUCCESS
        } catch {
            status = (error as? ESError<es_new_client_result_t>)?.result ?? ES_NEW_CLIENT_RESULT_ERR_INTERNAL
            return nil
        }
    }
    
    /// Initialise a new ESClient and connect to the ES subsystem
    /// - throws: ESClientCreateError in case of error
    public convenience init(_ name: String? = nil) throws {
        var client: OpaquePointer!
        weak var weakSelf: ESClient?
        let status = es_new_client(&client) { innerClient, rawMessage in
            if let self = weakSelf {
                let message = ESMessagePtr(message: rawMessage)
                self.handleMessage(message)
            } else {
                _ = innerClient.esRespond(rawMessage, flags: .max, cache: false)
            }
        }
        
        try self.init(name: name, client: client, native: client, status: status)
        weakSelf = self
    }
    
    private init(name: String?, client: ESNativeClient?, native: OpaquePointer, status: es_new_client_result_t) throws {
        let name = name ?? "ESClient"
        guard let client, status == ES_NEW_CLIENT_RESULT_SUCCESS else {
            throw ESError("es_new_client", result: status, client: name)
        }
        
        _ = validESEvents(client)
        
        self.name = name
        self.client = client
        self.unsafeNativeClient = native
        self.pathMutes = ESMutePath(client: client)
        self.processMutes = ESMuteProcess(client: client)
        
        do {
            self.timebaseInfo = try mach_timebase_info.system()
        } catch {
            log.error("Failed to get timebase info: \(error)")
            self.timebaseInfo = nil
        }
        
        pathMutes.interestHandler = { [weak self] process in
            guard let self else { return .listen() }
            return self.queue.sync { self.pathInterestHandler?(process) ?? .listen() }
        }
    }
    
    deinit {
        if client.esUnsubscribeAll() != ES_RETURN_SUCCESS {
            log.warning("Failed to unsubscribeAll on ESClient.deinit")
        }
        if client.esDeleteClient() != ES_RETURN_SUCCESS {
            log.warning("Failed to deleteClient on ESClient.deinit")
        }
    }
    
    public var name: String
    
    public var config = Config()
    
    /// Reference to `es_client_t` used under the hood.
    /// DO NOT use it for modifyng any mutes/inversions/etc, the behaviour is undefined.
    /// You may want to use it for informational purposes (list of mutes, etc).
    public var unsafeNativeClient: OpaquePointer
    
    // MARK: Messages
    
    /// Handler invoked each time AUTH message is coming from EndpointSecurity.
    /// The message SHOULD be responded using the second parameter - reply block.
    public var authMessageHandler: ((ESMessagePtr, @escaping (ESAuthResolution) -> Void) -> Void)?
    
    /// Handler invoked for each AUTH message after it has been responded.
    /// Userful for statistic and post-actions.
    public var postAuthMessageHandler: ((ESMessagePtr, ResponseInfo) -> Void)?
    
    /// Handler invoked each time NOTIFY message is coming from EndpointSecurity.
    public var notifyMessageHandler: ((ESMessagePtr) -> Void)?
    
    /// Queue where `pathInterestHandler`, `authMessageHandler`, `postAuthMessageHandler`
    /// and `notifyMessageHandler` handlers are called.
    /// Defaults to `nil` that means all handlers are called directly on native `es_client` queue.
    public var queue: DispatchQueue?
    
    /// Subscribe to some set of events
    /// - Parameters:
    ///     - events: Array of es_event_type_t to subscribe to
    ///     - returns: Boolean indicating success or error
    /// - Note: Subscribing to new event types does not remove previous subscriptions
    public func subscribe(_ events: [es_event_type_t]) throws {
        try tryAction("esSubscribe", success: ES_RETURN_SUCCESS) {
            client.esSubscribe(events)
        }
    }
    
    /// Unsubscribe from some set of events
    /// - Parameters:
    ///     - events: Array of es_event_type_t to unsubscribe from
    ///     - returns: Boolean indicating success or error
    /// - Note: Events not included in the given `events` array that were previously subscribed to
    ///         will continue to be subscribed to
    public func unsubscribe(_ events: [es_event_type_t]) throws {
        try tryAction("esUnsubscribe", success: ES_RETURN_SUCCESS) {
            client.esUnsubscribe(events)
        }
    }
    
    /// Unsubscribe from all events
    /// - Parameters:
    ///     - returns: Boolean indicating success or error
    public func unsubscribeAll() throws {
        try tryAction("esUnsubscribe", success: ES_RETURN_SUCCESS) {
            client.esUnsubscribeAll()
        }
    }
    
    /// Clear all cached results for all clients.
    /// - Parameters:
    ///     - returns: es_clear_cache_result_t value indicating success or an error
    public func clearCache() throws {
        try tryAction("esUnsubscribe", success: ES_CLEAR_CACHE_RESULT_SUCCESS) {
            client.esClearCache()
        }
    }
    
    // MARK: Interest
    
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
    /// - `mute(path:)` rules
    /// - `mute(process:)` rules
    /// - `pathInterestHandler` resolution
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
    public func clearPathInterestCache() {
        pathMutes.clearIgnoreCache()
    }
    
    // MARK: Mute
    
    /// Suppress events from the process described by the given `mute` rule.
    /// - Parameters:
    ///     - mute: process to mute.
    ///     - events: set of events to mute.
    public func mute(process rule: ESMuteProcessRule, events: ESEventSet = .all) {
        guard let token = rule.token else { return }
        processMutes.mute(token, events: events.events)
    }
    
    /// Unmute events for the process described by the given `mute` rule.
    /// - Parameters:
    ///     - mute: process to unmute.
    ///     - events: set of events to mute.
    public func unmute(process rule: ESMuteProcessRule, events: ESEventSet = .all) {
        guard let token = rule.token else { return }
        processMutes.unmute(token, events: events.events)
    }
    
    /// Unmute all events for all processes. Clear the rules.
    public func unmuteAllProcesses() {
        processMutes.unmuteAll()
    }
    
    /// Suppress events for the the given at path and type.
    /// - Parameters:
    ///     - mute: process path to mute.
    ///     - type: path type.
    ///     - events: set of events to mute.
    public func mute(path: String, type: es_mute_path_type_t, events: ESEventSet = .all) throws {
        switch type {
        case ES_MUTE_PATH_TYPE_PREFIX, ES_MUTE_PATH_TYPE_LITERAL:
            pathMutes.mute(path, type: type, events: events.events)
        default:
            if #available(macOS 12.0, *) {
                try tryAction("esMutePathEvents", success: ES_RETURN_SUCCESS) {
                    client.esMutePathEvents(path, type, Array(events.events))
                }
            } else {
                try tryAction("esMutePathEvents", success: ES_RETURN_SUCCESS) { ES_RETURN_ERROR }
            }
        }
    }
    
    /// Unmute events for the given at path and type.
    /// - Parameters:
    ///     - mute: process path to unmute.
    ///     - type: path type.
    ///     - events: set of events to unmute.
    @available(macOS 12.0, *)
    public func unmute(path: String, type: es_mute_path_type_t, events: ESEventSet = .all) throws {
        switch type {
        case ES_MUTE_PATH_TYPE_PREFIX, ES_MUTE_PATH_TYPE_LITERAL:
            pathMutes.unmute(path, type: type, events: events.events)
        default:
            try tryAction("esUnmutePathEvents", success: ES_RETURN_SUCCESS) {
                client.esUnmutePathEvents(path, type, Array(events.events))
            }
        }
    }
    
    /// Unmute all events for all process paths.
    public func unmuteAllPaths() throws {
        try tryAction("unmuteAllPaths", success: ES_RETURN_SUCCESS) {
            pathMutes.unmuteAll() ? ES_RETURN_SUCCESS : ES_RETURN_ERROR
        }
    }
    
    /// Unmute all target paths. Works only for macOS 13.0+.
    @available(macOS 13.0, *)
    public func unmuteAllTargetPaths() throws {
        try tryAction("esUnmuteAllTargetPaths", success: ES_RETURN_SUCCESS) {
            client.esUnmuteAllTargetPaths()
        }
    }
    
    /// Invert the mute state of a given mute dimension.
    @available(macOS 13.0, *)
    public func invertMuting(_ muteType: es_mute_inversion_type_t) throws {
        let result: Bool
        switch muteType {
        case ES_MUTE_INVERSION_TYPE_PROCESS:
            result = processMutes.invertMuting()
        case ES_MUTE_INVERSION_TYPE_PATH:
            result = pathMutes.invertMuting()
        default:
            result = client.esInvertMuting(muteType) == ES_RETURN_SUCCESS
        }
        try tryAction("invertMuting(\(muteType))", success: ES_RETURN_SUCCESS) {
            result ? ES_RETURN_SUCCESS : ES_RETURN_ERROR
        }
    }
    
    /// Mute state of a given mute dimension.
    @available(macOS 13.0, *)
    public func mutingInverted(_ muteType: es_mute_inversion_type_t) throws -> Bool {
        let status = client.esMutingInverted(muteType)
        switch status {
        case ES_MUTE_INVERTED:
            return true
        case ES_MUTE_NOT_INVERTED:
            return false
        default:
            throw ESError<es_mute_inverted_return_t>("mutingInverted(\(muteType))", result: status, client: name)
        }
    }
    
    // MARK: Private

    private var client: ESNativeClient
    private let pathMutes: ESMutePath
    private let processMutes: ESMuteProcess
    private let timebaseInfo: mach_timebase_info?
    
    @inline(__always)
    private func handleMessage(_ message: ESMessagePtr) {
        let isMuted = checkIgnored(message)
        switch message.action_type {
        case ES_ACTION_TYPE_AUTH:
            guard let authMessageHandler, !isMuted else {
                respond(message, resolution: .allowOnce, reason: .muted)
                return
            }
            
            var item: DispatchWorkItem?
            if let timebaseInfo, let messageTimeout = config.messageTimeout {
                item = scheduleCancel(for: message, timebaseInfo: timebaseInfo, timeout: messageTimeout) {
                    self.respond(message, resolution: .allowOnce, reason: .timeout)
                }
            }
            
            queue.async {
                authMessageHandler(message) {
                    self.respond(message, resolution: $0, reason: .normal, timeoutItem: item)
                }
            }
        case ES_ACTION_TYPE_NOTIFY:
            guard !isMuted else { return }
            queue.async { self.notifyMessageHandler?(message) }
        default:
            log.warning("Unknown es_action_type = \(message.action_type)")
        }
    }
    
    @inline(__always)
    private func checkIgnored(_ message: ESMessagePtr) -> Bool {
        let event = message.event_type
        let converter = ESConverter(version: message.version)
        
        let path = converter.esString(message.process.pointee.executable.pointee.path)
        let token = message.process.pointee.audit_token
        lazy var process = converter.esProcess(message.process.pointee)
        
        guard !pathMutes.checkIgnored(event, path: path, process: process) else { return true }
        guard !processMutes.checkMuted(event, process: token) else { return true }
        
        return false
    }
    
    @inline(__always)
    private func respond(_ message: ESMessagePtr, resolution: ESAuthResolution, reason: ResponseReason, timeoutItem: DispatchWorkItem? = nil) {
        guard timeoutItem?.isCancelled != true else { return }
        timeoutItem?.cancel()
        
        let status = client.esRespond(message.rawMessage, flags: resolution.result.rawValue, cache: resolution.cache)
        
        if let postAuthMessageHandler {
            let responseInfo = ResponseInfo(reason: reason, resolution: resolution, status: status)
            queue.async { postAuthMessageHandler(message, responseInfo) }
        }
    }
    
    private func scheduleCancel(
        for message: ESMessagePtr,
        timebaseInfo: mach_timebase_info,
        timeout: Config.MessageTimeout,
        cancellation: @escaping () -> Void
    ) -> DispatchWorkItem? {
        let machInterval = message.deadline - message.mach_time
        let fullInterval = TimeInterval(machTime: machInterval, timebase: timebaseInfo)
        
        let interval: TimeInterval
        switch timeout {
        case .seconds(let seconds):
            interval = min(seconds, fullInterval)
        case .ratio(let ratio):
            interval = fullInterval * ratio.clamped(to: 0.0...1.0)
        }
        
        let item = DispatchWorkItem(block: cancellation)
        DispatchQueue.global().asyncAfter(deadline: .now() + interval, execute: item)
        
        return item
    }
}

extension ESClient {
    public struct Config: Equatable, Codable {
        public var messageTimeout: MessageTimeout?
        
        public enum MessageTimeout: Equatable, Codable {
            case ratio(Double) // 0...1.0
            case seconds(TimeInterval)
        }
        
        public init() {}
    }
    
    public enum ResponseReason: Equatable, Codable {
        case muted
        case timeout
        case normal
    }
    
    public struct ResponseInfo: Equatable, Codable {
        public var reason: ResponseReason
        public var resolution: ESAuthResolution
        public var status: es_respond_result_t
        
        public init(reason: ESClient.ResponseReason, resolution: ESAuthResolution, status: es_respond_result_t) {
            self.reason = reason
            self.resolution = resolution
            self.status = status
        }
    }
}

extension ESClient {
    /// For testing purposes only.
    internal static func test(newClient: (inout ESNativeClient?, @escaping es_handler_block_t) -> es_new_client_result_t) throws -> ESClient {
        var native: ESNativeClient?
        weak var weakSelf: ESClient?
        let status = newClient(&native) { _, rawMessage in
            if let self = weakSelf {
                let message = ESMessagePtr(unowned: rawMessage)
                self.handleMessage(message)
            } else {
                fatalError("ESClient.test if nil")
            }
        }
        
        let client = try ESClient(name: nil, client: native, native: OpaquePointer(bitPattern: 0xdeadbeef)!, status: status)
        weakSelf = client
        
        return client
    }
}

extension ESMuteProcessRule {
    fileprivate var token: audit_token_t? {
        switch self {
        case .token(let token):
            return token
        case .pid(let pid):
            do {
                return try audit_token_t(pid: pid)
            } catch {
                log.warning("Failed to get auditToken for pid = \(pid)")
                return nil
            }
        }
    }
}
