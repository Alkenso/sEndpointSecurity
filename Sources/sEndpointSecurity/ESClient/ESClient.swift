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

import Combine
import Foundation
import EndpointSecurity
import SwiftConvenience

private let log = SCLogger.internalLog(.client)

public class ESClient {
    public var config = Config()
    
    /// Perfonamce-sensitive handler, called **synchronously** for each message.
    /// Do here as minimum work as possible.
    /// To filter processes, use mute/unmute process methods.
    /// Provided ESProcess can be used to avoid parsing of whole message.
    public var messageFilterHandler: ((ESMessagePtr, ESProcess) -> Bool)?
    
    /// Handler invoked each time AUTH message is coming from EndpointSecurity.
    /// The message MUST be replied using the second parameter - reply block.
    public var authMessageHandler: ((ESMessagePtr, @escaping (ESAuthResolution) -> Void) -> Void)?
    
    /// Handler invoked for each AUTH message after it has been replied.
    /// Userful for statistic and post-actions.
    public var postAuthMessageHandler: ((ESMessagePtr, ResponseInfo) -> Void)?
    
    /// Handler invoked each time NOTIFY message is coming from EndpointSecurity.
    public var notifyMessageHandler: ((ESMessagePtr) -> Void)?
    
    /// Queue where all events are processed. Default to serial,  user-interactive queue.
    /// When customized, it may be concurrent as well
    public var eventQueue = DispatchQueue(label: "ESClient.event.queue", qos: .userInteractive)
    
    /// Initialise a new ESClient and connect to the ES subsystem. No-throw version
    /// Subscribe to some set of events
    /// - Parameters:
    ///     - status: Out parameter indicating status on initialization result
    public convenience init?(status: inout es_new_client_result_t) {
        do {
            try self.init()
            status = ES_NEW_CLIENT_RESULT_SUCCESS
        } catch {
            status = (error as? ESClientCreateError)?.status ?? ES_NEW_CLIENT_RESULT_ERR_INTERNAL
            return nil
        }
    }
    
    /// Initialise a new ESClient and connect to the ES subsystem
    /// - throws: ESClientCreateError in case of error
    public init() throws {
        do {
            _timebaseInfo = try mach_timebase_info.system()
        } catch {
            log.error("Failed to get timebase info: \(error)")
            _timebaseInfo = nil
        }
        
        let status = es_new_client(&_client) { [weak self] innerClient, message in
            if let self = self {
                self.handleMessage(message)
            } else {
                _ = innerClient.esFallback(message)
            }
        }
        
        guard status == ES_NEW_CLIENT_RESULT_SUCCESS else {
            throw ESClientCreateError(status: status)
        }
    }
    
    deinit {
        if let client = _client {
            _ = es_unsubscribe_all(client)
            es_delete_client(client)
        }
    }
    
    /// Subscribe to some set of events
    /// - Parameters:
    ///     - events: Array of es_event_type_t to subscribe to
    ///     - returns: Boolean indicating success or error
    /// - Note: Subscribing to new event types does not remove previous subscriptions
    public func subscribe(_ events: [es_event_type_t]) -> Bool {
        _client.esSubscribe(events) == ES_RETURN_SUCCESS
    }
    
    /// Unsubscribe from some set of events
    /// - Parameters:
    ///     - events: Array of es_event_type_t to unsubscribe from
    ///     - returns: Boolean indicating success or error
    /// - Note: Events not included in the given `events` array that were previously subscribed to
    ///         will continue to be subscribed to
    public func unsubscribe(_ events: [es_event_type_t]) -> Bool {
        _client.esUnsubscribe(events) == ES_RETURN_SUCCESS
    }
    
    /// Unsubscribe from all events
    /// - Parameters:
    ///     - returns: Boolean indicating success or error
    public func unsubscribeAll() -> Bool {
        es_unsubscribe_all(_client) == ES_RETURN_SUCCESS
    }
    
    /// Clear all cached results for all clients.
    /// - Parameters:
    ///     - returns: es_clear_cache_result_t value indicating success or an error
    public func clearCache() -> es_clear_cache_result_t {
        es_clear_cache(_client)
    }
    
    /// Suppress all events from the process described by the given `mute` rule
    /// - Parameters:
    ///     - mute: The rule to mute processes that match it
    ///     - returns: Boolean indicating success or error
    public func muteProcess(_ mute: ESMuteProcess) -> Bool {
        switch mute {
        case .token(var token):
            return es_mute_process(_client, &token) == ES_RETURN_SUCCESS
        case .pid(let pid):
            do {
                var token = try audit_token_t(pid: pid)
                return es_mute_process(_client, &token) == ES_RETURN_SUCCESS
            } catch {
                return false
            }
        case .euid, .name, .pathPrefix, .pathLiteral, .teamIdentifier, .signingID:
            eventQueue.async(flags: .barrier) { self._processMuteRules.insert(mute) }
            return true
        }
    }
    
    /// Unmute a process for all event types
    /// - Parameters:
    ///     - mute: The rule to unmute
    ///     - returns: Boolean indicating success or error
    public func unmuteProcess(_ mute: ESMuteProcess) -> Bool {
        switch mute {
        case .token(var token):
            return es_unmute_process(_client, &token) == ES_RETURN_SUCCESS
        case .pid(let pid):
            do {
                var token = try audit_token_t(pid: pid)
                return es_unmute_process(_client, &token) == ES_RETURN_SUCCESS
            } catch {
                return false
            }
        case .euid, .name, .pathPrefix, .pathLiteral, .teamIdentifier, .signingID:
            eventQueue.async(flags: .barrier) { self._processMuteRules.remove(mute) }
            return true
        }
    }
    
    public func mutePath(prefix: String) -> Bool {
        es_mute_path_prefix(_client, prefix) == ES_RETURN_SUCCESS
    }
    
    public func mutePath(literal: String) -> Bool {
        es_mute_path_literal(_client, literal) == ES_RETURN_SUCCESS
    }
    
    public func unmuteAllPaths() -> Bool {
        es_unmute_all_paths(_client) == ES_RETURN_SUCCESS
    }
    
    
    // MARK: Private
    private var _client: OpaquePointer!
    private let _timebaseInfo: mach_timebase_info?
    private var _processMuteRules: Set<ESMuteProcess> = []
    
    private func shoudMuteMessage(_ message: ESMessagePtr) -> Bool {
        let process =  ESConverter(version: message.version).esProcess(message.process)
        guard messageFilterHandler?(message, process) != false else { return true }
        let isMutes = _processMuteRules.contains { $0.matches(process: process) }
        return isMutes
    }
    
    private func handleMessage(_ rawMessage: UnsafePointer<es_message_t>) {
        let message = ESMessagePtr(message: rawMessage)
        eventQueue.async {
            self.processMessage(message)
        }
    }
    
    private func processMessage(_ message: ESMessagePtr) {
        let isMuted = shoudMuteMessage(message)
        
        switch message.action_type {
        case ES_ACTION_TYPE_AUTH:
            guard let authMessageHandler = authMessageHandler, !isMuted else {
                respond(message, resolution: .allowOnce, reason: .muted)
                return
            }
            
            let item = scheduleCancel(for: message) {
                self.respond(message, resolution: .allowOnce, reason: .timeout)
            }
            
            authMessageHandler(message) {
                self.respond(message, resolution: $0, reason: .normal, timeoutItem: item)
            }
        case ES_ACTION_TYPE_NOTIFY:
            guard !isMuted else { return }
            notifyMessageHandler?(message)
        default:
            log.warning("Unknown es_action type = \(message.action_type)")
            break
        }
    }
    
    private func respond(_ message: ESMessagePtr, resolution: ESAuthResolution, reason: ResponseReason, timeoutItem: DispatchWorkItem? = nil) {
        timeoutItem?.cancel()
        
        let status = _client.esResolve(message.unsafeRawMessage, flags: resolution.result.rawValue, cache: resolution.cache)
        
        let responseInfo = ResponseInfo(reason: reason, resolution: resolution, status: status)
        postAuthMessageHandler?(message, responseInfo)
    }
    
    private func scheduleCancel(for message: ESMessagePtr, cancellation: @escaping () -> Void) -> DispatchWorkItem? {
        guard let timebaseInfo = _timebaseInfo else { return nil }
        let machInterval = message.deadline - message.mach_time
        let fullInterval = TimeInterval(machTime: machInterval, timebase: timebaseInfo)
        
        let interval: TimeInterval
        switch config.messageTimeout {
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

public extension ESClient {
    struct Config {
        public var messageTimeout: MessageTimeout = .ratio(0.5)
        
        public enum MessageTimeout {
            case ratio(Double) // 0...1.0
            case seconds(TimeInterval)
        }
    }
    
    enum ResponseReason {
        case muted
        case timeout
        case normal
    }
    
    struct ResponseInfo {
        public var reason: ResponseReason
        public var resolution: ESAuthResolution
        public var status: es_respond_result_t
    }
}
