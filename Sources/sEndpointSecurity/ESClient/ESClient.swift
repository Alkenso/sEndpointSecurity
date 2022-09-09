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
import EndpointSecurity
import Foundation
import SwiftConvenience

private let log = SCLogger.internalLog(.client)

public class ESClient {
    public var config = Config()
    
    /// Perform process filtering, additionally to 'mute' rules.
    /// Should be used for granular process filtering.
    /// Return `false` if process should be muted and all related messages skipped.
    /// - Warning: Perfonamce-sensitive handler, called **synchronously** for each process.
    /// Do here as minimum work as possible.
    public var processFilterHandler: ((ESProcess) -> Bool)?
    
    /// Handler invoked each time AUTH message is coming from EndpointSecurity.
    /// The message SHOULD be responded using the second parameter - reply block.
    public var authMessageHandler: ((ESMessagePtr, @escaping (ESAuthResolution) -> Void) -> Void)?
    
    /// Handler invoked for each AUTH message after it has been responded.
    /// Userful for statistic and post-actions.
    public var postAuthMessageHandler: ((ESMessagePtr, ResponseInfo) -> Void)?
    
    /// Handler invoked each time NOTIFY message is coming from EndpointSecurity.
    public var notifyMessageHandler: ((ESMessagePtr) -> Void)?
    
    /// Queue where all events are processed. Default to serial, user-interactive queue.
    /// May be customized, both serial and concurrent queues are supported.
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
            self.timebaseInfo = try mach_timebase_info.system()
        } catch {
            log.error("Failed to get timebase info: \(error)")
            self.timebaseInfo = nil
        }
        
        let status = es_new_client(&client) { [weak self] innerClient, rawMessage in
            if let self = self {
                let message = ESMessagePtr(message: rawMessage)
                self.eventQueue.async { self.handleMessage(message) }
            } else {
                _ = innerClient.esRespond(rawMessage, flags: .max, cache: false)
            }
        }
        
        guard status == ES_NEW_CLIENT_RESULT_SUCCESS else {
            throw ESClientCreateError(status: status)
        }
    }
    
    deinit {
        if let client = client {
            _ = client.esUnsubscribeAll()
            es_delete_client(client)
        }
    }
    
    /// Subscribe to some set of events
    /// - Parameters:
    ///     - events: Array of es_event_type_t to subscribe to
    ///     - returns: Boolean indicating success or error
    /// - Note: Subscribing to new event types does not remove previous subscriptions
    public func subscribe(_ events: [es_event_type_t]) -> Bool {
        client.esSubscribe(events) == ES_RETURN_SUCCESS
    }
    
    /// Unsubscribe from some set of events
    /// - Parameters:
    ///     - events: Array of es_event_type_t to unsubscribe from
    ///     - returns: Boolean indicating success or error
    /// - Note: Events not included in the given `events` array that were previously subscribed to
    ///         will continue to be subscribed to
    public func unsubscribe(_ events: [es_event_type_t]) -> Bool {
        client.esUnsubscribe(events) == ES_RETURN_SUCCESS
    }
    
    /// Unsubscribe from all events
    /// - Parameters:
    ///     - returns: Boolean indicating success or error
    public func unsubscribeAll() -> Bool {
        client.esUnsubscribeAll() == ES_RETURN_SUCCESS
    }
    
    /// Clear all cached results for all clients.
    /// - Parameters:
    ///     - returns: es_clear_cache_result_t value indicating success or an error
    public func clearCache() -> es_clear_cache_result_t {
        client.esClearCache()
    }
    
    /// Clear muted processes (mute rules are not changed).
    /// All processes muted by 'processFilterHandler' or 'muteProcess' rules will be re-evaluated.
    public func clearMutedProcesses() {
        eventQueue.async(flags: .barrier) { [self] in
            guard let muted = client.esMutedProcesses() else {
                log.error("Failed to get muted processes")
                return
            }
            muted.forEach {
                if client.esUnmuteProcess($0) != ES_RETURN_SUCCESS {
                    log.error("Failed to unmute process with pid = \($0.pid)")
                }
            }
        }
    }
    
    /// Suppress all events from the process described by the given `mute` rule
    /// - Parameters:
    ///     - mute: The rule to mute processes that match it
    ///     - returns: Boolean indicating success or error
    public func muteProcess(_ mute: ESMuteProcess) -> Bool {
        if let result = muteNative(mute) {
            return result
        } else {
            eventQueue.async(flags: .barrier) { self.processMuteRules.insert(mute) }
            return true
        }
    }
    
    private func muteNative(_ mute: ESMuteProcess) -> Bool? {
        switch mute {
        case .token(var token):
            return es_mute_process(client, &token) == ES_RETURN_SUCCESS
        case .pid(let pid):
            do {
                var token = try audit_token_t(pid: pid)
                return es_mute_process(client, &token) == ES_RETURN_SUCCESS
            } catch {
                return false
            }
        case .path(let path, let type):
            if #available(macOS 12.0, *) {
                return client.esMutePath(path, type.esMutePathType) == ES_RETURN_SUCCESS
            } else {
                return nil
            }
        case .name, .euid, .teamIdentifier, .signingID:
            return nil
        }
    }
    
    /// Unmute a process for all event types
    /// - Parameters:
    ///     - mute: The rule to unmute
    ///     - returns: Boolean indicating success or error
    public func unmuteProcess(_ mute: ESMuteProcess) -> Bool {
        if let result = unmuteNative(mute) {
            return result
        } else {
            eventQueue.async(flags: .barrier) { self.processMuteRules.remove(mute) }
            return true
        }
    }
    
    private func unmuteNative(_ mute: ESMuteProcess) -> Bool? {
        switch mute {
        case .token(var token):
            return es_unmute_process(client, &token) == ES_RETURN_SUCCESS
        case .pid(let pid):
            do {
                var token = try audit_token_t(pid: pid)
                return es_unmute_process(client, &token) == ES_RETURN_SUCCESS
            } catch {
                return false
            }
        case .path(let path, let type):
            if #available(macOS 12.0, *) {
                return client.esUnmutePath(path, type.esMutePathType) == ES_RETURN_SUCCESS
            } else {
                return nil
            }
        case .name, .euid, .teamIdentifier, .signingID:
            return nil
        }
    }
    
    // MARK: Private

    private var client: OpaquePointer!
    private let timebaseInfo: mach_timebase_info?
    private var processMuteRules: Set<ESMuteProcess> = []
    
    private func handleMessage(_ message: ESMessagePtr) {
        let isMuted = shouldMute(message)
        if isMuted {
            _ = client.esMuteProcess(message.process.pointee.audit_token)
        }
        
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
        }
    }
    
    private func shouldMute(_ message: ESMessagePtr) -> Bool {
        let process = ESConverter(version: message.version).esProcess(message.process)
        guard processFilterHandler?(process) != false else { return true }
        return processMuteRules.contains { $0.matches(process: process) }
    }
    
    private func respond(_ message: ESMessagePtr, resolution: ESAuthResolution, reason: ResponseReason, timeoutItem: DispatchWorkItem? = nil) {
        guard timeoutItem?.isCancelled != true else { return }
        timeoutItem?.cancel()
        
        let status = client.esRespond(message.rawMessage, flags: resolution.result.rawValue, cache: resolution.cache)
        
        let responseInfo = ResponseInfo(reason: reason, resolution: resolution, status: status)
        postAuthMessageHandler?(message, responseInfo)
    }
    
    private func scheduleCancel(for message: ESMessagePtr, cancellation: @escaping () -> Void) -> DispatchWorkItem? {
        guard let timebaseInfo = timebaseInfo else { return nil }
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

extension ESClient {
    public struct Config: Equatable, Codable {
        public var messageTimeout: MessageTimeout = .ratio(0.5)
        
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
