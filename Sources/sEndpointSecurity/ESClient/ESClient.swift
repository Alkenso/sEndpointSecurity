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

public class ESClient {
    public var config = Config()
    
    /// Handler invoked each time AUTH message is coming from EndpointSecurity.
    /// The message SHOULD be responded using the second parameter - reply block.
    public var authMessageHandler: ((ESMessagePtr, @escaping (ESAuthResolution) -> Void) -> Void)?
    
    /// Handler invoked for each AUTH message after it has been responded.
    /// Userful for statistic and post-actions.
    public var postAuthMessageHandler: ((ESMessagePtr, ResponseInfo) -> Void)?
    
    /// Handler invoked each time NOTIFY message is coming from EndpointSecurity.
    public var notifyMessageHandler: ((ESMessagePtr) -> Void)?
    
    /// Queue where `authMessageHandler`, `postAuthMessageHandler` and `notifyMessageHandler` handlers are called.
    /// Defaults to serial, user-interactive queue.
    /// `nil` means all handlers are called directly on native es_client queue.
    public var queue: DispatchQueue? = DispatchQueue(label: "ESClient.queue", qos: .userInteractive)
    
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
        
        guard status == ES_NEW_CLIENT_RESULT_SUCCESS else {
            throw ESClientCreateError(status: status)
        }
        
        self.client = client
        self.mutePath = ESMutePath(client: client)
        self.muteProcess = ESMuteProcess(client: client)
        
        weakSelf = self
    }
    
    deinit {
        if let client = client {
            if client.esUnsubscribeAll() != ES_RETURN_SUCCESS {
                log.warning("Failed to unsubscribeAll on ESClient.deinit")
            }
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
    
    // MARK: Mute
    
    /// Perform process filtering, additionally to mute path and process rules.
    /// Designed to be used for granular process filtering.
    ///
    /// The process may be muted and all related messages skipped accoding to returned `ESMuteResolution`.
    /// More information on `ESMuteResolution` see in related documentation.
    ///
    /// The final decision if the particular event is muted or not relies on multiple mute sources.
    /// If at least one of above matches the message's `event_type`, the message is muted.
    /// Sources considered:
    /// - `mutePath` rules
    /// - `muteProcess` rules
    /// - `processMuteHandler` resolution
    ///
    /// - Note: Mute resolutions are cached to avoid often handler calls.
    /// To reset cache, call `clearProcessMuteHandlerCache`.
    /// - Note: Behaviour when handler not set equals to returning `ESMuteResolution.allowAll`.
    ///
    /// - Warning: Perfonamce-sensitive handler, called **synchronously** for each process on `eventQueue`.
    /// Do here as minimum work as possible.
    public var processMuteHandler: ((ESProcess) -> ESMuteResolution)?
    
    /// Clears the cache related to process muting.
    /// All processes will be re-evaluated against mute rules and `processMuteHandler`.
    public func clearProcessMuteHandlerCache() {
        mutePath.clearAdditionalMutes()
        muteProcess.clearAdditionalMutes()
    }
    
    /// Suppress events from the process described by the given `mute` rule.
    /// - Parameters:
    ///     - mute: process to mute.
    ///     - events: set of events to mute.
    public func muteProcess(_ mute: ESMuteProcessRule, events: ESEventSet = .all) {
        guard let token = mute.token else { return }
        muteProcess.mute(token, events: events)
    }
    
    /// Unmute events for the process described by the given `mute` rule.
    /// - Parameters:
    ///     - mute: process to unmute.
    ///     - events: set of events to mute.
    public func unmuteProcess(_ mute: ESMuteProcessRule, events: ESEventSet = .all) {
        guard let token = mute.token else { return }
        muteProcess.unmute(token, events: events)
    }
    
    /// Unmute all events for all processes. Clear the rules.
    public func unmuteAllProcesses() {
        muteProcess.unmuteAll()
    }
    
    /// Suppress events for the process at path. Path is described by the `mute` rule.
    /// - Parameters:
    ///     - mute: process path to mute.
    ///     - events: set of events to mute.
    public func mutePath(_ mute: ESMutePathRule, events: ESEventSet = .all) {
        mutePath.mute(mute, events: events)
    }
    
    /// Unmute events for the process at path. Path is described by the `mute` rule.
    /// - Parameters:
    ///     - mute: process path to unmute.
    ///     - events: set of events to unmute.
    public func unmutePath(_ mute: ESMutePathRule, events: ESEventSet = .all) {
        mutePath.unmute(mute, events: events)
    }
    
    /// Unmute all events for all process paths. Clear the rules.
    public func unmuteAllPaths() {
        mutePath.unmuteAll()
    }
    
    /// Suppress a subset of events matching an event target path. Works only for macOS 13.0+.
    /// - Parameters:
    ///     - targetPath: path to be muted.
    ///     - type: mute type.
    ///     - events: set of events to mute.
    public func muteTargetPath(_ targetPath: String, type muteType: ESMutePathType, events: ESEventSet = .all) -> Bool {
        guard #available(macOS 13.0, *) else { return false }
        return client.esMutePathEvents(targetPath, muteType.targetPath, Array(events.events)) == ES_RETURN_SUCCESS
    }
    
    /// Unmute events of events matching an event target path. Works only for macOS 13.0+.
    /// - Parameters:
    ///     - targetPath: path to be unmuted.
    ///     - type: mute type.
    ///     - events: set of events to unmute.
    public func unmuteTargetPath(_ targetPath: String, type muteType: ESMutePathType, events: ESEventSet = .all) -> Bool {
        guard #available(macOS 13.0, *) else { return false }
        return client.esUnmutePathEvents(targetPath, muteType.targetPath, Array(events.events)) == ES_RETURN_SUCCESS
    }
    
    /// Unmute all target paths. Works only for macOS 13.0+.
    public func unmuteAllTargetPaths() {
        guard #available(macOS 13.0, *) else { return }
        if client.esUnmuteAllTargetPaths() != ES_RETURN_SUCCESS {
            log.warning("Failed to unmute all paths")
        }
    }
    
    /// Invert the mute state of a given mute dimension. Works only for macOS 13.0+.
    public func invertMuting(_ muteType: es_mute_inversion_type_t) -> Bool {
        guard #available(macOS 13.0, *) else { return false }
        return client.esInvertMuting(muteType) == ES_RETURN_SUCCESS
    }
    
    /// Mute state of a given mute dimension. Works only for macOS 13.0+.
    public func mutingInverted(_ muteType: es_mute_inversion_type_t) -> Bool? {
        guard #available(macOS 13.0, *) else { return false }
        
        switch client.esMutingInverted(muteType) {
        case ES_MUTE_INVERTED: return true
        case ES_MUTE_NOT_INVERTED: return false
        case ES_MUTE_INVERTED_ERROR: return nil
        default: return nil
        }
    }
    
    // MARK: Private
    
    private var client: OpaquePointer!
    private let timebaseInfo: mach_timebase_info?
    private let mutePath: ESMutePath
    private let muteProcess: ESMuteProcess
    
    private func handleMessage(_ message: ESMessagePtr) {
        let isMuted = checkMuted(message)
        switch message.action_type {
        case ES_ACTION_TYPE_AUTH:
            guard let authMessageHandler = authMessageHandler, !isMuted else {
                respond(message, resolution: .allowOnce, reason: .muted)
                return
            }
            
            let item = scheduleCancel(for: message) {
                self.respond(message, resolution: .allowOnce, reason: .timeout)
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
    
    private func checkMuted(_ message: ESMessagePtr) -> Bool {
        let converter = ESConverter(version: message.version)
        let path = converter.esString(message.process.pointee.executable.pointee.path)
        let token = message.process.pointee.audit_token
        let event = message.event_type
        
        if let isMutedByPath = mutePath.checkMutedByCache(path, event: event),
           let isMutedByProcess = muteProcess.checkMutedByCache(token, event: event) {
            return isMutedByPath || isMutedByProcess
        }
        
        let process = converter.esProcess(message.process)
        let filterResolution = processMuteHandler?(process) ?? .allowAll
        
        let isMutedByPath = mutePath.checkMuted(
            process, event: message.event_type, additionalyMuted: filterResolution.mutePathEvents
        )
        let isMutedByProcess = muteProcess.checkMuted(
            process, event: message.event_type, additionalyMuted: filterResolution.muteProcessEvents
        )
        
        return isMutedByPath || isMutedByProcess
    }
    
    private func respond(_ message: ESMessagePtr, resolution: ESAuthResolution, reason: ResponseReason, timeoutItem: DispatchWorkItem? = nil) {
        guard timeoutItem?.isCancelled != true else { return }
        timeoutItem?.cancel()
        
        let status = client.esRespond(message.rawMessage, flags: resolution.result.rawValue, cache: resolution.cache)
        
        let responseInfo = ResponseInfo(reason: reason, resolution: resolution, status: status)
        if let postAuthMessageHandler = postAuthMessageHandler {
            queue.async { postAuthMessageHandler(message, responseInfo) }
        }
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

private extension Optional where Wrapped == DispatchQueue {
    @inline(__always)
    func async(execute work: @escaping () -> Void) {
        if let self = self {
            self.async(execute: work)
        } else {
            work()
        }
    }
}

private struct ExecutableID: Hashable {
    var path: String
    var cdHash: Data
}
