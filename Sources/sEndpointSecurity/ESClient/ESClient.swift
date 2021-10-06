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


public class ESClient {
    public var config = Config()
    
    /// Perfonamce-sensitive handler, called **synchronously** for each message.
    /// Do as minimum work as possible.
    /// To filter processes, use mute/unmute process methods.
    /// Provided ESProcess can be used to avoid parsing of whole message.
    public var messageFilterHandler: ((ESMessagePtr, ESProcess) -> Bool)?
    
    public var authMessageHandler: ((ESMessagePtr, @escaping (ESAuthResolution) -> Void) -> Void)?
    public var postAuthMessageHandler: ((ESMessagePtr, ResponseInfo) -> Void)?
    
    public var notifyMessageHandler: ((ESMessagePtr) -> Void)?
    
    
    public convenience init?(status: inout es_new_client_result_t?) {
        do {
            try self.init()
        } catch {
            status = (error as? ESClientCreateError)?.status ?? ES_NEW_CLIENT_RESULT_ERR_INTERNAL
            return nil
        }
    }
    
    public init() throws {
        do {
            _timebaseInfo = try mach_timebase_info.system()
        } catch {
            log("Failed to get timebase info: \(error)")
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
        
        _processMutes.scheduleCleanup(on: _queue, interval: 10.0)
    }
    
    deinit {
        if let client = _client {
            _ = es_unsubscribe_all(client)
            es_delete_client(client)
        }
    }
    
    public func subscribe(_ events: [es_event_type_t]) -> Bool {
        _client.esSubscribe(events) == ES_RETURN_SUCCESS
    }
    
    public func unsubscribe(_ events: [es_event_type_t]) -> Bool {
        _client.esUnsubscribe(events) == ES_RETURN_SUCCESS
    }
    
    public func unsubscribeAll() -> Bool {
        es_unsubscribe_all(_client) == ES_RETURN_SUCCESS
    }
    
    public func clearCache() -> es_clear_cache_result_t {
        es_clear_cache(_client)
    }
    
    public func muteProcess(_ mute: ESMuteProcess) -> Bool {
        _queue.sync { _processMutes.mute(mute) == ES_RETURN_SUCCESS }
    }
    
    public func unmuteProcess(_ mute: ESMuteProcess) -> Bool {
        _queue.sync { _processMutes.unmute(mute) == ES_RETURN_SUCCESS }
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
    private let _queue = DispatchQueue(label: "ESClient.event.queue", qos: .userInteractive)
    private var _client: OpaquePointer!
    private let _timebaseInfo: mach_timebase_info?
    private lazy var _processMutes = ProcessMutes(esClient: _client)
    
    
    private func shoudMuteMessage(_ message: ESMessagePtr) -> Bool {
        let process =  ESConverter(version: message.version).esProcess(message.process)
        guard messageFilterHandler?(message, process) != false else { return false }
        return _processMutes.isMuted(process)
    }
    
    private func handleMessage(_ rawMessage: UnsafePointer<es_message_t>) {
        let message = ESMessagePtr(message: rawMessage)
        _queue.async {
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
            log("Unknown es_action type = \(message.action_type)")
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
