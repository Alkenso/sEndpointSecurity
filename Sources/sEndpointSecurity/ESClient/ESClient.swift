//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 16.09.2021.
//

import Combine
import Foundation
import EndpointSecurity
import SwiftConvenience


public struct ESAuthResolution: Equatable, Codable {
    public var result: ESAuthResult
    public var cache: Bool
}

public extension ESAuthResolution {
    static let allow = ESAuthResolution(result: .auth(true), cache: true)
    static let allowOnce = ESAuthResolution(result: .auth(true), cache: false)
    static let deny = ESAuthResolution(result: .auth(false), cache: true)
    static let denyOnce = ESAuthResolution(result: .auth(false), cache: false)
}

public enum ESMuteProcess: Hashable, Codable {
    // - Exact process
    case token(audit_token_t)
    case pid(pid_t)
    
    // - Patterns
    case euid(uid_t)
    
    case name(String)
    case pathPrefix(String)
    case pathLiteral(String)
    
    //  Codesign Team Identifier (DEVELOPMENT_TEAM in Xcode)
    case teamIdentifier(String)
    
    //  Usually equals to application bundle identifier
    case signingID(String)
}

public enum ESClientCreateError: Error {
    case create(es_new_client_result_t)
    case subscribe
    case other(Error)
}

public class ESClient {
    public var config = Config()
    
    /// Perfonamce-sensitive handler. Do as minimum work as possible.
    /// To filter processes, use mute/unmute process methods.
    public var filterMessageHandler: ((ESMessagePtr, ESProcess) -> Bool /* isIncluded */)?
    
    public var authMessageHandler: ((ESMessagePtr, _ reply: @escaping (ESAuthResolution) -> Void) -> Void)?
    public var postAuthMessageHandler: ((_ msg: ESMessagePtr, _ info: ResponseInfo) -> Void)?
    
    public var notifyMessageHandler: ((ESMessagePtr) -> Void)?
    
    
    public init() throws {
        _timebaseInfo = try ESClientCreateError.catching { try mach_timebase_info.system() }
        
        let status = es_new_client(&_client) { [weak self] innerClient, message in
            let handled = self?.handleMessage(message) ?? false
            if !handled {
                _ = innerClient.esFallback(message)
            }
        }
        
        guard status == ES_NEW_CLIENT_RESULT_SUCCESS else {
            throw ESClientCreateError.create(status)
        }
        
        let delete = DeinitAction { [_client] in es_delete_client(_client) }
        
        let mandatoryEvents = [
            ES_EVENT_TYPE_NOTIFY_EXIT
        ]
        guard _eventSubscriptions.subscribeMandatory(mandatoryEvents) == ES_RETURN_SUCCESS else {
            throw ESClientCreateError.subscribe
        }
        delete.release()
    }
    
    deinit {
        _ = es_unsubscribe_all(_client)
        es_delete_client(_client)
    }
    
    public func subscribe(_ events: [es_event_type_t]) -> Bool {
        _eventSubscriptions.subscribe(events) == ES_RETURN_SUCCESS
    }
    
    public func unsubscribe(_ events: [es_event_type_t]) -> Bool {
        _eventSubscriptions.unsubscribe(events) == ES_RETURN_SUCCESS
    }
    
    public func unsubscribeAll() -> Bool {
        _eventSubscriptions.unsubscribeAll() == ES_RETURN_SUCCESS
    }
    
    public func clearCache() -> es_clear_cache_result_t {
        es_clear_cache(_client)
    }
    
    public func muteProcess(_ mute: ESMuteProcess) -> Bool {
        _processMutes.mute(mute) == ES_RETURN_SUCCESS
    }
    
    public func unmuteProcess(_ mute: ESMuteProcess) -> Bool {
        _processMutes.unmute(mute) == ES_RETURN_SUCCESS
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
    private let _timebaseInfo: mach_timebase_info
    private lazy var _eventSubscriptions = EventSubscriptions(esClient: _client)
    private lazy var _processMutes = ProcessMutes(esClient: _client)
    private var _cachedProcesses: [audit_token_t: ESProcess] = [:]
    
    
    private func shoudMuteMessage(_ message: ESMessagePtr) -> Bool {
        let process = findProcess(for: message)
        guard filterMessageHandler?(message, process) != false else { return false }
        return _processMutes.isMuted(process)
    }
    
    private func handleMessage(_ message: UnsafePointer<es_message_t>) -> Bool {
        let isSubscribed = _eventSubscriptions.isSubscribed(message.pointee.event_type)
        if _eventSubscriptions.isSubscribed(message.pointee.event_type) {
            processMessage(message)
        }
        
        applySideEffects(message)
        
        return isSubscribed
    }
    
    private func processMessage(_ rawMessage: UnsafePointer<es_message_t>) {
        let message = ESMessagePtr(message: rawMessage)
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
            break
        }
    }
    
    private func respond(_ message: ESMessagePtr, resolution: ESAuthResolution, reason: ResponseReason?, timeoutItem: DispatchWorkItem? = nil) {
        timeoutItem?.cancel()
        
        let status = _client.esResolve(message.unsafeRawMessage, flags: resolution.result.rawValue, cache: resolution.cache)
        
        if let reason = reason {
            let responseInfo = ResponseInfo(reason: reason, resolution: resolution, status: status)
            postAuthMessageHandler?(message, responseInfo)
        }
    }
    
    private func applySideEffects(_ message: UnsafePointer<es_message_t>) {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            _processMutes.unmute(message.pointee.process.pointee.audit_token)
        default:
            break
        }
    }
    
    private func findProcess(for message: ESMessagePtr) -> ESProcess {
        let token = message.process.pointee.audit_token
        if let found = _cachedProcesses[token] {
            return found
        } else {
            let parsed = ESConverter(version: message.version).esProcess(message.process)
            _cachedProcesses[token] = parsed
            return parsed
        }
    }
    
    private func scheduleCancel(for message: ESMessagePtr, cancellation: @escaping () -> Void) -> DispatchWorkItem {
        let machInterval = message.deadline - message.mach_time
        let fullInterval = TimeInterval(machTime: machInterval, timebase: _timebaseInfo)
        
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

private extension ESClientCreateError {
    static func catching<R>(_ body: () throws -> R) rethrows -> R {
        do {
            return try body()
        } catch {
            throw ESClientCreateError.other(error)
        }
    }
}
