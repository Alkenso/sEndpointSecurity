//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 27.09.2021.
//

import EndpointSecurity
import Foundation
import SwiftConvenience


public class ESXPCClient {
    public let authMessage = TransformerOneToOne<ESMessagePtr, ESAuthResolution>(combine: ESAuthResolution.combine)
    public let notifyMessage = Notifier<ESMessagePtr>()
    public let customMessage = Notifier<ESXPCCustomMessage>()
    
    public var connectionState = Notifier<Result<es_new_client_result_t, Error>>()
    
    public var reconnectOnFailure: Bool = true
    public var logErrorHandler: ((Error) -> Void)?
    
    @Atomic private var _connection: ESXPCConnection
    private let _delegate: ESClientXPCDelegate
    
    
    // MARK: Initialization & Activation
    
    public convenience init(_ createConnection: @escaping @autoclosure () -> NSXPCConnection) {
        self.init(createConnection)
    }
    
    public init(_ createConnection: @escaping () -> NSXPCConnection) {
        let delegate = ESClientXPCDelegate()
        _connection = ESXPCConnection(delegate: delegate, createConnection: createConnection)
        _delegate = delegate
    }
    
    deinit {
        invalidate()
    }
    
    public func activate(completion: @escaping (Result<es_new_client_result_t, Error>) -> Void) {
        activate(async: true, completion: completion)
    }
    
    public func activate() throws -> es_new_client_result_t {
        var result: Result<es_new_client_result_t, Error>!
        activate(async: false) { result = $0 }
        return try result.get()
    }
    
    public func invalidate() {
        _connection.xpcConnection.invalidate()
    }
    
    
    private func activate(async: Bool, completion: @escaping (Result<es_new_client_result_t, Error>) -> Void) {
        _delegate.authMessageHandler = { [authMessage] in authMessage.async($0, completion: $1) }
        _delegate.notifyMessageHandler = notifyMessage.notify
        _delegate.customMessageHandler = customMessage.notify
        _delegate.errorLogHandler = logErrorHandler
        
        _connection.reconnectOnFailure = reconnectOnFailure
        _connection.connectionStateHandler = connectionState.notify
        
        _connection.connect(async: async, notify: completion)
    }
    
    
    // MARK: ES Client
    
    public func subscribe(_ events: [es_event_type_t], completion: @escaping (Result<Bool, Error>) -> Void) {
        remoteObjectProxy(completion)?.subscribe(xpcEvents(events)) { completion(.success($0)) }
    }
    
    public func unsubscribe(_ events: [es_event_type_t], completion: @escaping (Result<Bool, Error>) -> Void) {
        remoteObjectProxy(completion)?.unsubscribe(xpcEvents(events)) { completion(.success($0)) }
    }
    
    public func unsubscribeAll(completion: @escaping (Result<Bool, Error>) -> Void) {
        remoteObjectProxy(completion)?.unsubscribeAll { completion(.success($0)) }
    }
    
    public func clearCache(completion: @escaping (Result<es_clear_cache_result_t, Error>) -> Void) {
        remoteObjectProxy(completion)?.clearCache { completion(.success($0)) }
    }
    
    public func muteProcess(_ mute: ESMuteProcess, completion: @escaping (Result<Bool, Error>) -> Void) {
        guard let proxy = remoteObjectProxy(completion),
              let data = xpcEncode(mute, completion)
        else {
            return
        }
        proxy.muteProcess(data) { completion(.success($0)) }
    }
    
    public func unmuteProcess(_ mute: ESMuteProcess, completion: @escaping (Result<Bool, Error>) -> Void) {
        guard let proxy = remoteObjectProxy(completion),
              let data = xpcEncode(mute, completion)
        else {
            return
        }
        proxy.unmuteProcess(data) { completion(.success($0)) }
    }
    
    public func mutePath(prefix: String, completion: @escaping (Result<Bool, Error>) -> Void) {
        remoteObjectProxy(completion)?.mutePath(prefix: prefix) { completion(.success($0)) }
    }
    
    public func mutePath(literal: String, completion: @escaping (Result<Bool, Error>) -> Void) {
        remoteObjectProxy(completion)?.mutePath(literal: literal) { completion(.success($0)) }
    }
    
    public func unmuteAllPaths(completion: @escaping (Result<Bool, Error>) -> Void) {
        remoteObjectProxy(completion)?.unmuteAllPaths { completion(.success($0)) }
    }
    
    public func custom(_ custom: ESXPCCustomMessage, completion: @escaping (Error?) -> Void) {
        guard let proxy = remoteObjectProxy(completion) else { return }
        proxy.custom(id: custom.id, payload: custom.payload, isReply: custom.isReply) {
            completion(nil)
        }
    }
    
    
    private func remoteObjectProxy<T>(_ errorHandler: @escaping (Result<T, Error>) -> Void) -> ESClientXPCProtocol? {
        remoteObjectProxy { errorHandler(.failure($0)) }
    }
    
    private func remoteObjectProxy(_ errorHandler: @escaping (Error) -> Void) -> ESClientXPCProtocol? {
        let remoteObject = _connection.xpcConnection.remoteObjectProxyWithErrorHandler {
            errorHandler($0)
        }
        guard let proxy = remoteObject as? ESClientXPCProtocol else {
            let error = CommonError.unexpected("Failed cast \(remoteObject) to \(ESClientXPCProtocol.self)")
            errorHandler(error)
            return nil
        }
        return proxy
    }
    
    private func xpcEvents(_ events: [es_event_type_t]) -> [NSNumber] {
        events.map(\.rawValue).map(NSNumber.init)
    }
    
    private func xpcEncode<T: Encodable, R>(_ value: T, _ completion: @escaping (Result<R, Error>) -> Void) -> Data? {
        do {
            return try JSONEncoder().encode(value)
        } catch {
            completion(.failure(error))
            logErrorHandler?(error)
            return nil
        }
    }
}

public struct ESXPCCustomMessage {
    public var id: UUID
    public var payload: Data
    public var isReply: Bool
    
    public init(id: UUID, payload: Data, isReply: Bool) {
        self.id = id
        self.payload = payload
        self.isReply = isReply
    }
}

extension ESXPCCustomMessage {
    public static func request(_ payload: Data) -> Self {
        .init(id: UUID(), payload: payload, isReply: false)
    }
    
    public static func response(id: UUID, payload: Data) -> Self {
        .init(id: id, payload: payload, isReply: true)
    }
}

    
private class ESClientXPCDelegate: NSObject, ESClientXPCDelegateProtocol {
    var authMessageHandler: ((ESMessagePtr, @escaping (ESAuthResolution) -> Void) -> Void)?
    var notifyMessageHandler: ((ESMessagePtr) -> Void)?
    var customMessageHandler: ((ESXPCCustomMessage) -> Void)?
    
    var errorLogHandler: ((Error) -> Void)?
    
    
    func handleAuth(_ message: ESMessagePtrXPC, reply: @escaping (UInt32, Bool) -> Void) {
        do {
            let decoded = try ESMessagePtr(data: message)
            try authMessageHandler.get()(decoded) {
                reply($0.result.rawValue, $0.cache)
            }
        } catch {
            let resolution = ESAuthResolution.allowOnce
            reply(resolution.result.rawValue, resolution.cache)
            errorLogHandler?(error)
        }
        
    }
    
    func handleNotify(_ message: ESMessagePtrXPC) {
        do {
            let decoded = try ESMessagePtr(data: message)
            notifyMessageHandler?(decoded)
        } catch {
            errorLogHandler?(error)
        }
    }
    
    func custom(id: UUID, payload: Data, isReply: Bool, reply: @escaping () -> Void) {
        customMessageHandler?(ESXPCCustomMessage(id: id, payload: payload, isReply: isReply))
    }
}
