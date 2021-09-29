//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 19.09.2021.
//

import EndpointSecurity
import Foundation
import SwiftConvenience




//public struct ESAsyncClient1 {
//    var behavior: Behavior
//
//    public var authMessage: EvaluationChain<ESMessagePtr, ESAuthResolution>
//    public var notifyMessage: NotificationChain<ESMessagePtr>
//
//    public func subscribe(_ events: [es_event_type_t], completion: @escaping (Bool) -> Void) {
//
//    }
//
//    public func unsubscribe(_ events: [es_event_type_t], completion: @escaping (Bool) -> Void) {
//
//    }
//
//    public func unsubscribeAll(completion: @escaping (Bool) -> Void) {
//
//    }
//
//    public func clearCache(events: [es_event_type_t], completion: @escaping (Bool) -> Void) {
//
//    }
//
//    public func clearAllCache(completion: @escaping (es_clear_cache_result_t) -> Void) {
//
//    }
//
//    public func muteProcess(_ mute: ESMuteProcess, completion: @escaping (Bool) -> Void) {
//
//    }
//
//    public func unmuteProcess(_ mute: ESMuteProcess, completion: @escaping (Bool) -> Void) {
//
//    }
//
//    public func unmuteAllProcesses(completion: @escaping (Bool) -> Void) {
//
//    }
//
//    public func mutePath(prefix: String, completion: @escaping (Bool) -> Void) {
//
//    }
//
//    public func mutePath(literal: String, completion: @escaping (Bool) -> Void) {
//
//    }
//
//    public func unmuteAllPaths(completion: @escaping (Bool) -> Void) {
//
//    }
//
//    public func custom(_ in: Data, completion: @escaping (_ out: Data) -> Void) {
//
//    }
//}

//extension ESAsyncClient1 {
//    public struct Behavior {
//        public var esReturn: (Result<es_return_t, Error>) -> Bool = { $0.value == ES_RETURN_SUCCESS }
//        public var esClearCacheResult: (Result<es_clear_cache_result_t, Error>) -> es_clear_cache_result_t = { $0.value ?? ES_CLEAR_CACHE_RESULT_ERR_INTERNAL }
//
//        public init() {}
//    }
//}


public class ESXPCConnection {
    public let client: ESXPCClient
    public var connectionStateChange = Notifier<Result<es_new_client_result_t, Error>>()
    
    public var reconnectOnFailure: Bool = true
    public var messageDecodingFailStrategy: ((Error) -> ESAuthResolution)?
    
    
    public convenience init(_ createConnection: @escaping @autoclosure () -> NSXPCConnection) {
        self.init(createConnection)
    }
    
    public init(_ createConnection: @escaping () -> NSXPCConnection) {
        let prepareConnection = { () -> NSXPCConnection in
            let connection = createConnection()
            connection.remoteObjectInterface = .esClient
            connection.exportedInterface = .esClientDelegate
            return connection
        }
        _createConnection = prepareConnection
        
        let dummyConnection = prepareConnection()
        dummyConnection.invalidate()
        client = ESXPCClient(connection: dummyConnection)
        client.messageDecodingFailStrategy = { [weak self] in self?.messageDecodingFailStrategy?($0) ?? .allowOnce }
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
        client.connection.invalidate()
    }
    
    
    // MARK: Private
    private let _createConnection: () -> NSXPCConnection
    
    
    private func activate(async: Bool, completion: @escaping (Result<es_new_client_result_t, Error>) -> Void) {
        connect(async: async, notify: completion)
    }
    
    private func reconnect() {
        guard reconnectOnFailure else { return }
        connect(async: true, notify: nil)
    }
    
    private func connect(async: Bool, notify: ((Result<es_new_client_result_t, Error>) -> Void)?) {
        let connection = _createConnection()
        connection.exportedObject = self
        connection.resume()

        let remoteObject = (async ? connection.remoteObjectProxyWithErrorHandler : connection.synchronousRemoteObjectProxyWithErrorHandler) { [weak self] in
            self?.handleConnect(.failure($0), notify: notify)
        }
        guard let proxy = remoteObject as? ESClientXPCProtocol else {
            let error = CommonError.cast(remoteObject, to: ESClientXPCProtocol.self)
            handleConnect(.failure(error), notify: notify)
            return
        }
        
        proxy.create { [weak self] in
            self?.handleConnect(.success(($0, connection)), notify: notify)
        }
    }

    private func handleConnect(
        _ result: Result<(result: es_new_client_result_t, connection: NSXPCConnection), Error>,
        notify: ((Result<es_new_client_result_t, Error>) -> Void)?
    ) {
        defer {
            let notifyResult = result.map(\.result)
            notify?(notifyResult)
            connectionStateChange.notify(notifyResult)
        }

        guard let value = result.value, value.result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            result.value?.connection.invalidate()
            scheduleReconnect()
            return
        }

        let invalidationHandler = { [weak self, weak connection = result.value?.connection] in
            connection?.invalidationHandler = nil
            connection?.interruptionHandler = nil
            self?.reconnect()
        }
        value.connection.invalidationHandler = invalidationHandler
        value.connection.interruptionHandler = invalidationHandler

        client.connection = value.connection
    }

    private func scheduleReconnect() {
        let reconnectDelay: TimeInterval = 3.0
        DispatchQueue.global().asyncAfter(deadline: .now() + reconnectDelay, execute: reconnect)
    }
}
