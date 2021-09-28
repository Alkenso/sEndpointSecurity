//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 27.09.2021.
//

import Combine
import EndpointSecurity
import Foundation
import SwiftConvenience


public class ESXPCService: NSObject {
    public var verifyConnectionHandler: ((audit_token_t) -> Bool)?
    public var receiveCustomMessageHandler: ((_ message: ESXPCCustomMessage, _ peer: UUID) -> Void)?
    public var notifyErrorHandler: ((Error) -> Void)?
    
    
    public init(listener: NSXPCListener, createClient: @escaping () throws -> ESClient) {
        _listener = listener
        _createClient = createClient
        
        super.init()
        
        _listener.delegate = self
    }
    
    public func activate() {
        _listener.resume()
    }
    
    public func sendCustomMessage(_ message: ESXPCCustomMessage, to peer: UUID) {
        _sendCustomMessage.notify((message, peer))
    }
    
    
    // MARK: Private
    private let _sendCustomMessage = Notifier<(message: ESXPCCustomMessage, peer: UUID)>()
    private let _createClient: () throws -> ESClient
    private let _listener: NSXPCListener
}

extension ESXPCService: NSXPCListenerDelegate {
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        guard verifyConnectionHandler?(newConnection.auditToken) ?? true else { return false }
        
        newConnection.exportedInterface = .esClient
        newConnection.remoteObjectInterface = .esClientDelegate
        guard let delegate = newConnection.remoteObjectProxy as? ESClientXPCDelegateProtocol else {
            let error = CommonError.cast(newConnection.remoteObjectProxy, to: ESClientXPCDelegateProtocol.self)
            notifyErrorHandler?(error)
            return false
        }
        
        let client = createClient(delegate)
        newConnection.exportedObject = client
        newConnection.resume()
        
        return true
    }
    
    private func createClient(_ delegate: ESClientXPCDelegateProtocol) -> ESXPCServiceClient {
        let client = ESXPCServiceClient(delegate: delegate, createClient: _createClient)
        
        client.receiveCustomMessageHandler = { [weak self, clientID = client.id] in
            self?.receiveCustomMessageHandler?($0, clientID)
        }
        
        client.notifyErrorHandler = notifyErrorHandler
        
        client.parentSubscription = _sendCustomMessage.register { [weak client] in
            guard let client = client, client.id == $0.peer else { return }
            client.sendCustomMessage($0.message)
        }
        
        return client
    }
}

class ESXPCServiceClient: NSObject, ESClientXPCProtocol {
    let id = UUID()
    var receiveCustomMessageHandler: ((ESXPCCustomMessage) -> Void)?
    var notifyErrorHandler: ((Error) -> Void)?
    var parentSubscription: Any?
    
    
    init(delegate: ESClientXPCDelegateProtocol, createClient: @escaping () throws -> ESClient) {
        _delegate = delegate
        _createClient = createClient
    }
    
    func sendCustomMessage(_ message: ESXPCCustomMessage) {
        _sendCustomMessage.notify(message)
    }
    
    func create(completion: @escaping (es_new_client_result_t) -> Void) {
        do {
            let client = try _createClient()
            defer { _client = client }
            
            client.authMessage.register(on: _queue) { [weak self] message, authCompletion in
                guard let self = self else { return authCompletion(.allowOnce) }
                self.handleAuthMessage(message, completion: authCompletion)
            }
            .store(in: &_cancellables)
            
            client.notifyMessage.register(on: _queue) { [weak self] in
                guard let xpcMessage = self?.encodeMessage($0) else { return }
                self?._delegate.handleNotify(xpcMessage)
            }
            .store(in: &_cancellables)
            
            _sendCustomMessage.register { [weak self] in
                self?._delegate.custom(id: $0.id, payload: $0.payload, isReply: $0.isReply) {}
            }
            .store(in: &_cancellables)
            
            completion(ES_NEW_CLIENT_RESULT_SUCCESS)
        } catch {
            if case let .create(status) = error as? ESClientCreateError {
                completion(status)
            } else {
                completion(ES_NEW_CLIENT_RESULT_ERR_INTERNAL)
            }
        }
    }
    
    func subscribe(_ events: [NSNumber], reply: @escaping (Bool) -> Void) {
        DispatchQueue.global().async {
            let converted = events.map(\.uint32Value).map(es_event_type_t.init(rawValue:))
            reply(self._client?.subscribe(converted) ?? false)
        }
    }
    
    func unsubscribe(_ events: [NSNumber], reply: @escaping (Bool) -> Void) {
        DispatchQueue.global().async {
            let converted = events.map(\.uint32Value).map(es_event_type_t.init(rawValue:))
            reply(self._client?.unsubscribe(converted) ?? false)
        }
    }
    
    func unsubscribeAll(reply: @escaping (Bool) -> Void) {
        DispatchQueue.global().async {
            reply(self._client?.unsubscribeAll() ?? false)
        }
    }
    
    func clearCache(reply: @escaping (es_clear_cache_result_t) -> Void) {
        DispatchQueue.global().async {
            reply(self._client?.clearCache() ?? ES_CLEAR_CACHE_RESULT_ERR_INTERNAL)
        }
    }
    
    func muteProcess(_ mute: ESMuteProcessXPC, reply: @escaping (Bool) -> Void) {
        DispatchQueue.global().async {
            guard let decoded = self.decodeMute(mute) else { return reply(false) }
            reply(self._client?.muteProcess(decoded) ?? false)
        }
    }
    
    func unmuteProcess(_ mute: ESMuteProcessXPC, reply: @escaping (Bool) -> Void) {
        DispatchQueue.global().async {
            guard let decoded = self.decodeMute(mute) else { return reply(false) }
            reply(self._client?.unmuteProcess(decoded) ?? false)
        }
    }
    
    func mutePath(prefix: String, reply: @escaping (Bool) -> Void) {
        DispatchQueue.global().async {
            reply(self._client?.mutePath(prefix: prefix) ?? false)
        }
    }
    
    func mutePath(literal: String, reply: @escaping (Bool) -> Void) {
        DispatchQueue.global().async {
            reply(self._client?.mutePath(literal: literal) ?? false)
        }
    }
    
    func unmuteAllPaths(reply: @escaping (Bool) -> Void) {
        DispatchQueue.global().async {
            reply(self._client?.unmuteAllPaths() ?? false)
        }
    }
    
    func custom(id: UUID, payload: Data, isReply: Bool, reply: @escaping () -> Void) {
        DispatchQueue.global().async {
            self.receiveCustomMessageHandler?(
                ESXPCCustomMessage(id: id, payload: payload, isReply: isReply)
            )
            reply()
        }
    }
    
    
    // MARK: Private
    private let _sendCustomMessage = Notifier<ESXPCCustomMessage>()
    private let _queue = DispatchQueue(label: "ESXPCServiceClient.queue")
    private let _createClient: () throws -> ESClient
    private let _delegate: ESClientXPCDelegateProtocol
    private var _cancellables: [AnyCancellable] = []
    private var _client: ESClient?
    
    
    private func handleAuthMessage(
        _ message: ESMessagePtr,
        completion: @escaping (ESAuthResolution) -> Void
    ) {
        guard let remoteObject = _delegate as? NSXPCProxyCreating else {
            completion(.allowOnce)
            return
        }
        
        let proxy = remoteObject.remoteObjectProxyWithErrorHandler { [weak self] in
            completion(.allowOnce)
            self?.notifyErrorHandler?($0)
        }
        
        guard let delegateProxy = proxy as? ESClientXPCDelegateProtocol else {
            completion(.allowOnce)
            notifyErrorHandler?(
                CommonError.fatal(
                    "Failed to cast \(proxy) to \(ESClientXPCDelegateProtocol.self)"
                )
            )
            return
        }
        
        guard let xpcMessage = encodeMessage(message) else {
            completion(.allowOnce)
            return
        }
        delegateProxy.handleAuth(xpcMessage) {
            completion(ESAuthResolution(result: .flags($0), cache: $1))
        }
    }
    
    private func encodeMessage(_ message: ESMessagePtr) -> ESMessagePtrXPC? {
        do {
            return try message.serialize()
        } catch {
            notifyErrorHandler?(error)
            return nil
        }
    }
    
    private func decodeMute(_ mute: ESMuteProcessXPC) -> ESMuteProcess? {
        do {
            return try JSONDecoder().decode(ESMuteProcess.self, from: mute)
        } catch {
            notifyErrorHandler?(error)
            return nil
        }
    }
}
