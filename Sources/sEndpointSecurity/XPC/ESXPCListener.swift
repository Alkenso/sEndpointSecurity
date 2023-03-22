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

private let log = SCLogger.internalLog(.xpc)

public final class ESXPCListener: NSObject {
    private let createClient: () throws -> ESClient
    private let listener: NSXPCListener
    private let sendCustomMessage = EventNotify<(data: Data, peer: UUID, reply: (Result<Data, Error>) -> Void)>()
    
    /// When receiving incoming conneciton, ESXPCListener creates one ESClient for each connection.
    /// `pathInterestHandler`, `authMessageHandler`, `notifyMessageHandler` are overriden by XPC engine.
    /// Rest handles can be setup prior to returning new client from `createClient`.
    public init(listener: NSXPCListener, createClient: @escaping () throws -> ESClient) {
        self.listener = listener
        self.createClient = createClient
        
        super.init()
        
        listener.delegate = self
    }
    
    public var verifyConnectionHandler: ((audit_token_t) -> Bool)?
    public var receiveCustomMessageHandler: ((Data, UUID, @escaping (Result<Data, Error>) -> Void) -> Void)?
    
    public func activate() {
        listener.resume()
    }
    
    public func sendCustomMessage(_ data: Data, to peer: UUID, reply: @escaping (Result<Data, Error>) -> Void) {
        sendCustomMessage.notify((data, peer, reply))
    }
    
    // MARK: Private
}

extension ESXPCListener: NSXPCListenerDelegate {
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        guard verifyConnectionHandler?(newConnection.auditToken) ?? true else { return false }
        
        newConnection.exportedInterface = .esClient
        newConnection.remoteObjectInterface = .esClientDelegate
        guard let delegate = newConnection.remoteObjectProxy as? ESClientXPCDelegateProtocol else {
            let error = CommonError.cast(newConnection.remoteObjectProxy, to: ESClientXPCDelegateProtocol.self)
            log.fatal("Failed to accept new connection. Error: \(error)")
            return false
        }
        
        let client = createExportedObject(delegate)
        newConnection.exportedObject = client
        newConnection.invalidationHandler = { [weak client, weak newConnection] in
            client?.unsubscribeAll(reply: { _ in })
            newConnection?.invalidationHandler = nil
        }
        newConnection.interruptionHandler = { [weak newConnection] in
            newConnection?.interruptionHandler = nil
            newConnection?.invalidate()
        }
        newConnection.resume()
        
        return true
    }
    
    private func createExportedObject(_ delegate: ESClientXPCDelegateProtocol) -> ESXPCExportedObject {
        let exportedClient = ESXPCExportedObject(delegate: delegate, createClient: createClient)
        
        exportedClient.receiveCustomMessageHandler = { [weak self, clientID = exportedClient.id] in
            self?.receiveCustomMessageHandler?($0, clientID, $1)
        }
        
        exportedClient.parentSubscription = sendCustomMessage.subscribe { [weak exportedClient] in
            guard let exportedClient, exportedClient.id == $0.peer else { return }
            exportedClient.receiveCustomMessage($0.data, reply: $0.reply)
        }
        
        return exportedClient
    }
}

private final class ESXPCExportedObject: NSObject, ESClientXPCProtocol {
    let id = UUID()
    
    init(delegate: ESClientXPCDelegateProtocol, createClient: @escaping () throws -> ESClient) {
        self.delegate = delegate
        self.createClient = createClient
    }
    
    var receiveCustomMessageHandler: ((Data, @escaping (Result<Data, Error>) -> Void) -> Void)?
    var parentSubscription: Any?
    
    func receiveCustomMessage(_ data: Data, reply: @escaping (Result<Data, Error>) -> Void) {
        delegate.receiveCustomMessage(data) { reply(Result(success: $0, failure: $1)) }
    }
    
    func create(converterConfig: Data, completion: @escaping (es_new_client_result_t) -> Void) {
        do {
            self.converterConfig = try xpcDecoder.decode(ESConverter.Config.self, from: converterConfig)
            
            let client = try createClient()
            client.pathInterestHandler = { [weak self] in self?.handlePathInterest($0) ?? .listen() }
            client.authMessageHandler = { [weak self] in self?.handleAuthMessage($0, completion: $1) }
            client.notifyMessageHandler = { [weak self] in self?.handleNotifyMessage($0) }
            
            self.client = client
            
            completion(ES_NEW_CLIENT_RESULT_SUCCESS)
        } catch {
            if let error = error as? ESClientCreateError {
                completion(error.status)
            } else {
                completion(ES_NEW_CLIENT_RESULT_ERR_INTERNAL)
            }
        }
    }
    
    func subscribe(_ events: [NSNumber], reply: @escaping (Bool) -> Void) {
        let converted = events.map(\.uint32Value).map(es_event_type_t.init(rawValue:))
        reply(client?.subscribe(converted) ?? false)
    }
    
    func unsubscribe(_ events: [NSNumber], reply: @escaping (Bool) -> Void) {
        let converted = events.map(\.uint32Value).map(es_event_type_t.init(rawValue:))
        reply(client?.unsubscribe(converted) ?? false)
    }
    
    func unsubscribeAll(reply: @escaping (Bool) -> Void) {
        reply(client?.unsubscribeAll() ?? false)
    }
    
    func clearCache(reply: @escaping (es_clear_cache_result_t) -> Void) {
        reply(client?.clearCache() ?? ES_CLEAR_CACHE_RESULT_ERR_INTERNAL)
    }
    
    func clearPathInterestCache(reply: @escaping (Bool) -> Void) {
        reply(client?.clearPathInterestCache() != nil)
    }
    
    func mute(process mute: Data, events: [NSNumber], reply: @escaping (Bool) -> Void) {
        if let decoded = ESMuteProcessRule(from: mute, decoder: .json(decoder: xpcDecoder), log: log) {
            reply(client?.mute(process: decoded, events: .fromNumbers(events)) != nil)
        } else {
            reply(false)
        }
    }
    
    func unmute(process mute: Data, events: [NSNumber], reply: @escaping (Bool) -> Void) {
        if let decoded = ESMuteProcessRule(from: mute, decoder: .json(decoder: xpcDecoder), log: log) {
            reply(client?.unmute(process: decoded, events: .fromNumbers(events)) != nil)
        } else {
            reply(false)
        }
    }
    
    func unmuteAllProcesses(reply: @escaping (Bool) -> Void) {
        reply(client?.unmuteAllProcesses() != nil)
    }
    
    func mute(path: String, type: es_mute_path_type_t, events: [NSNumber], reply: @escaping (Bool) -> Void) {
        reply(client?.mute(path: path, type: type, events: .fromNumbers(events)) ?? false)
    }
    
    func unmute(path: String, type: es_mute_path_type_t, events: [NSNumber], reply: @escaping (Bool) -> Void) {
        if #available(macOS 12.0, *) {
            reply(client?.unmute(path: path, type: type, events: .fromNumbers(events)) ?? false)
        } else {
            reply(false)
        }
    }
    
    func unmuteAllPaths(reply: @escaping (Bool) -> Void) {
        reply(client?.unmuteAllPaths() ?? false)
    }
    
    func unmuteAllTargetPaths(reply: @escaping (Bool) -> Void) {
        if #available(macOS 13.0, *) {
            reply(client?.unmuteAllTargetPaths() ?? false)
        } else {
            reply(false)
        }
    }
    
    func invertMuting(_ muteType: es_mute_inversion_type_t, reply: @escaping (Bool) -> Void) {
        if #available(macOS 13.0, *) {
            reply(client?.invertMuting(muteType) ?? false)
        } else {
            reply(false)
        }
    }
    
    func mutingInverted(_ muteType: es_mute_inversion_type_t, reply: @escaping (Bool) -> Void) {
        if #available(macOS 13.0, *) {
            reply(client?.mutingInverted(muteType) ?? false)
        } else {
            reply(false)
        }
    }
    
    func sendCustomMessage(_ data: Data, reply: @escaping (Data?, Error?) -> Void) {
        if let receiveCustomMessageHandler {
            receiveCustomMessageHandler(data) { reply($0.success, $0.failure) }
        } else {
            reply(nil, CommonError.unexpected("receiveCustomMessageHandler not set"))
        }
    }
    
    // MARK: Private
    
    private let createClient: () throws -> ESClient
    private let delegate: ESClientXPCDelegateProtocol
    private var client: ESClient?
    private var converterConfig: ESConverter.Config = .default
    
    private func handlePathInterest(_ process: ESProcess) -> ESInterest {
        do {
            let encoded = try xpcEncoder.encode(process)
            let executor = SynchronousExecutor("HandlePathInterest", timeout: 5.0)
            let interest = try executor { self.delegate.handlePathInterest(encoded, reply: $0) }
            let decoded = try xpcDecoder.decode(ESInterest.self, from: interest)
            return decoded
        } catch {
            log.error("handlePathInterest failed. Error: \(error)")
            return .listen()
        }
    }
    
    private func handleAuthMessage(_ message: ESMessagePtr, completion: @escaping (ESAuthResolution) -> Void) {
        processMessage(
            message,
            errorHandler: {
                log.error("handleAuthMessage failed. Error: \($0)")
                completion(.allowOnce)
            },
            actionHandler: {
                $0.handleAuth($1) {
                    completion(ESAuthResolution(result: .flags($0), cache: $1))
                }
            }
        )
    }
    
    private func handleNotifyMessage(_ message: ESMessagePtr) {
        processMessage(
            message,
            errorHandler: { log.error("handleNotifyMessage failed. Error: \($0)") },
            actionHandler: { $0.handleNotify($1) }
        )
    }
    
    private func processMessage(
        _ message: ESMessagePtr,
        errorHandler: @escaping (Error) -> Void,
        actionHandler: @escaping (ESClientXPCDelegateProtocol, Data) -> Void
    ) {
        guard let remoteObject = delegate as? NSXPCProxyCreating else {
            let error = CommonError.cast(delegate, to: NSXPCProxyCreating.self)
            errorHandler(error)
            return
        }
        
        let proxy = remoteObject.remoteObjectProxyWithErrorHandler(errorHandler)
        
        guard let delegateProxy = proxy as? ESClientXPCDelegateProtocol else {
            let error = CommonError.cast(proxy, to: ESClientXPCDelegateProtocol.self)
            errorHandler(error)
            return
        }
        
        do {
            let converted = try message.converted(converterConfig)
            let encoded = try xpcEncoder.encode(converted)
            actionHandler(delegateProxy, encoded)
        } catch {
            errorHandler(error)
        }
    }
}

extension ESEventSet {
    fileprivate static func fromNumbers(_ numbers: [NSNumber]) -> ESEventSet {
        ESEventSet(events: numbers.map { es_event_type_t($0.uint32Value) })
    }
}
