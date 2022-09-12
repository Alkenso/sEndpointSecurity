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

private let log = SCLogger.internalLog(.xpcCommunication)

public class ESXPCService: NSObject {
    public var verifyConnectionHandler: ((audit_token_t) -> Bool)?
    public var receiveCustomMessageHandler: ((_ message: ESXPCCustomMessage, _ peer: UUID) -> Void)?

    /// When receiving incoming conneciton, ESXPCService creates one ESClient for each connection.
    /// You can setup all message handlers of ESClient prior to returning it from 'createConnection'.
    public init(listener: NSXPCListener, createClient: @escaping () throws -> ESClient) {
        self._listener = listener
        self._createClient = createClient

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

    private let _sendCustomMessage = EventNotify<(message: ESXPCCustomMessage, peer: UUID)>()
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
            log.fatal("Failed to accept new connection. Error: \(error)")
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

        client.parentSubscription = _sendCustomMessage.subscribe { [weak client] in
            guard let client = client, client.id == $0.peer else { return }
            client.sendCustomMessage($0.message)
        }

        return client
    }
}

class ESXPCServiceClient: NSObject, ESClientXPCProtocol {
    let id = UUID()
    var receiveCustomMessageHandler: ((ESXPCCustomMessage) -> Void)?
    var parentSubscription: Any?

    init(delegate: ESClientXPCDelegateProtocol, createClient: @escaping () throws -> ESClient) {
        self._delegate = delegate
        self._createClient = createClient
    }

    func sendCustomMessage(_ message: ESXPCCustomMessage) {
        _sendCustomMessage.notify(message)
    }
    
    func create(completion: @escaping (es_new_client_result_t) -> Void) {
        do {
            let client = try _createClient()
            defer { _client = client }

            let localAuthHandler = client.authMessageHandler
            client.authMessageHandler = { [weak self] message, authCompletion in
                Self.authenticate(message, handler: localAuthHandler) { localResolution in
                    Self.authenticate(message, handler: self?.handleAuthMessage) { remoteResolution in
                        let resolutions = [localResolution, remoteResolution].compactMap { $0 }
                        authCompletion(.combine(resolutions))
                    }
                }
            }

            let localNotifyHandler = client.notifyMessageHandler
            client.notifyMessageHandler = { [weak self] in
                localNotifyHandler?($0)
                self?.handleNotifyMessage($0)
            }

            _sendCustomMessage.subscribe { [weak self] in
                self?._delegate.custom(id: $0.id, payload: $0.payload, isReply: $0.isReply) {}
            }
            .store(in: &_cancellables)

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

    func muteProcess(_ mute: ESMuteProcessRuleXPC, events: ESEventSetXPC, reply: @escaping (Error?) -> Void) {
        withDecodedMute(
            from: mute, type: ESMuteProcessRule.self, events: events,
            actionName: "mute process", reply: reply
        ) { client, mute, events in
            client.muteProcess(mute, events: events)
        }
    }

    func unmuteProcess(_ mute: ESMuteProcessRuleXPC, events: ESEventSetXPC, reply: @escaping (Error?) -> Void) {
        withDecodedMute(
            from: mute, type: ESMuteProcessRule.self, events: events,
            actionName: "unmute process", reply: reply
        ) { client, mute, events in
            client.unmuteProcess(mute, events: events)
        }
    }
    
    func mutePath(_ mute: ESMutePathRuleXPC, events: ESEventSetXPC, reply: @escaping (Error?) -> Void) {
        withDecodedMute(
            from: mute, type: ESMutePathRule.self, events: events,
            actionName: "mute path", reply: reply
        ) { client, mute, events in
            client.mutePath(mute, events: events)
        }
    }
    
    func unmutePath(_ mute: ESMutePathRuleXPC, events: ESEventSetXPC, reply: @escaping (Error?) -> Void) {
        withDecodedMute(
            from: mute, type: ESMutePathRule.self, events: events,
            actionName: "unmute path", reply: reply
        ) { client, mute, events in
            client.unmutePath(mute, events: events)
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

    private let _sendCustomMessage = EventNotify<ESXPCCustomMessage>()
    private let _queue = DispatchQueue(label: "ESXPCServiceClient.queue")
    private let _createClient: () throws -> ESClient
    private let _delegate: ESClientXPCDelegateProtocol
    private var _cancellables: [AnyCancellable] = []
    private var _client: ESClient?

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
        actionHandler: @escaping (ESClientXPCDelegateProtocol, ESMessagePtrXPC) -> Void
    ) {
        _queue.async {
            guard let remoteObject = self._delegate as? NSXPCProxyCreating else {
                let error = CommonError.cast(self._delegate, to: NSXPCProxyCreating.self)
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
                let xpcMessage = try message.serialized()
                actionHandler(delegateProxy, xpcMessage)
            } catch {
                errorHandler(error)
            }
        }
    }
    
    private func withDecodedMute<Mute: Decodable>(
        from data: Data, type: Mute.Type, events: ESEventSetXPC,
        actionName: String, reply: @escaping (Error?) -> Void,
        body: @escaping (ESClient, Mute, ESEventSet) -> Void
    ) {
        DispatchQueue.global().async { [self] in
            do {
                let decodedMute = try xpcDecoder.decode(Mute.self, from: data)
                let decodedEvents = try xpcDecoder.decode(ESEventSet.self, from: events)
                let client = try _client.get(name: "ESClient")
                body(client, decodedMute, decodedEvents)
                reply(nil)
            } catch {
                log.error("Failed to \(actionName). Error: \(error)")
                reply(error.xpcCompatible())
            }
        }
    }
    
    private func decodeMute(_ mute: ESMuteProcessRuleXPC) -> ESMuteProcessRule? {
        ESMuteProcessRule(from: mute, decoder: .json(), log: log)
    }
    
    private static func authenticate(
        _ message: ESMessagePtr,
        handler: ((ESMessagePtr, @escaping (ESAuthResolution) -> Void) -> Void)?,
        completion: @escaping (ESAuthResolution?) -> Void
    ) {
        if let handler = handler {
            handler(message, completion)
        } else {
            completion(nil)
        }
    }
}
