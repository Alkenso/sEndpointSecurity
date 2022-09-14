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

import EndpointSecurity
import Foundation
import SwiftConvenience

private let log = SCLogger.internalLog(.xpcClient)

public class ESXPCClient {
    public var authMessageHandler: ((ESMessage, @escaping (ESAuthResolution) -> Void) -> Void)?
    public var notifyMessageHandler: ((ESMessage) -> Void)?
    public var customMessageHandler: ((ESXPCCustomMessage) -> Void)?

    public var connectionStateHandler: ((Result<es_new_client_result_t, Error>) -> Void)?
    
    public var converterConfig: ESConverter.Config = .default

    @Atomic private var _connection: ESXPCConnection
    private let _delegate: ESClientXPCDelegate

    // MARK: Initialization & Activation

    public convenience init(_ createConnection: @escaping @autoclosure () -> NSXPCConnection) {
        self.init(createConnection)
    }

    public init(_ createConnection: @escaping () -> NSXPCConnection) {
        let delegate = ESClientXPCDelegate()
        self._connection = ESXPCConnection(delegate: delegate, createConnection: createConnection)
        self._delegate = delegate
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
        _connection.invalidate()
    }

    private func activate(async: Bool, completion: @escaping (Result<es_new_client_result_t, Error>) -> Void) {
        _delegate.authMessageHandler = authMessageHandler
        _delegate.notifyMessageHandler = notifyMessageHandler
        _delegate.customMessageHandler = customMessageHandler

        _connection.connectionStateHandler = connectionStateHandler
        _connection.converterConfig = converterConfig

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
    
    public func muteProcess(_ mute: ESMuteProcessRule, events: ESEventSet = .all, completion: @escaping (Error?) -> Void) {
        withEncodedMute(mute, events: events, actionName: "mute process", reply: completion) { client, mute, events in
            client.muteProcess(mute, events: events, reply: completion)
        }
    }
    
    public func unmuteProcess(_ mute: ESMuteProcessRule, events: ESEventSet = .all, completion: @escaping (Error?) -> Void) {
        withEncodedMute(mute, events: events, actionName: "unmute process", reply: completion) { client, mute, events in
            client.unmuteProcess(mute, events: events, reply: completion)
        }
    }
    
    public func unmuteAllProcesses(completion: @escaping (Error?) -> Void) {
        remoteObjectProxy(completion)?.unmuteAllProcesses(reply: completion)
    }
    
    public func mutePath(_ mute: ESMutePathRule, events: ESEventSet = .all, completion: @escaping (Error?) -> Void) {
        withEncodedMute(mute, events: events, actionName: "mute path", reply: completion) { client, mute, events in
            client.mutePath(mute, events: events, reply: completion)
        }
    }
    
    public func unmutePath(_ mute: ESMutePathRule, events: ESEventSet = .all, completion: @escaping (Error?) -> Void) {
        withEncodedMute(mute, events: events, actionName: "unmute path", reply: completion) { client, mute, events in
            client.unmutePath(mute, events: events, reply: completion)
        }
    }
    
    public func unmuteAllPaths(completion: @escaping (Error?) -> Void) {
        remoteObjectProxy(completion)?.unmuteAllPaths(reply: completion)
    }

    public func custom(_ custom: ESXPCCustomMessage, completion: @escaping (Error?) -> Void) {
        guard let proxy = _connection.remoteObjectProxy(completion) else { return }
        proxy.custom(id: custom.id, payload: custom.payload, isReply: custom.isReply) {
            completion(nil)
        }
    }
    
    private func remoteObjectProxy<T>(_ errorHandler: @escaping (Result<T, Error>) -> Void) -> ESClientXPCProtocol? {
        _connection.remoteObjectProxy { errorHandler(.failure($0)) }
    }
    
    private func remoteObjectProxy(_ errorHandler: @escaping (Error?) -> Void) -> ESClientXPCProtocol? {
        _connection.remoteObjectProxy { errorHandler($0) }
    }

    private func xpcEvents(_ events: [es_event_type_t]) -> [NSNumber] {
        events.map(\.rawValue).map(NSNumber.init)
    }
    
    private func withEncodedMute<Mute: Encodable>(
        _ mute: Mute, events: ESEventSet,
        actionName: String, reply: @escaping (Error?) -> Void,
        body: @escaping (ESClientXPCProtocol, _ mute: Data, _ events: Data) -> Void
    ) {
        guard let proxy = remoteObjectProxy(reply) else { return }
        do {
            let encodedMute = try xpcEncoder.encode(mute)
            let encodedEvents = try xpcEncoder.encode(events)
            body(proxy, encodedMute, encodedEvents)
        } catch {
            reply(error)
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
    var authMessageHandler: ((ESMessage, @escaping (ESAuthResolution) -> Void) -> Void)?
    var notifyMessageHandler: ((ESMessage) -> Void)?
    var customMessageHandler: ((ESXPCCustomMessage) -> Void)?

    var errorLogHandler: ((Error) -> Void)?
    
    private static let fallback = ESAuthResolution.allowOnce

    func handleAuth(_ message: ESMessageXPC, reply: @escaping (UInt32, Bool) -> Void) {
        do {
            guard let authMessageHandler = authMessageHandler else {
                reply(Self.fallback.result.rawValue, Self.fallback.cache)
                log.warning("Auth message came but no authMessageHandler installed")
                return
            }
            
            let decoded = try xpcDecoder.decode(ESMessage.self, from: message)
            authMessageHandler(decoded) {
                reply($0.result.rawValue, $0.cache)
            }
        } catch {
            reply(Self.fallback.result.rawValue, Self.fallback.cache)
            log.error("Failed to decode ESMessagePtr from auth event data. Error: \(error)")
        }
    }

    func handleNotify(_ message: ESMessageXPC) {
        do {
            guard let notifyMessageHandler = notifyMessageHandler else {
                log.warning("Notify message came but no notifyMessageHandler installed")
                return
            }
            
            let decoded = try xpcDecoder.decode(ESMessage.self, from: message)
            notifyMessageHandler(decoded)
        } catch {
            log.error("Failed to decode ESMessagePtr from notify event data. Error: \(error)")
        }
    }

    func custom(id: UUID, payload: Data, isReply: Bool, reply: @escaping () -> Void) {
        customMessageHandler?(ESXPCCustomMessage(id: id, payload: payload, isReply: isReply))
    }
}
