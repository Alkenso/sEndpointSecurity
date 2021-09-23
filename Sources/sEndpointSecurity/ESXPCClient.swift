//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 19.09.2021.
//

import Foundation



/*
func test_ESAuthResolution_combine() {
    XCTAssertEqual(
        ESAuthResolution.combine([]),
        ESAuthResolution(result: .auth(true), cache: false)
    )
    XCTAssertEqual(
        ESAuthResolution.combine([
            ESAuthResolution(result: .flags(123), cache: true)
        ]),
        ESAuthResolution(result: .flags(123), cache: true)
    )
    XCTAssertEqual(
        ESAuthResolution.combine([
            ESAuthResolution(result: .auth(true), cache: false),
            ESAuthResolution(result: .flags(123), cache: true)
        ]),
        ESAuthResolution(result: .flags(123), cache: false)
    )
    XCTAssertEqual(
        ESAuthResolution.combine([
            ESAuthResolution(result: .auth(false), cache: false),
            ESAuthResolution(result: .flags(123), cache: true)
        ]),
        ESAuthResolution(result: .auth(false), cache: false)
    )
    XCTAssertEqual(
        ESAuthResolution.combine([
            ESAuthResolution(result: .auth(true), cache: false),
            ESAuthResolution(result: .flags(0), cache: true)
        ]),
        ESAuthResolution(result: .auth(false), cache: false)
    )
}
extension ESAuthResolution {
    static func combine(_ resolutions: [ESAuthResolution]) -> ESAuthResolution {
        guard let first = resolutions.first else { return .allowOnce }
        guard resolutions.count > 1 else { return first }
        
        let flags = resolutions.map(\.result.rawValue).reduce(UInt32.max) { $0 & $1 }
        let cache = resolutions.map(\.cache).reduce(true) { $0 && $1 }
        
        return ESAuthResolution(result: .flags(flags), cache: cache)
    }
}

public protocol XPCProxyCreating {
    associatedtype T
    func remoteProxyObject(withErrorHandler handler: @escaping (Error) -> Void) -> T
}

extension XPCProxyCreating {
    
}

public protocol ESAsyncClient {
    func subscribe(_ events: [es_event_type_t], completion: @escaping (es_return_t) -> Void)
}

public class ESXPCConnection: XPCProxyCreating, ESXPCClientProxy {
    typealias T = ESXPCClientProxy
    
    public var authMessage = EvaluationChain<ESMessagePtr, ESAuthResolution>()
    public var notifyMessage = NotificationChain<ESMessagePtr>()
    public var notifyStateChanged = NotificationChain<Result<es_new_client_result_t, Error>>()
    
    public var messageDecodingFailStrategy: ((Error) -> ESAuthResolution)?
    
    public convenience init(_ createConnection: @escaping @autoclosure () -> NSXPCConnection) {
        self.init(createConnection)
    }
    
    public init(_ createConnection: @escaping () -> NSXPCConnection) {
        _createConnection = createConnection
    }
    
    public func activate() {
        reconnect()
    }
    
    public func remoteProxyObject(withErrorHandler handler: @escaping (Error) -> Void) -> ESXPCClientProxy {
        self
    }
    
    public func subscribe(_ events: [es_event_type_t], completion: @escaping (es_return_t) -> Void) {
        
    }
    
    
    public func subscribe(_ events: [es_event_type_t], completion: @escaping (Result<es_return_t, Error>) -> Void) {
        
    }
    
    public func unsubscribe(_ events: [es_event_type_t], completion: @escaping (Result<es_return_t, Error>) -> Void) {
        
    }
    
    public func unsubscribeAll(completion: @escaping (Result<es_return_t, Error>) -> Void) {
        
    }
    
    public func clearCache(events: [es_event_type_t], completion: @escaping (Result<es_return_t, Error>) -> Void) {
        
    }
    
    public func clearAllCache(completion: @escaping (Result<es_clear_cache_result_t, Error>) -> Void) {
        
    }
    
    public func muteProcess(_ mute: ESMuteProcess, completion: @escaping (Result<es_return_t, Error>) -> Void) {
        
    }
    
    public func unmuteProcess(_ mute: ESMuteProcess, completion: @escaping (Result<es_return_t, Error>) -> Void) {
        
    }
    
    public func unmuteAllProcesses(completion: @escaping (Result<es_return_t, Error>) -> Void) {
        
    }
    
    public func mutePath(prefix: String, completion: @escaping (Result<es_return_t, Error>) -> Void) {
        
    }
    
    public func mutePath(literal: String, completion: @escaping (Result<es_return_t, Error>) -> Void) {
        
    }
    
    public func unmuteAllPaths(completion: @escaping (Result<es_return_t, Error>) -> Void) {
        
    }
    
    public func custom(_ in: Data, completion: @escaping (_ out: Result<Data, Error>) -> Void) {
        
    }
    
    
    // MARK: Private
    private let _createConnection: () -> NSXPCConnection
    private var _connection: NSXPCConnection?
    
    
    private func reconnect() {
        let connection = _createConnection()
//        connection.remoteObjectInterface = .securityEngine
        connection.resume()

        let remoteObject = connection.remoteObjectProxyWithErrorHandler { [weak self] in
            self?.handleConnect(.failure($0))
        }
        guard let proxy = remoteObject as? ESClientXPC else {
            handleConnect(.failure(CommonError.unexpected("Failed cast \(remoteObject) to \(ESClientXPC.self)")))
            return
        }
        
        let delegate = ESClientXPCDelegateProxy(weakMain: self)
        proxy.create(delegate: delegate) { [weak self] result in
            self?.handleConnect(.success((result, connection)))
        }
    }
    
    private func handleConnect(_ result: Result<(result: es_new_client_result_t, connection: NSXPCConnection), Error>) {
        defer {
            notifyStateChanged.notify(result.map(\.result))
        }
        
        guard let value = result.value, value.result == ES_NEW_CLIENT_RESULT_SUCCESS else {
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
        
        _connection = value.connection
    }
    
    private func scheduleReconnect() {
        let reconnectDelay: TimeInterval = 3.0
        DispatchQueue.global().asyncAfter(deadline: .now() + reconnectDelay, execute: reconnect)
    }
}

class ESClientXPCDelegateProxy: NSObject, ESClientXPCDelegate {
    private weak var _weakMain: ESXPCClient?
    
    init(weakMain: ESXPCClient) {
        _weakMain = weakMain
    }
    
    func handleAuth(_ message: ESMessagePtrXPC, reply: @escaping (UInt32, ESFileCacheOptions) -> Void) {
        guard let main = _weakMain else { return reply(.max, []) }
        
        do {
            let decoded = try ESMessagePtr(data: message)
            main.authMessage.evaluate(decoded) { resolutions in
                
            }
        } catch {
            let resolution = main.messageDecodingFailStrategy?(error) ?? .allowOnce
            reply(resolution.flags, resolution.cache)
        }
        
    }
    
    func handleNotify(_ message: ESMessagePtrXPC) {
        guard let main = _weakMain else { return }
        
        do {
            let decoded = try ESMessagePtr(data: message)
            main.notifyMessage.notify(decoded)
        } catch {
            _ = main.messageDecodingFailStrategy?(error)
        }
    }
}

extension ESAuthResolution {
    var flags: UInt32 {
        switch result {
        case .auth(let value):
            return value ? .max : 0
        case .flags(let value):
            return value
        }
    }
}


typealias ESMessagePtrXPC = Data
typealias ESMuteProcessXPC = Data

@objc
protocol ESClientXPC {
    func create(delegate: ESClientXPCDelegate, completion: @escaping (es_new_client_result_t) -> Void)
    
    func subscribe(_ events: [NSNumber], completion: @escaping (es_return_t) -> Void)
    func unsubscribe(_ events: [NSNumber], completion: @escaping (es_return_t) -> Void)
    func unsubscribeAll(completion: @escaping (es_return_t) -> Void)
    func clearCache(events: [NSNumber], completion: @escaping (es_return_t) -> Void)
    func clearAllCache(completion: @escaping (es_clear_cache_result_t) -> Void)
    func muteProcess(_ mute: ESMuteProcessXPC, completion: @escaping (es_return_t) -> Void)
    func unmuteProcess(_ mute: ESMuteProcessXPC, completion: @escaping (es_return_t) -> Void)
    func unmuteAllProcesses(completion: @escaping (es_return_t) -> Void)
    func mutePath(prefix: String, completion: @escaping (es_return_t) -> Void)
    func mutePath(literal: String, completion: @escaping (es_return_t) -> Void)
    func unmuteAllPaths(completion: @escaping (es_return_t) -> Void)
    
    func custom(_ in: Data, completion: @escaping (_ out: Data) -> Void)
}

@objc
protocol ESClientXPCDelegate {
    func handleAuth(_ message: ESMessagePtrXPC, reply: @escaping (UInt32, ESFileCacheOptions) -> Void)
    func handleNotify(_ message: ESMessagePtrXPC)
}


extension ESMuteProcess {
#warning("implement codable")
    public init(from decoder: Decoder) throws {
        fatalError()
    }
    
    public func encode(to encoder: Encoder) throws {
        fatalError()
    }
}
*/
