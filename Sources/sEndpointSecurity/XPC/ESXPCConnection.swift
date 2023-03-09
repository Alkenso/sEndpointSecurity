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

private let log = SCLogger.internalLog(.xpc)

internal class ESXPCConnection {
    typealias ConnectResult = Result<es_new_client_result_t, Error>
    var connectionStateHandler: ((ConnectResult) -> Void)?
    
    var converterConfig: ESConverter.Config = .default
    
    init(delegate: ESClientXPCDelegateProtocol, createConnection: @escaping () -> NSXPCConnection) {
        self.delegate = delegate
        
        let prepareConnection = { () -> NSXPCConnection in
            let connection = createConnection()
            connection.remoteObjectInterface = .esClient
            connection.exportedInterface = .esClientDelegate
            return connection
        }
        self.createConnection = prepareConnection
        
        let dummyConnection = prepareConnection()
        dummyConnection.resume()
        dummyConnection.invalidate()
        self.xpcConnection = dummyConnection
    }
    
    func connect(async: Bool, notify: ((ConnectResult) -> Void)?) {
        let encodedConfig: Data
        do {
            encodedConfig = try xpcEncoder.encode(converterConfig)
        } catch {
            handleConnect(.failure(error), notify: notify)
            return
        }
        
        let connection = createConnection()
        connection.exportedObject = delegate
        connection.resume()
        
        let remoteObject = (async ? connection.remoteObjectProxyWithErrorHandler : connection.synchronousRemoteObjectProxyWithErrorHandler) { [weak self] in
            self?.handleConnect(.failure($0), notify: notify)
        }
        guard let proxy = remoteObject as? ESClientXPCProtocol else {
            let error = CommonError.cast(remoteObject, to: ESClientXPCProtocol.self)
            handleConnect(.failure(error), notify: notify)
            return
        }
        
        proxy.create(converterConfig: encodedConfig) { [weak self] in
            self?.handleConnect(.success(($0, connection)), notify: notify)
        }
    }
    
    func remoteObjectProxy(_ errorHandler: @escaping (Error) -> Void) -> ESClientXPCProtocol? {
        let remoteObject = xpcConnection.remoteObjectProxyWithErrorHandler {
            errorHandler($0)
        }
        guard let proxy = remoteObject as? ESClientXPCProtocol else {
            let error = CommonError.cast(remoteObject, to: ESClientXPCProtocol.self)
            errorHandler(error)
            return nil
        }
        return proxy
    }
    
    func invalidate() {
        reconnectOnFailure = false
        xpcConnection.invalidate()
    }
    
    // MARK: Private

    private let delegate: ESClientXPCDelegateProtocol
    private let createConnection: () -> NSXPCConnection
    @Atomic private var xpcConnection: NSXPCConnection
    @Atomic private var reconnectOnFailure = true
    
    private func reconnect() {
        guard reconnectOnFailure else { return }
        connect(async: true, notify: nil)
    }

    private func handleConnect(
        _ result: Result<(result: es_new_client_result_t, connection: NSXPCConnection), Error>,
        notify: ((ConnectResult) -> Void)?
    ) {
        defer {
            let notifyResult = result.map(\.result)
            notify?(notifyResult)
            connectionStateHandler?(notifyResult)
        }
        
        guard let value = result.success, value.result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            log.error("Connect failed with result = \(result)")
            result.success?.connection.invalidate()
            if notify == nil {
                scheduleReconnect()
            }
            return
        }
        
        value.connection.invalidationHandler = { [weak self, weak connection = value.connection] in
            log.warning("ESXPC connection invalidated")
            
            connection?.invalidationHandler = nil
            self?.connectionStateHandler?(.failure(CocoaError(.xpcConnectionInterrupted)))
            self?.scheduleReconnect()
        }
        value.connection.interruptionHandler = { [weak connection = value.connection] in
            log.warning("ESXPC connection interrupted. Invalidating...")
            
            connection?.interruptionHandler = nil
            connection?.invalidate()
        }
        
        xpcConnection = value.connection
    }

    private func scheduleReconnect() {
        let reconnectDelay: TimeInterval = 3.0
        DispatchQueue.global().asyncAfter(deadline: .now() + reconnectDelay, execute: reconnect)
    }
}
