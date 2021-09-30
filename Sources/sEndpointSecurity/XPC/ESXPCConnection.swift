//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 19.09.2021.
//

import EndpointSecurity
import Foundation
import SwiftConvenience


class ESXPCConnection {
    @Atomic var xpcConnection: NSXPCConnection
    
    typealias ConnectResult = Result<es_new_client_result_t, Error>
    var connectionStateHandler: ((ConnectResult) -> Void)?
    
    var reconnectOnFailure: Bool = true
    
    
    init(delegate: ESClientXPCDelegateProtocol, createConnection: @escaping () -> NSXPCConnection) {
        _delegate = delegate
        
        let prepareConnection = { () -> NSXPCConnection in
            let connection = createConnection()
            connection.remoteObjectInterface = .esClient
            connection.exportedInterface = .esClientDelegate
            return connection
        }
        _createConnection = prepareConnection
        
        let dummyConnection = prepareConnection()
        dummyConnection.resume()
        dummyConnection.invalidate()
        xpcConnection = dummyConnection
    }
    
    func connect(async: Bool, notify: ((ConnectResult) -> Void)?) {
        let connection = _createConnection()
        connection.exportedObject = _delegate
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
    
    
    // MARK: Private
    private let _delegate: ESClientXPCDelegateProtocol
    private let _createConnection: () -> NSXPCConnection
    
    
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
        
        guard let value = result.value, value.result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            result.value?.connection.invalidate()
            scheduleReconnect()
            return
        }
        
        result.value?.connection.invalidationHandler = { [weak self, weak connection = result.value?.connection] in
            connection?.invalidationHandler = nil
            self?.reconnect()
        }
        result.value?.connection.interruptionHandler = { [weak connection = result.value?.connection] in
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
