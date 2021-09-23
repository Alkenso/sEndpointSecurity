import EndpointSecurity
import Foundation
import SwiftConvenience


class ProcessMuteRules {
    private let _esClient: OpaquePointer
    private let _esMute: @convention(c) (OpaquePointer, UnsafePointer<audit_token_t>) -> es_return_t
    private let _esUnmute: @convention(c) (OpaquePointer, UnsafePointer<audit_token_t>) -> es_return_t
    private var _muteRules: Set<ESMuteProcess> = []
    private let _queue = DispatchQueue(label: "ProcessCache.queue")
    
    
    convenience init(esClient: OpaquePointer) {
        self.init(esClient: esClient, esMute: es_mute_process, esUnmute: es_unmute_process)
    }
    
    init(
        esClient: OpaquePointer,
        esMute: @escaping @convention(c) (OpaquePointer, UnsafePointer<audit_token_t>) -> es_return_t,
        esUnmute: @escaping @convention(c) (OpaquePointer, UnsafePointer<audit_token_t>) -> es_return_t
    ) {
        _esClient = esClient
        _esMute = esMute
        _esUnmute = esUnmute
    }
    
    func mute(_ options: ESMuteProcess) -> es_return_t {
        if case var .token(token) = options {
            return _esMute(_esClient, &token)
        } else {
            _queue.async { self._muteRules.insert(options) }
            return ES_RETURN_SUCCESS
        }
    }
    
    func unmute(_ options: ESMuteProcess) -> es_return_t {
        if case var .token(token) = options {
            return _esUnmute(_esClient, &token)
        } else {
            _queue.async { self._muteRules.remove(options) }
            return ES_RETURN_SUCCESS
        }
    }
    
    func unmute(_ process: audit_token_t) {
        _queue.async { self._muteRules.remove(.pid(process.pid)) }
    }
    
    func isMuted(_ process: ESProcess) -> Bool {
        _queue.sync {
            guard !_muteRules.isEmpty else { return false }
            return _muteRules.contains { $0.matches(process: process) }
        }
    }
}

extension ESMuteProcess {
    func matches(process: ESProcess) -> Bool {
        switch self {
        case .token(let value):
            return process.auditToken == value
        case .pid(let value):
            return process.auditToken.pid == value
        case .euid(let value):
            return process.auditToken.euid == value
        case .name(let value):
            return process.executable.path.hasSuffix("/" + value)
        case .pathPrefix(let value):
            return process.executable.path.hasPrefix(value)
        case .pathLiteral(let value):
            return process.executable.path == value
        case .teamIdentifier(let value):
            return process.teamID == value
        case .signingID(let value):
            return process.signingID == value
        }
    }
}
