import EndpointSecurity
import Foundation
import SwiftConvenience


class ProcessMutes {
    private let _esMute: (audit_token_t) -> es_return_t
    private let _esUnmute: (audit_token_t) -> es_return_t
    
    private let _queue = DispatchQueue(label: "ProcessMute.queue")
    private var _muteRules: Set<ESMuteProcess> = []
    
    
    init(
        esMute: @escaping (audit_token_t) -> es_return_t,
        esUnmute: @escaping (audit_token_t) -> es_return_t
    ) {
        _esMute = esMute
        _esUnmute = esUnmute
    }
    
    func mute(_ options: ESMuteProcess) -> es_return_t {
        if case let .token(token) = options {
            return _esMute(token)
        } else {
            _queue.async { self._muteRules.insert(options) }
            return ES_RETURN_SUCCESS
        }
    }
    
    func unmute(_ options: ESMuteProcess) -> es_return_t {
        if case let .token(token) = options {
            return _esUnmute(token)
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

extension ProcessMutes {
    convenience init(esClient: OpaquePointer) {
        self.init(
            esMute: { withUnsafePointer(to: $0) { es_mute_process(esClient, $0) } },
            esUnmute: { withUnsafePointer(to: $0) { es_unmute_process(esClient, $0) } }
        )
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
