//  MIT License
//
//  Copyright (c) 2021 Alkenso (Vladimir Vashurkin)
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
