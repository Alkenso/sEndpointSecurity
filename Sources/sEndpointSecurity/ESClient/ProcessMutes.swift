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
    private let _checkProcessAlive: (pid_t) -> Bool
    
    private var _muteRules: Set<ESMuteProcess> = []
    
    
    init(
        esMute: @escaping (audit_token_t) -> es_return_t,
        esUnmute: @escaping (audit_token_t) -> es_return_t,
        checkProcessAlive: @escaping (pid_t) -> Bool
    ) {
        _esMute = esMute
        _esUnmute = esUnmute
        _checkProcessAlive = checkProcessAlive
    }
    
    func mute(_ options: ESMuteProcess) -> es_return_t {
        if case let .token(token) = options {
            return _esMute(token)
        } else {
            _muteRules.insert(options)
            return ES_RETURN_SUCCESS
        }
    }
    
    func unmute(_ options: ESMuteProcess) -> es_return_t {
        if case let .token(token) = options {
            return _esUnmute(token)
        } else {
            _muteRules.remove(options)
            return ES_RETURN_SUCCESS
        }
    }
    
    func isMuted(_ process: ESProcess) -> Bool {
        _muteRules.contains { $0.matches(process: process) }
    }
    
    func scheduleCleanup(on queue: DispatchQueue, interval: TimeInterval) {
        queue.asyncAfter(deadline: .now() + interval, flags: .barrier) { [weak self] in
            guard let self = self else { return }
            let rules = self._muteRules
            DispatchQueue.global().async {
                let rulesToRemove = rules.filter {
                    switch $0 {
                    case .token(let token):
                        return self._checkProcessAlive(token.pid)
                    case .pid(let pid):
                        return self._checkProcessAlive(pid)
                    case .euid, .name, .pathPrefix, .pathLiteral, .teamIdentifier, .signingID:
                        return true
                    }
                }
                queue.async {
                    self._muteRules.subtract(rulesToRemove)
                    self.scheduleCleanup(on: queue, interval: interval)
                }
            }
        }
    }
}

extension ProcessMutes {
    convenience init(esClient: OpaquePointer) {
        self.init(
            esMute: { withUnsafePointer(to: $0) { es_mute_process(esClient, $0) } },
            esUnmute: { withUnsafePointer(to: $0) { es_unmute_process(esClient, $0) } },
            checkProcessAlive: { getpgid($0) >= 0 }
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
