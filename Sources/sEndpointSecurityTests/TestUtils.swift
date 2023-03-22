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

import sEndpointSecurity

import EndpointSecurity
import Foundation
import SwiftConvenience

extension audit_token_t {
    static func random() -> audit_token_t {
        var token = audit_token_t()
        withUnsafeMutablePointer(to: &token) {
            _ = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<audit_token_t>.size, $0)
        }
        return token
    }
}

extension ESProcess {
    static func test(_ path: String) -> ESProcess {
        test(path: path, token: nil)
    }
    
    static func test(_ token: audit_token_t) -> ESProcess {
        test(path: nil, token: token)
    }
    
    static func test(path: String? = nil, token: audit_token_t? = nil, teamID: String? = nil) -> ESProcess {
        ESProcess(
            auditToken: token ?? .random(),
            ppid: 10,
            originalPpid: 20,
            groupID: 30,
            sessionID: 40,
            codesigningFlags: 50,
            isPlatformBinary: true,
            isESClient: true,
            cdHash: Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            signingID: "signing_id",
            teamID: teamID ?? "team_id",
            executable: ESFile(
                path: path ?? "/root/path/to/executable/test_process",
                truncated: false,
                stat: .init()
            ),
            tty: nil,
            startTime: nil,
            responsibleAuditToken: nil,
            parentAuditToken: nil
        )
    }
}

private var nextMessageID: UInt64 = 1

func createMessage(path: String, signingID: String, teamID: String, event: es_event_type_t, isAuth: Bool) -> Resource<UnsafePointer<es_message_t>> {
    let message = UnsafeMutablePointer<es_message_t>.allocate(capacity: 1)
    message.pointee.version = 4
    message.pointee.global_seq_num = nextMessageID
    nextMessageID += 1
    
    message.pointee.process = .allocate(capacity: 1)
    message.pointee.process.pointee = .init(
        audit_token: .random(), ppid: 10, original_ppid: 10, group_id: 20, session_id: 500,
        codesigning_flags: 0x800, is_platform_binary: false, is_es_client: false,
        cdhash: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        signing_id: .init(string: signingID),
        team_id: .init(string: teamID),
        executable: .allocate(capacity: 1),
        tty: nil,
        start_time: .init(tv_sec: 100, tv_usec: 500),
        responsible_audit_token: .random(),
        parent_audit_token: .random()
    )
    message.pointee.process.pointee.executable.pointee.path = .init(string: path)
    
    message.pointee.action_type = isAuth ? ES_ACTION_TYPE_AUTH : ES_ACTION_TYPE_NOTIFY
    message.pointee.event_type = event
    
    return .raii(message) { _ in
        message.pointee.process.pointee.team_id.data?.deallocate()
        message.pointee.process.pointee.signing_id.data?.deallocate()
        message.pointee.process.pointee.executable.pointee.path.data?.deallocate()
        message.pointee.process.pointee.executable.deallocate()
        message.pointee.process.deallocate()
        message.deallocate()
    }
}

private extension es_string_token_t {
    init(string: String) {
        let ptr = strdup(string)
        self.init(length: UnsafePointer(ptr).flatMap(strlen) ?? 0, data: ptr)
    }
}
