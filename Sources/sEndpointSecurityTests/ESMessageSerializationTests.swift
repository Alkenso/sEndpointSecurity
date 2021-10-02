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

@testable import sEndpointSecurity

import EndpointSecurity
import Foundation
import SwiftConvenience
import XCTest


class ESMessageSerializationTests: XCTestCase {
    struct TestEntity<ES, Converted> {
        var resource: Resource<ES>
        var converted: Converted
        var es: ES { resource.unsafeValue }
    }
    
    struct TestEntityPtr<ES, Converted> {
        var resource: Resource<UnsafeMutablePointer<ES>>
        var converted: Converted
        var es: UnsafeMutablePointer<ES> { resource.unsafeValue }
    }
    
    let converter = ESConverter(version: 4)
    var testESString1: TestEntity<es_string_token_t, String>!
    var testESString2: TestEntity<es_string_token_t, String>!
    var testESToken: TestEntity<es_token_t, Data>!
    var testESFile1: TestEntityPtr<es_file_t, ESFile>!
    var testESFile2: TestEntityPtr<es_file_t, ESFile>!
    var testESProcess: TestEntityPtr<es_process_t, ESProcess>!
    
    override func setUpWithError() throws {
        let str1 = rawESString("test string 1")
        testESString1 = .init(resource: str1, converted: converter.esString(str1.unsafeValue))
        
        let str2 = rawESString("test another string")
        testESString1 = .init(resource: str2, converted: converter.esString(str2.unsafeValue))
        
        let data = rawESToken(Data(pod: UInt64.random(in: 0..<UInt64.max)))
        testESToken = .init(resource: data, converted: converter.esToken(data.unsafeValue))
        
        let file1 = rawESFile(Bundle.main.bundleURL.path, truncated: false, stat: try stat(url: Bundle.main.bundleURL))
        testESFile1 = .init(resource: file1, converted: converter.esFile(file1.unsafeValue))
        
        let file2 = rawESFile(NSTemporaryDirectory(), truncated: false, stat: try stat(path: NSTemporaryDirectory()))
        testESFile2 = .init(resource: file2, converted: converter.esFile(file2.unsafeValue))
        
        let rawSigningID = rawESString("Signing ID")
        let rawTeamID = rawESString("Team ID")
        let rawExecutableFile = rawESFile(Bundle.main.bundleURL.path, truncated: true, stat: try stat(url: Bundle.main.bundleURL))
        let rawTTYFile = rawESFile("/path/to/tty/file", truncated: true, stat: try stat(url: Bundle.main.bundleURL))
        let rawProcess = UnsafeMutablePointer<es_process_t>.allocate(capacity: 1)
        try rawProcess.initialize(
            to: es_process_t(
                audit_token: .random(),
                ppid: 10,
                original_ppid: 20,
                group_id: 30,
                session_id: 40,
                codesigning_flags: 50,
                is_platform_binary: true,
                is_es_client: true,
                cdhash: (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14),
                signing_id: rawSigningID.unsafeValue,
                team_id: rawTeamID.unsafeValue,
                executable: rawExecutableFile.unsafeValue,
                tty: rawTTYFile.unsafeValue,
                start_time: .init(tv_sec: 60, tv_usec: 70),
                responsible_audit_token: .random(),
                parent_audit_token: .random()
            )
        )
        let process = Resource.raii(rawProcess) {
            withExtendedLifetime([rawSigningID, rawTeamID, rawExecutableFile, rawTTYFile], {})
            $0.deallocate()
        }
        testESProcess = .init(resource: process, converted: converter.esProcess(process.unsafeValue))
    }
    
    
    func test_es_string() throws {
        let str = "qwerty"
        let ptr = rawESString(str)
        
        XCTAssertEqual(converter.esString(ptr.unsafeValue), str)
    }
    
    func test_es_token() throws {
        func parameterized(_ data: Data) {
            data.withUnsafeBytes {
                let esToken = es_token_t(size: $0.count, data: $0.bindMemory(to: UInt8.self).baseAddress)
                XCTAssertEqual(converter.esToken(esToken), data)
            }
        }
        
        parameterized(Data([0x00, 0x01, 0x02, 0x03, 0x04]))
        parameterized(Data([0x00]))
        parameterized(Data([]))
    }
    
    func test_es_file() throws {
        let path = Bundle.main.bundleURL.path + "qq1"
        let pathTruncated = true
        let stat = try stat(url: Bundle.main.bundleURL)
        
        let rawInitial = rawESFile(path, truncated: pathTruncated, stat: stat)
        let rawRestored = try encodeDecode(rawInitial.pointee)
        let file = converter.esFile(rawRestored.unsafeValue)
        
        XCTAssertTrue(file.path == path)
        XCTAssertEqual(file.path, path)
        XCTAssertEqual(file.truncated, true)
        XCTAssertEqual(file.stat, stat)
    }
    
    func test_es_process() throws {
        let rawSigningID = rawESString("Signing ID")
        let rawTeamID = rawESString("Team ID")
        let rawExecutableFile = rawESFile(Bundle.main.bundleURL.path, truncated: true, stat: try stat(url: Bundle.main.bundleURL))
        let rawTTYFile = rawESFile("/path/to/tty/file", truncated: true, stat: try stat(url: Bundle.main.bundleURL))
        defer { withExtendedLifetime([rawSigningID, rawTeamID, rawExecutableFile, rawTTYFile], {}) }
        
        let rawInitial = try es_process_t(
            audit_token: .current(),
            ppid: 10,
            original_ppid: 20,
            group_id: 30,
            session_id: 40,
            codesigning_flags: 50,
            is_platform_binary: true,
            is_es_client: true,
            cdhash: (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14),
            signing_id: rawSigningID.unsafeValue,
            team_id: rawTeamID.unsafeValue,
            executable: rawExecutableFile.unsafeValue,
            tty: rawTTYFile.unsafeValue,
            start_time: .init(),
            responsible_audit_token: .current(),
            parent_audit_token: .current()
        )
        
        let rawRestored = try encodeDecode(rawInitial)
        let converted = converter.esProcess(rawRestored.unsafeValue)
        
        XCTAssertEqual(converted.auditToken, rawInitial.audit_token)
        XCTAssertEqual(converted.ppid, rawInitial.ppid)
        XCTAssertEqual(converted.originalPpid, rawInitial.original_ppid)
        XCTAssertEqual(converted.groupID, rawInitial.group_id)
        XCTAssertEqual(converted.sessionID, rawInitial.session_id)
        XCTAssertEqual(converted.codesigningFlags, rawInitial.codesigning_flags)
        XCTAssertEqual(converted.isPlatformBinary, rawInitial.is_platform_binary)
        XCTAssertEqual(converted.isESClient, rawInitial.is_es_client)
        XCTAssertEqual(converted.cdHash, Data(pod: rawInitial.cdhash))
        XCTAssertEqual(converted.signingID, converter.esString(rawInitial.signing_id))
        XCTAssertEqual(converted.teamID, converter.esString(rawInitial.team_id))
        XCTAssertEqual(converted.executable, converter.esFile(rawInitial.executable.pointee))
        XCTAssertEqual(converted.tty, rawInitial.tty.flatMap(converter.esFile))
        XCTAssertEqual(converted.startTime, rawInitial.start_time)
        XCTAssertEqual(converted.responsibleAuditToken, rawInitial.responsible_audit_token)
        XCTAssertEqual(converted.parentAuditToken, rawInitial.parent_audit_token)
    }
    
    func test_es_thread() throws {
        let rawInitial = es_thread_t(thread_id: 100500)
        let rawRestored = try encodeDecode(rawInitial)
        let converted = converter.esThread(rawRestored.unsafeValue)
        
        XCTAssertEqual(converted.threadID, rawInitial.thread_id)
    }
    
    func test_es_thread_state() throws {
        let state = Data([0x00, 0x01, 0x02, 0x03, 0x04])
        let rawState = rawESToken(state)
        defer { withExtendedLifetime(rawState, {}) }
        
        let rawInitial = es_thread_state_t(flavor: 100500, state: rawState.unsafeValue)
        let rawRestored = try encodeDecode(rawInitial)
        let converted = try converter.esThreadState(rawRestored.unsafeValue)
        
        XCTAssertEqual(converted.flavor, rawInitial.flavor)
        XCTAssertEqual(converted.state, state)
    }
    
    func test_authResult() throws {
        let authAllow = try converter.esAuthResult(
            es_result_t(
                result_type: ES_RESULT_TYPE_AUTH,
                result: .init(auth: ES_AUTH_RESULT_ALLOW)
            )
        )
        XCTAssertEqual(authAllow, .auth(true))
        
        let authDeny = try converter.esAuthResult(
            es_result_t(
                result_type: ES_RESULT_TYPE_AUTH,
                result: .init(auth: ES_AUTH_RESULT_DENY)
            )
        )
        XCTAssertEqual(authDeny, .auth(false))
        
        let flags = try converter.esAuthResult(
            es_result_t(
                result_type: ES_RESULT_TYPE_FLAGS,
                result: .init(flags: 100500)
            )
        )
        XCTAssertEqual(flags, .flags(100500))
    }
    
    func test_action() throws {
        let auth = try converter.esAction(ES_ACTION_TYPE_AUTH, .init(auth: .init()))
        XCTAssertEqual(auth, .auth)
        
        let notify = try converter.esAction(
            ES_ACTION_TYPE_NOTIFY,
            .init(
                notify: es_result_t(result_type: ES_RESULT_TYPE_FLAGS, result: .init(flags: 100500))
            )
        )
        XCTAssertEqual(notify, .notify(.flags(100500)))
    }
    
    func test_es_message() throws {
        let rawSigningID = rawESString("Signing ID")
        let rawTeamID = rawESString("Team ID")
        let rawExecutableFile = rawESFile(Bundle.main.bundleURL.path, truncated: true, stat: try stat(url: Bundle.main.bundleURL))
        let rawTTYFile = rawESFile("/path/to/tty/file", truncated: true, stat: try stat(url: Bundle.main.bundleURL))
        defer { withExtendedLifetime([rawSigningID, rawTeamID, rawExecutableFile, rawTTYFile], {}) }
        
        let rawFile = try rawESFile("/path/to/executable/file", truncated: true, stat: .random())
        defer { withExtendedLifetime(rawFile, {}) }
        
        let rawInitial = UnsafeMutablePointer<es_message_t>.allocate(capacity: 1)
        rawInitial.bzero()
        
        rawInitial.pointee.version = 4
        rawInitial.pointee.time = .init(tv_sec: 100, tv_nsec: 500)
        rawInitial.pointee.mach_time = 100
        rawInitial.pointee.deadline = 200
        rawInitial.pointee.process = .allocate(capacity: 1)
        try rawInitial.pointee.process.initialize(
            to: es_process_t(
                audit_token: .random(),
                ppid: 10,
                original_ppid: 20,
                group_id: 30,
                session_id: 40,
                codesigning_flags: 50,
                is_platform_binary: true,
                is_es_client: true,
                cdhash: (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14),
                signing_id: rawSigningID.unsafeValue,
                team_id: rawTeamID.unsafeValue,
                executable: rawExecutableFile.unsafeValue,
                tty: rawTTYFile.unsafeValue,
                start_time: .init(tv_sec: 60, tv_usec: 70),
                responsible_audit_token: .random(),
                parent_audit_token: .random()
            )
        )
        rawInitial.pointee.seq_num = 300
        rawInitial.pointee.action_type = ES_ACTION_TYPE_NOTIFY
        rawInitial.pointee.action = .init(notify: .init(result_type: ES_RESULT_TYPE_FLAGS, result: .init(flags: 123)))
        rawInitial.pointee.event_type = ES_EVENT_TYPE_AUTH_OPEN
        rawInitial.pointee.event.open.fflag = 321
        rawInitial.pointee.event.open.file = rawFile.unsafeValue
        rawInitial.pointee.thread = .allocate(capacity: 1)
        rawInitial.pointee.thread?.initialize(to: es_thread_t(thread_id: 500))
        rawInitial.pointee.global_seq_num = 400
        
        let rawRestored = try encodeDecode(rawInitial.pointee)
        let converted = try ESConverter.esMessage(rawRestored.unsafeValue)
        
        XCTAssertEqual(converted.version, rawInitial.pointee.version)
        XCTAssertEqual(converted.time, rawInitial.pointee.time)
        XCTAssertEqual(converted.machTime, rawInitial.pointee.mach_time)
        XCTAssertEqual(converted.deadline, rawInitial.pointee.deadline)
        XCTAssertEqual(converted.process, converter.esProcess(rawInitial.pointee.process))
        XCTAssertEqual(converted.seqNum, rawInitial.pointee.seq_num)
        XCTAssertEqual(converted.action, try converter.esAction(rawInitial.pointee.action_type, rawInitial.pointee.action))
        XCTAssertEqual(converted.event, try converter.esEvent(rawInitial.pointee.event_type, rawInitial.pointee.event))
        XCTAssertEqual(converted.thread, rawInitial.pointee.thread.map(\.pointee).flatMap(converter.esThread))
        XCTAssertEqual(converted.globalSeqNum, rawInitial.pointee.global_seq_num)
    }
}

private extension ESConverter {
    func esEvent(_ type: es_event_type_t, _ event: Resource<es_events_t>) throws -> ESEvent {
        try esEvent(type, event.unsafeValue)
    }
}

extension ESMessageSerializationTests {
    func test_esEvent_access() throws {
        var event = es_event_access_t.bzeroed()
        event.mode = 123
        event.target = testESFile1.es
        
        let initial = es_events_t(access: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_ACCESS, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_ACCESS, restored)
        
        XCTAssertEqual(
            converted,
            .access(
                .init(
                    mode: 123,
                    target: testESFile1.converted
                )
            )
        )
    }
    
    func test_esEvent_chdir() throws {
        var event = es_event_chdir_t.bzeroed()
        event.target = testESFile1.es
        
        let initial = es_events_t(chdir: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_CHDIR, ES_EVENT_TYPE_AUTH_CHDIR] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .chdir(
                    .init(
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_chroot() throws {
        var event = es_event_chroot_t.bzeroed()
        event.target = testESFile1.es
        
        let initial = es_events_t(chroot: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_CHROOT, ES_EVENT_TYPE_AUTH_CHROOT] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .chroot(
                    .init(
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_clone() throws {
        var event = es_event_clone_t.bzeroed()
        event.source = testESFile1.es
        event.target_dir = testESFile2.es
        event.target_name = testESString1.es
        
        let initial = es_events_t(clone: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_CLONE, ES_EVENT_TYPE_AUTH_CLONE] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            if case let .clone(convertedEvent) = converted {
                XCTAssertEqual(convertedEvent.source, testESFile1.converted)
                XCTAssertEqual(convertedEvent.targetDir, testESFile2.converted)
                XCTAssertEqual(convertedEvent.targetName, testESString1.converted)
            } else {
                XCTFail("Invalid event decoded")
            }
            XCTAssertEqual(
                converted,
                .clone(
                    .init(
                        source: testESFile1.converted,
                        targetDir: testESFile2.converted,
                        targetName: testESString1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_close() throws {
        var event = es_event_close_t.bzeroed()
        event.target = testESFile1.es
        event.modified = true
        
        let initial = es_events_t(close: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_CLOSE, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_CLOSE, restored)
        
        XCTAssertEqual(
            converted,
            .close(
                .init(
                    modified: true,
                    target: testESFile1.converted
                )
            )
        )
    }
    
    func test_esEvent_create_existing() throws {
        var event = es_event_create_t.bzeroed()
        event.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE
        event.destination.existing_file = testESFile1.es
        
        let initial = es_events_t(create: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_AUTH_CREATE] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .create(
                    .init(
                        destination: .existingFile(testESFile1.converted)
                    )
                )
            )
        }
    }
    
    func test_esEvent_create_new() throws {
        var event = es_event_create_t.bzeroed()
        event.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        event.destination.new_path.dir = testESFile1.es
        event.destination.new_path.filename = testESString1.es
        event.destination.new_path.mode = 0777
        
        let initial = es_events_t(create: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_AUTH_CREATE] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .create(
                    .init(
                        destination: .newPath(
                            dir: testESFile1.converted,
                            filename: testESString1.converted,
                            mode: 0777
                        )
                    )
                )
            )
        }
    }
    
    func test_esEvent_cs_invalidated() throws {
        let event = es_event_cs_invalidated_t.bzeroed()
        
        let initial = es_events_t(cs_invalidated: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED, restored)
        
        XCTAssertEqual(converted, .csInvalidated)
    }
    
    func test_esEvent_deleteextattr() throws {
        var event = es_event_deleteextattr_t.bzeroed()
        event.extattr = testESString1.es
        event.target = testESFile1.es
        
        let initial = es_events_t(deleteextattr: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, ES_EVENT_TYPE_AUTH_DELETEEXTATTR] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            if case let .deleteextattr(convertedEvent) = converted {
                XCTAssertEqual(convertedEvent.extattr, testESString1.converted)
                XCTAssertEqual(convertedEvent.target, testESFile1.converted)
            } else {
                XCTFail("Invalid event decoded")
            }
            XCTAssertEqual(
                converted,
                .deleteextattr(
                    .init(
                        target: testESFile1.converted,
                        extattr: testESString1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_dup() throws {
        var event = es_event_dup_t.bzeroed()
        event.target = testESFile1.es
        
        let initial = es_events_t(dup: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_DUP, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_DUP, restored)
        
        XCTAssertEqual(
            converted,
            .dup(
                .init(
                    target: testESFile1.converted
                )
            )
        )
    }
    
    func test_esEvent_exchangedata() throws {
        var event = es_event_exchangedata_t.bzeroed()
        event.file1 = testESFile1.es
        event.file2 = testESFile2.es
        
        let initial = es_events_t(exchangedata: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_EXCHANGEDATA] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .exchangedata(
                    .init(
                        file1: testESFile1.converted,
                        file2: testESFile2.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_exec() throws {
        var event = es_event_exec_t.bzeroed()
        event.target = testESProcess.es
        event.script = testESFile1.es
        event.cwd = testESFile2.es
        event.last_fd = 10
        
        let initial = es_events_t(exec: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_AUTH_EXEC] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .exec(
                    .init(
                        target: testESProcess.converted,
                        script: testESFile1.converted,
                        cwd: testESFile2.converted,
                        lastFD: 10
                    )
                )
            )
        }
    }
    
    func test_esEvent_exit() throws {
        var event = es_event_exit_t.bzeroed()
        event.stat = SIGKILL
        
        let initial = es_events_t(exit: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_EXIT, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_EXIT, restored)
        
        XCTAssertEqual(
            converted,
            .exit(
                .init(
                    status: SIGKILL
                )
            )
        )
    }
    
    func test_esEvent_file_provider_materialize() throws {
        var event = es_event_file_provider_materialize_t.bzeroed()
        event.instigator = testESProcess.es
        event.source = testESFile1.es
        event.target = testESFile2.es
        
        let initial = es_events_t(file_provider_materialize: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE, ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .fileProviderMaterialize(
                    .init(
                        instigator: testESProcess.converted,
                        source: testESFile1.converted,
                        target: testESFile2.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_file_provider_update() throws {
        var event = es_event_file_provider_update_t.bzeroed()
        event.source = testESFile1.es
        event.target_path = testESString1.es
        
        let initial = es_events_t(file_provider_update: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE, ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .fileProviderUpdate(
                    .init(
                        source: testESFile1.converted,
                        targetPath: testESString1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_fcntl() throws {
        var event = es_event_fcntl_t.bzeroed()
        event.target = testESFile1.es
        event.cmd = 123
        
        let initial = es_events_t(fcntl: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_FCNTL, ES_EVENT_TYPE_AUTH_FCNTL] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .fcntl(
                    .init(
                        target: testESFile1.converted,
                        cmd: 123
                    )
                )
            )
        }
    }
    
    func test_esEvent_fork() throws {
        var event = es_event_fork_t.bzeroed()
        event.child = testESProcess.es
        
        let initial = es_events_t(fork: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_FORK, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_FORK, restored)
        
        XCTAssertEqual(
            converted,
            .fork(
                .init(
                    child: testESProcess.converted
                )
            )
        )
    }
    
    func test_esEvent_fsgetpath() throws {
        var event = es_event_fsgetpath_t.bzeroed()
        event.target = testESFile1.es
        
        let initial = es_events_t(fsgetpath: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_FSGETPATH, ES_EVENT_TYPE_AUTH_FSGETPATH] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .fsgetpath(
                    .init(
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_get_task() throws {
        var event = es_event_get_task_t.bzeroed()
        event.target = testESProcess.es
        
        let initial = es_events_t(get_task: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_GET_TASK, ES_EVENT_TYPE_AUTH_GET_TASK] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .getTask(
                    .init(
                        target: testESProcess.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_get_task_read() throws {
        var event = es_event_get_task_read_t.bzeroed()
        event.target = testESProcess.es
        
        let initial = es_events_t(get_task_read: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_GET_TASK_READ, ES_EVENT_TYPE_AUTH_GET_TASK_READ] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .getTaskRead(
                    .init(
                        target: testESProcess.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_get_task_inspect() throws {
        var event = es_event_get_task_inspect_t.bzeroed()
        event.target = testESProcess.es
        
        let initial = es_events_t(get_task_inspect: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT, restored)
        
        XCTAssertEqual(
            converted,
            .getTaskInspect(
                .init(
                    target: testESProcess.converted
                )
            )
        )
    }
    
    func test_esEvent_get_task_name() throws {
        var event = es_event_get_task_name_t.bzeroed()
        event.target = testESProcess.es
        
        let initial = es_events_t(get_task_name: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME, restored)
        
        XCTAssertEqual(
            converted,
            .getTaskName(
                .init(
                    target: testESProcess.converted
                )
            )
        )
    }
    
    func test_esEvent_getattrlist() throws {
        var event = es_event_getattrlist_t.bzeroed()
        event.attrlist = .random
        event.target = testESFile1.es
        
        let initial = es_events_t(getattrlist: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_GETATTRLIST, ES_EVENT_TYPE_AUTH_GETATTRLIST] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .getattrlist(
                    .init(
                        attrlist: event.attrlist,
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_getextattr() throws {
        var event = es_event_getextattr_t.bzeroed()
        event.target = testESFile1.es
        event.extattr = testESString1.es
        
        let initial = es_events_t(getextattr: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_GETEXTATTR, ES_EVENT_TYPE_AUTH_GETEXTATTR] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            if case let .getextattr(convertedEvent) = converted {
                XCTAssertEqual(convertedEvent.target, testESFile1.converted)
                XCTAssertEqual(convertedEvent.extattr, testESString1.converted)
            } else {
                XCTFail("Invalid event decoded")
            }
            XCTAssertEqual(
                converted,
                .getextattr(
                    .init(
                        target: testESFile1.converted,
                        extattr: testESString1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_iokit_open() throws {
        var event = es_event_iokit_open_t.bzeroed()
        event.user_client_type = 1
        event.user_client_class = testESString1.es
        
        let initial = es_events_t(iokit_open: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, ES_EVENT_TYPE_AUTH_IOKIT_OPEN] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            if case let .iokitOpen(convertedEvent) = converted {
                XCTAssertEqual(convertedEvent.userClientType, 1)
                XCTAssertEqual(convertedEvent.userClientClass, testESString1.converted)
            } else {
                XCTFail("Invalid event decoded")
            }
            XCTAssertEqual(
                converted,
                .iokitOpen(
                    .init(
                        userClientType: 1,
                        userClientClass: testESString1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_kextload() throws {
        var event = es_event_kextload_t.bzeroed()
        event.identifier = testESString1.es
        
        let initial = es_events_t(kextload: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_KEXTLOAD, ES_EVENT_TYPE_AUTH_KEXTLOAD] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .kextload(
                    .init(
                        identifier: testESString1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_kextunload() throws {
        var event = es_event_kextunload_t.bzeroed()
        event.identifier = testESString1.es
        
        let initial = es_events_t(kextunload: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, restored)
        
        XCTAssertEqual(
            converted,
            .kextunload(
                .init(
                    identifier: testESString1.converted
                )
            )
        )
    }
    
    func test_esEvent_link() throws {
        var event = es_event_link_t.bzeroed()
        event.source = testESFile1.es
        event.target_dir = testESFile2.es
        event.target_filename = testESString1.es
        
        let initial = es_events_t(link: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_AUTH_LINK] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .link(
                    .init(
                        source: testESFile1.converted,
                        targetDir: testESFile2.converted,
                        targetFilename: testESString1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_listextattr() throws {
        var event = es_event_listextattr_t.bzeroed()
        event.target = testESFile1.es
        
        let initial = es_events_t(listextattr: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, ES_EVENT_TYPE_AUTH_LISTEXTATTR] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .listextattr(
                    .init(
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_lookup() throws {
        var event = es_event_lookup_t.bzeroed()
        event.source_dir = testESFile1.es
        event.relative_target = testESString1.es
        
        let initial = es_events_t(lookup: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_LOOKUP, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_LOOKUP, restored)
        
        XCTAssertEqual(
            converted,
            .lookup(
                .init(
                    sourceDir: testESFile1.converted,
                    relativeTarget: testESString1.converted
                )
            )
        )
    }
    
    func test_esEvent_mmap() throws {
        var event = es_event_mmap_t.bzeroed()
        event.protection = 10
        event.max_protection = 20
        event.flags = 30
        event.file_pos = 40
        event.source = testESFile1.es
        
        let initial = es_events_t(mmap: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_AUTH_MMAP] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .mmap(
                    .init(
                        protection: 10,
                        maxProtection: 20,
                        flags: 30,
                        filePos: 40,
                        source: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_mount() throws {
        var event = es_event_mount_t.bzeroed()
        let ptr = UnsafeMutablePointer<statfs>.allocate(capacity: 1)
        ptr.initialize(to: .random)
        defer { ptr.deallocate() }
        event.statfs = ptr
        
        let initial = es_events_t(mount: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_MOUNT, ES_EVENT_TYPE_AUTH_MOUNT] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .mount(
                    .init(
                        statfs: ptr.pointee
                    )
                )
            )
        }
    }
    
    func test_esEvent_mprotect() throws {
        var event = es_event_mprotect_t.bzeroed()
        event.protection = 10
        event.address = 20
        event.size = 30
        
        let initial = es_events_t(mprotect: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_MPROTECT, ES_EVENT_TYPE_AUTH_MPROTECT] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .mprotect(
                    .init(
                        protection: 10,
                        address: 20,
                        size: 30
                    )
                )
            )
        }
    }
    
    func test_esEvent_open() throws {
        var event = es_event_open_t.bzeroed()
        event.fflag = 123
        event.file = testESFile1.es
        
        let initial = es_events_t(open: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_AUTH_OPEN] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .open(
                    .init(
                        fflag: 123,
                        file: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_proc_check() throws {
        var event = es_event_proc_check_t.bzeroed()
        event.type = ES_PROC_CHECK_TYPE_PIDINFO
        event.target = testESProcess.es
        event.flavor = 123
        
        let initial = es_events_t(proc_check: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_PROC_CHECK, ES_EVENT_TYPE_AUTH_PROC_CHECK] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .procCheck(
                    .init(
                        target: testESProcess.converted,
                        type: ES_PROC_CHECK_TYPE_PIDINFO,
                        flavor: 123
                    )
                )
            )
        }
    }
    
    func test_esEvent_proc_suspend_resume() throws {
        var event = es_event_proc_suspend_resume_t.bzeroed()
        event.type = ES_PROC_SUSPEND_RESUME_TYPE_RESUME
        event.target = testESProcess.es
        
        let initial = es_events_t(proc_suspend_resume: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME, ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .procSuspendResume(
                    .init(
                        target: testESProcess.converted,
                        type: ES_PROC_SUSPEND_RESUME_TYPE_RESUME
                    )
                )
            )
        }
    }
    
    func test_esEvent_pty_close() throws {
        var event = es_event_pty_close_t.bzeroed()
        event.dev = 123
        
        let initial = es_events_t(pty_close: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_PTY_CLOSE, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_PTY_CLOSE, restored)
        
        XCTAssertEqual(
            converted,
            .ptyClose(
                .init(
                    dev: 123
                )
            )
        )
    }
    
    func test_esEvent_pty_grant() throws {
        var event = es_event_pty_grant_t.bzeroed()
        event.dev = 123
        
        let initial = es_events_t(pty_grant: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_PTY_GRANT, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_PTY_GRANT, restored)
        
        XCTAssertEqual(
            converted,
            .ptyGrant(
                .init(
                    dev: 123
                )
            )
        )
    }
    
    func test_esEvent_readdir() throws {
        var event = es_event_readdir_t.bzeroed()
        event.target = testESFile1.es
        
        let initial = es_events_t(readdir: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_READDIR, ES_EVENT_TYPE_AUTH_READDIR] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .readdir(
                    .init(
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_readlink() throws {
        var event = es_event_readlink_t.bzeroed()
        event.source = testESFile1.es
        
        let initial = es_events_t(readlink: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_READLINK, ES_EVENT_TYPE_AUTH_READLINK] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .readlink(
                    .init(
                        source: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_remote_thread_create() throws {
        let state = UnsafeMutablePointer<es_thread_state_t>.allocate(capacity: 1)
        state.initialize(to: es_thread_state_t(flavor: 123, state: testESToken.es))
        defer { state.deallocate() }
        
        var event = es_event_remote_thread_create_t.bzeroed()
        event.thread_state = state
        event.target = testESProcess.es
        
        let initial = es_events_t(remote_thread_create: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, restored)
        
        XCTAssertEqual(
            converted,
            .remoteThreadCreate(
                .init(
                    target: testESProcess.converted,
                    threadState: ESThreadState(flavor: 123, state: testESToken.converted)
                )
            )
        )
    }
    
    func test_esEvent_remount() throws {
        let ptr = UnsafeMutablePointer<statfs>.allocate(capacity: 1)
        ptr.initialize(to: .random)
        
        var event = es_event_remount_t.bzeroed()
        event.statfs = ptr
        
        let initial = es_events_t(remount: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_REMOUNT, ES_EVENT_TYPE_AUTH_REMOUNT] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .remount(
                    .init(
                        statfs: ptr.pointee
                    )
                )
            )
        }
    }
    
    func test_esEvent_rename_existing() throws {
        var event = es_event_rename_t.bzeroed()
        event.source = testESFile1.es
        event.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE
        event.destination.existing_file = testESFile2.es
        
        let initial = es_events_t(rename: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_AUTH_RENAME] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .rename(
                    .init(
                        source: testESFile1.converted,
                        destination: .existingFile(testESFile2.converted)
                    )
                )
            )
        }
    }
    
    func test_esEvent_rename_new() throws {
        var event = es_event_rename_t.bzeroed()
        event.source = testESFile1.es
        event.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        event.destination.new_path.dir = testESFile2.es
        event.destination.new_path.filename = testESString1.es
        
        let initial = es_events_t(rename: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_AUTH_RENAME] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .rename(
                    .init(
                        source: testESFile1.converted,
                        destination: .newPath(
                            dir: testESFile2.converted,
                            filename: testESString1.converted
                        )
                    )
                )
            )
        }
    }
    
    func test_esEvent_searchfs() throws {
        var event = es_event_searchfs_t.bzeroed()
        event.attrlist = .random
        event.target = testESFile1.es
        
        let initial = es_events_t(searchfs: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_SEARCHFS, ES_EVENT_TYPE_AUTH_SEARCHFS] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .searchfs(
                    .init(
                        attrlist: event.attrlist,
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_setacl() throws {
        var event = es_event_setacl_t.bzeroed()
        event.target = testESFile1.es
        event.set_or_clear = ES_SET
        
        let initial = es_events_t(setacl: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_SETACL, ES_EVENT_TYPE_AUTH_SETACL] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .setacl(
                    .init(
                        target: testESFile1.converted,
                        setOrClear: ES_SET
                    )
                )
            )
        }
    }
    
    func test_esEvent_setattrlist() throws {
        var event = es_event_setattrlist_t.bzeroed()
        event.attrlist = .random
        event.target = testESFile1.es
        
        let initial = es_events_t(setattrlist: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_SETATTRLIST, ES_EVENT_TYPE_AUTH_SETATTRLIST] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .setattrlist(
                    .init(
                        attrlist: event.attrlist,
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_setextattr() throws {
        var event = es_event_setextattr_t.bzeroed()
        event.target = testESFile1.es
        event.extattr = testESString1.es
        
        let initial = es_events_t(setextattr: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_SETEXTATTR, ES_EVENT_TYPE_AUTH_SETEXTATTR] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .setextattr(
                    .init(
                        target: testESFile1.converted,
                        extattr: testESString1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_setflags() throws {
        var event = es_event_setflags_t.bzeroed()
        event.flags = 123
        event.target = testESFile1.es
        
        let initial = es_events_t(setflags: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_SETFLAGS, ES_EVENT_TYPE_AUTH_SETFLAGS] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .setflags(
                    .init(
                        flags: 123,
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_setmode() throws {
        var event = es_event_setmode_t.bzeroed()
        event.mode = 123
        event.target = testESFile1.es
        
        let initial = es_events_t(setmode: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_SETMODE, ES_EVENT_TYPE_AUTH_SETMODE] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .setmode(
                    .init(
                        mode: 123,
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_setowner() throws {
        var event = es_event_setowner_t.bzeroed()
        event.uid = 123
        event.gid = 456
        event.target = testESFile1.es
        
        let initial = es_events_t(setowner: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_SETOWNER, ES_EVENT_TYPE_AUTH_SETOWNER] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .setowner(
                    .init(
                        uid: 123,
                        gid: 456,
                        target: testESFile1.converted)
                    
                )
            )
        }
    }
    
    func test_esEvent_settime() throws {
        let event = es_event_settime_t.bzeroed()
        
        let initial = es_events_t(settime: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_SETTIME, ES_EVENT_TYPE_AUTH_SETTIME] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(converted, .settime)
        }
    }
    
    func test_esEvent_signal() throws {
        var event = es_event_signal_t.bzeroed()
        event.sig = SIGKILL
        event.target = testESProcess.es
        
        let initial = es_events_t(signal: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_SIGNAL, ES_EVENT_TYPE_AUTH_SIGNAL] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .signal(
                    .init(
                        sig: SIGKILL,
                        target: testESProcess.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_stat() throws {
        var event = es_event_stat_t.bzeroed()
        event.target = testESFile1.es
        
        let initial = es_events_t(stat: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_STAT, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_STAT, restored)
        
        XCTAssertEqual(
            converted,
            .stat(
                .init(
                    target: testESFile1.converted
                )
            )
        )
    }
    
    func test_esEvent_trace() throws {
        var event = es_event_trace_t.bzeroed()
        event.target = testESProcess.es
        
        let initial = es_events_t(trace: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_TRACE, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_TRACE, restored)
        
        XCTAssertEqual(
            converted,
            .trace(
                .init(
                    target: testESProcess.converted
                )
            )
        )
    }
    
    func test_esEvent_truncate() throws {
        var event = es_event_truncate_t.bzeroed()
        event.target = testESFile1.es
        
        let initial = es_events_t(truncate: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_TRUNCATE, ES_EVENT_TYPE_AUTH_TRUNCATE] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .truncate(
                    .init(
                        target: testESFile1.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_uipc_bind() throws {
        var event = es_event_uipc_bind_t.bzeroed()
        event.dir = testESFile1.es
        event.filename = testESString1.es
        event.mode = 123
        
        let initial = es_events_t(uipc_bind: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_UIPC_BIND, ES_EVENT_TYPE_AUTH_UIPC_BIND] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .uipcBind(
                    .init(
                        dir: testESFile1.converted,
                        filename: testESString1.converted,
                        mode: 123
                    )
                )
            )
        }
    }
    
    func test_esEvent_uipc_connect() throws {
        var event = es_event_uipc_connect_t.bzeroed()
        event.file = testESFile1.es
        event.domain = 123
        event.type = 456
        event.protocol = 789
        
        let initial = es_events_t(uipc_connect: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, ES_EVENT_TYPE_AUTH_UIPC_CONNECT] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .uipcConnect(
                    .init(
                        file: testESFile1.converted,
                        domain: 123,
                        type: 456,
                        protocol: 789
                    )
                )
            )
        }
    }
    
    func test_esEvent_unlink() throws {
        var event = es_event_unlink_t.bzeroed()
        event.target = testESFile1.es
        event.parent_dir = testESFile2.es
        
        let initial = es_events_t(unlink: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_AUTH_UNLINK] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .unlink(
                    .init(
                        target: testESFile1.converted,
                        parentDir: testESFile2.converted
                    )
                )
            )
        }
    }
    
    func test_esEvent_unmount() throws {
        var event = es_event_unmount_t.bzeroed()
        let ptr = UnsafeMutablePointer<statfs>.allocate(capacity: 1)
        ptr.initialize(to: .random)
        defer { ptr.deallocate() }
        event.statfs = ptr
        
        let initial = es_events_t(unmount: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_UNMOUNT, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_UNMOUNT, restored)
        
        XCTAssertEqual(
            converted,
            .unmount(
                .init(
                    statfs: ptr.pointee
                )
            )
        )
    }
    
    func test_esEvent_utimes() throws {
        var event = es_event_utimes_t.bzeroed()
        event.target = testESFile1.es
        event.atime = .init(tv_sec: 10, tv_nsec: 20)
        event.mtime = .init(tv_sec: 30, tv_nsec: 40)
        
        let initial = es_events_t(utimes: event)
        for eventType in [ES_EVENT_TYPE_NOTIFY_UTIMES, ES_EVENT_TYPE_AUTH_UTIMES] {
            let restored = try encodeDecode(eventType, initial)
            let converted = try converter.esEvent(eventType, restored)
            
            XCTAssertEqual(
                converted,
                .utimes(
                    .init(
                        target: testESFile1.converted,
                        aTime: event.atime,
                        mTime: event.mtime
                    )
                )
            )
        }
    }
    
    func test_esEvent_write() throws {
        var event = es_event_write_t.bzeroed()
        event.target = testESFile1.es
        
        let initial = es_events_t(write: event)
        let restored = try encodeDecode(ES_EVENT_TYPE_NOTIFY_WRITE, initial)
        let converted = try converter.esEvent(ES_EVENT_TYPE_NOTIFY_WRITE, restored)
        
        XCTAssertEqual(
            converted,
            .write(
                .init(
                    target: testESFile1.converted
                )
            )
        )
    }
}

private extension ESMessageSerializationTests {
    func encodeDecode<T: LocalConstructible>(_ value: T) throws -> Resource<T> {
        let writerOutput = DataBinaryWriterOutput()
        var writer = BinaryWriter(writerOutput)
        writer.userInfo.setMessageVersion(UInt32(converter.version))
        try value.encode(with: &writer)
        
        var reader = BinaryReader(data: writerOutput.data)
        reader.userInfo.setMessageVersion(UInt32(converter.version))
        let restored = try T(from: &reader)
        
        return .raii(restored) { $0.freeInternals() }
    }
    
    func encodeDecode(_ type: es_event_type_t, _ event: es_events_t) throws -> Resource<es_events_t> {
        let writerOutput = DataBinaryWriterOutput()
        var writer = BinaryWriter(writerOutput)
        writer.userInfo.setMessageVersion(UInt32(converter.version))
        try event.encode(type: type, with: &writer)
        
        var reader = BinaryReader(data: writerOutput.data)
        reader.userInfo.setMessageVersion(UInt32(converter.version))
        var restored = es_events_t()
        try restored.decode(type: type, from: &reader)
        
        return .raii(restored) { $0.freeInternals(type: type) }
    }
    
    func rawESString(_ str: String) -> Resource<es_string_token_t> {
        let ptr: UnsafeMutablePointer<CChar>! = strdup(str)
        return .raii(es_string_token_t(length: strlen(ptr), data: ptr), cleanup: { _ in free(ptr) })
    }
    
    func rawESToken(_ data: Data) -> Resource<es_token_t> {
        let rawPtr = data.withUnsafeBytes { buffer -> UnsafeMutablePointer<UInt8> in
            let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: buffer.count)
            guard let address = buffer.bindMemory(to: UInt8.self).baseAddress else { return ptr }
            ptr.initialize(from: address, count: buffer.count)
            return ptr
        }
        let ptr = Resource.pointer(rawPtr)
        return .raii(es_token_t(size: data.count, data: ptr.unsafeValue), cleanup: { _ in ptr.cleanup() })
    }
    
    func rawESFile(_ path: String, truncated: Bool, stat: stat) -> Resource<UnsafeMutablePointer<es_file_t>> {
        let pathPtr = rawESString(path)
        let rawFile = UnsafeMutablePointer<es_file_t>.allocate(capacity: 1)
        rawFile.initialize(
            to: es_file_t(
                path: pathPtr.unsafeValue,
                path_truncated: truncated,
                stat: stat
            )
        )
        
        return .raii(rawFile) {
            $0.deallocate()
            withExtendedLifetime(pathPtr, {})
        }
    }
}

private func withExtendedLifetime(_ values: [Any], _ body: () throws -> Void) rethrows -> Void {
    try withExtendedLifetime(values as Any, body)
}

private extension LocalConstructible {
    static func bzeroed() -> Self {
        let tmp = UnsafeMutablePointer<Self>.allocate(capacity: 1)
        defer { tmp.deallocate() }
        tmp.bzero()
        return tmp.pointee
    }
}
