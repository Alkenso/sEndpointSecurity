@testable import sEndpointSecurity

import EndpointSecurity
import Foundation
import SwiftConvenience
import SwiftConvenienceTestUtils
import XCTest

class ESClientTests: XCTestCase {
    var native: MockNativeClient!
    var client: ESClient!
    var handler: es_handler_block_t!
    
    override func setUpWithError() throws {
        native = MockNativeClient()
        client = try ESClient.test {
            $0 = native
            handler = $1
            return ES_NEW_CLIENT_RESULT_SUCCESS
        }
    }
    
    func test_usualFlow() throws {
        let queue = DispatchQueue.main
        client.queue = queue
        
        let processMuteHandlerExp = expectation(description: "Process mute handler called once per process")
        client.pathInterestHandler = {
            dispatchPrecondition(condition: .onQueue(queue))
            
            XCTAssertEqual($0.name, "test")
            processMuteHandlerExp.fulfill()
            return .listen()
        }
        
        let authMessageHandlerExp = expectation(description: "Auth handler is called")
        client.authMessageHandler = {
            dispatchPrecondition(condition: .onQueue(queue))
            
            XCTAssertEqual($0.event_type, ES_EVENT_TYPE_AUTH_SETTIME)
            $1(.allow)
            authMessageHandlerExp.fulfill()
        }
        
        let postAuthMessageHandlerExp = expectation(description: "Post-auth handler is called")
        client.postAuthMessageHandler = { [weak self] in
            dispatchPrecondition(condition: .onQueue(queue))
            
            XCTAssertEqual($0.event_type, ES_EVENT_TYPE_AUTH_SETTIME)
            XCTAssertEqual($1, ESClient.ResponseInfo(reason: .normal, resolution: .allow, status: ES_RESPOND_RESULT_SUCCESS))
            postAuthMessageHandlerExp.fulfill()
            
            XCTAssertEqual(self?.native.responses[$0.global_seq_num], .allow)
        }
        
        let notifyMessageHandlerExp = expectation(description: "Notify handler is called")
        client.notifyMessageHandler = {
            dispatchPrecondition(condition: .onQueue(queue))
            
            XCTAssertEqual($0.event_type, ES_EVENT_TYPE_NOTIFY_SETTIME)
            notifyMessageHandlerExp.fulfill()
        }
        
        XCTAssertEqual(client.subscribe([ES_EVENT_TYPE_AUTH_SETTIME, ES_EVENT_TYPE_NOTIFY_SETTIME]), true)
        XCTAssertEqual(native.subscriptions, [ES_EVENT_TYPE_AUTH_SETTIME, ES_EVENT_TYPE_NOTIFY_SETTIME])
        
        emitMessage(path: "/path/to/test", signingID: "s1", teamID: "t1", event: ES_EVENT_TYPE_AUTH_SETTIME, isAuth: true)
        emitMessage(path: "/path/to/test", signingID: "s1", teamID: "t1", event: ES_EVENT_TYPE_NOTIFY_SETTIME, isAuth: false)
        
        waitForExpectations(timeout: 0.1)
    }
    
    func test_mutes_ignores() {
        // Case 1.
        XCTAssertTrue(client.mutePath("test1", type: ES_MUTE_PATH_TYPE_LITERAL))
        
        let expCase1Test1NotCalled = expectation(description: "case 1: test1 process should be muted")
        expCase1Test1NotCalled.isInverted = true
        let expCase1Other = expectation(description: "case 1: other processes not muted")
        expCase1Other.expectedFulfillmentCount = 2
        client.notifyMessageHandler = {
            let name = ESConverter(version: $0.version).esProcess($0.process.pointee).name
            if name == "test1" {
                expCase1Test1NotCalled.fulfill()
            } else {
                XCTAssertTrue(name.contains("other"))
                expCase1Other.fulfill()
            }
        }
        emitMessage(path: "other1", signingID: "", teamID: "", event: ES_EVENT_TYPE_NOTIFY_OPEN, isAuth: false)
        emitMessage(path: "test1", signingID: "", teamID: "", event: ES_EVENT_TYPE_NOTIFY_OPEN, isAuth: false)
        emitMessage(path: "other2", signingID: "", teamID: "", event: ES_EVENT_TYPE_NOTIFY_CLOSE, isAuth: false)
        
        waitForExpectations()
        
        // Case 2.
        XCTAssertTrue(client.mutePath("test2", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN]))
        
        let expCase2OpenNotCalled = expectation(description: "case 2: OPEN event is mutes")
        expCase2OpenNotCalled.isInverted = true
        let expCase2OtherCalled = expectation(description: "case 2: other events not muted")
        expCase2OtherCalled.expectedFulfillmentCount = 2
        client.notifyMessageHandler = {
            if $0.event_type == ES_EVENT_TYPE_NOTIFY_OPEN {
                expCase2OpenNotCalled.fulfill()
            } else {
                expCase2OtherCalled.fulfill()
            }
        }
        emitMessage(path: "test2", signingID: "", teamID: "", event: ES_EVENT_TYPE_NOTIFY_EXEC, isAuth: false)
        emitMessage(path: "test2", signingID: "", teamID: "", event: ES_EVENT_TYPE_NOTIFY_OPEN, isAuth: false)
        emitMessage(path: "test2", signingID: "", teamID: "", event: ES_EVENT_TYPE_NOTIFY_OPEN, isAuth: false)
        emitMessage(path: "test2", signingID: "", teamID: "", event: ES_EVENT_TYPE_NOTIFY_CLOSE, isAuth: false)
        
        waitForExpectations()
        
        // Case 3.
        client.clearPathInterestCache()
        let expCase3Test3Handler = expectation(description: "case 3: test3 muteHandler should be called once")
        let expCase3Test4Handler = expectation(description: "case 3: test4 muteHandler should be called once")
        let expCase3Test5Handler = expectation(description: "case 3: test5 muteHandler should be called once")
        let expCase3OtherHandler = expectation(description: "case 3: others muteHandler should be called once per path")
        expCase3OtherHandler.expectedFulfillmentCount = 2 // `other1` and `other2`.
        client.pathInterestHandler = {
            if $0.name == "test3" {
                expCase3Test3Handler.fulfill()
                return .ignore()
            }
            if $0.name == "test4" {
                expCase3Test4Handler.fulfill()
                return .ignore()
            }
            if $0.name == "test5" {
                expCase3Test5Handler.fulfill()
                return .listen()
            }
            expCase3OtherHandler.fulfill()
            return .listen()
        }
        
        let expCase3Test3NotCalled = expectation(description: "case 3: test3 is muted for all events")
        expCase3Test3NotCalled.isInverted = true
        let expCase3Test4NotCalled = expectation(description: "case 3: test4 is muted for all events")
        expCase3Test4NotCalled.isInverted = true
        let expCase3Test5Called = expectation(description: "case 3: test5 is not muted")
        expCase3Test5Called.expectedFulfillmentCount = 2
        let expCase3OtherCalled = expectation(description: "case 3: others are not muted")
        expCase3OtherCalled.expectedFulfillmentCount = 4 // 2 by `other1` and 2 by `other2`.
        client.notifyMessageHandler = {
            let name = ESConverter(version: $0.version).esProcess($0.process.pointee).name
            switch name {
            case "test3": expCase3Test3NotCalled.fulfill()
            case "test4": expCase3Test4NotCalled.fulfill()
            case "test5": expCase3Test5Called.fulfill()
            default: expCase3OtherCalled.fulfill()
            }
        }
        for event in [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE] {
            for path in ["other1", "test3", "test4", "test5", "other2"] {
                emitMessage(path: path, signingID: "", teamID: "", event: event, isAuth: false)
            }
        }
        
        waitForExpectations()
    }
    
    @available(macOS 13.0, *)
    func test_inverted() {
        XCTAssertTrue(client.invertMuting(ES_MUTE_INVERSION_TYPE_PATH))
        
        /// Only events from `test...` shoud come.
        XCTAssertTrue(client.mutePath("test", type: ES_MUTE_PATH_TYPE_PREFIX))
        
        let processMuteHandlerExp = expectation(description: "Process mute handler called once per process")
        processMuteHandlerExp.expectedFulfillmentCount = 2
        client.pathInterestHandler = {
            XCTAssertEqual($0.name.starts(with: "test"), true)
            processMuteHandlerExp.fulfill()
            var ignores = [ES_EVENT_TYPE_AUTH_KEXTLOAD]
            if $0.name == "test2" {
                ignores.append(ES_EVENT_TYPE_NOTIFY_EXIT)
            }
            return .ignore(ESEventSet(events: ignores), suggestNativeMuting: true)
        }
        
        let authMessageHandlerExp = expectation(description: "Auth handler is called")
        authMessageHandlerExp.expectedFulfillmentCount = 2
        client.authMessageHandler = {
            XCTAssertEqual($0.event_type, ES_EVENT_TYPE_AUTH_SETTIME)
            $1(.allow)
            authMessageHandlerExp.fulfill()
        }
        
        let postAuthMessageHandlerExp = expectation(description: "Post-auth handler is called")
        postAuthMessageHandlerExp.expectedFulfillmentCount = 8
        client.postAuthMessageHandler = { _, _ in
            postAuthMessageHandlerExp.fulfill()
        }
        
        let notifyMessageHandlerExp = expectation(description: "Notify handler is called")
        notifyMessageHandlerExp.expectedFulfillmentCount = 3 // 2 for test1 + 1 for test2
        client.notifyMessageHandler = { _ in
            notifyMessageHandlerExp.fulfill()
        }
        
        for event in [ES_EVENT_TYPE_AUTH_SETTIME, ES_EVENT_TYPE_AUTH_KEXTLOAD] {
            for path in ["other1", "test1", "test2", "other2"] {
                emitMessage(path: path, signingID: "", teamID: "", event: event, isAuth: true)
            }
        }
        for event in [ES_EVENT_TYPE_NOTIFY_SETTIME, ES_EVENT_TYPE_NOTIFY_EXIT] {
            for path in ["other1", "test1", "test2", "other2"] {
                emitMessage(path: path, signingID: "", teamID: "", event: event, isAuth: false)
            }
        }
        
        waitForExpectations(timeout: 0.1)
    }
    
    private func emitMessage(path: String, signingID: String, teamID: String, event: es_event_type_t, isAuth: Bool) {
        let message = Self.createMessage(path: path, signingID: signingID, teamID: teamID, event: event, isAuth: isAuth)
        Self.emitQueue.async { [self] in
            handler(OpaquePointer(Unmanaged.passUnretained(native).toOpaque()), message.unsafeValue)
            Self.emitQueue.asyncAfter(deadline: .now() + 1, execute: message.cleanup)
        }
    }
    
    private static func createMessage(path: String, signingID: String, teamID: String, event: es_event_type_t, isAuth: Bool) -> Resource<UnsafePointer<es_message_t>> {
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
    
    private static var nextMessageID: UInt64 = 1
    private static let emitQueue = DispatchQueue(label: "ESClientTest.es_native_queue")
}

private extension es_string_token_t {
    init(string: String) {
        let ptr = strdup(string)
        self.init(length: UnsafePointer(ptr).flatMap(strlen) ?? 0, data: ptr)
    }
}
