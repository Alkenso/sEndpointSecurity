@testable import sEndpointSecurity

import EndpointSecurity
import Foundation
import SwiftConvenience
import SwiftConvenienceTestUtils
import XCTest

class ESServiceTests: XCTestCase {
    static let emitQueue = DispatchQueue(label: "ESClientTest.es_native_queue")
    var es: MockESClient!
    var service: ESService!
    
    override func setUp() {
        es = MockESClient()
        service = ESService { [es] in
            $0 = ES_NEW_CLIENT_RESULT_SUCCESS
            return es
        }
    }
    
    func test() {
        var controls: [ESSubscriptionControl] = []
        
        var s1 = ESSubscription()
        s1.events = [ES_EVENT_TYPE_NOTIFY_PTY_GRANT, ES_EVENT_TYPE_NOTIFY_SETUID]
        let s1Exp = expectation(description: "s1 notify called")
        s1Exp.expectedFulfillmentCount = 2
        s1.notifyMessageHandler = { _ in s1Exp.fulfill() }
        controls.append(service.register(s1))
        
        var s2 = ESSubscription()
        s2.events = [ES_EVENT_TYPE_NOTIFY_PTY_GRANT, ES_EVENT_TYPE_NOTIFY_EXIT]
        let s2Exp = expectation(description: "s2 notify called")
        s2Exp.expectedFulfillmentCount = 2
        s2.notifyMessageHandler = { _ in s2Exp.fulfill() }
        controls.append(service.register(s2))
        
        XCTAssertEqual(service.activate(), ES_NEW_CLIENT_RESULT_SUCCESS)
        
        for event in [ES_EVENT_TYPE_NOTIFY_PTY_GRANT, ES_EVENT_TYPE_NOTIFY_SETUID, ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_PTY_CLOSE] {
            emitMessage(path: "test1", signingID: "", teamID: "", event: event)
        }
        
        waitForExpectations()
    }
    
    func test_suspend_resume() {
        var s = ESSubscription()
        s.events = [ES_EVENT_TYPE_NOTIFY_PTY_GRANT, ES_EVENT_TYPE_NOTIFY_SETUID]
        var exp = expectation(description: "notify should not called")
        exp.isInverted = true
        s.notifyMessageHandler = { _ in exp.fulfill() }
        let c = service.register(s, suspended: true)
        
        XCTAssertEqual(service.activate(), ES_NEW_CLIENT_RESULT_SUCCESS)
        
        for event in [ES_EVENT_TYPE_NOTIFY_PTY_GRANT, ES_EVENT_TYPE_NOTIFY_SETUID] {
            emitMessage(path: "test1", signingID: "", teamID: "", event: event)
        }
        waitForExpectations()
        
        exp = expectation(description: "notify called")
        exp.expectedFulfillmentCount = 2
        c.resume()
        for event in [ES_EVENT_TYPE_NOTIFY_PTY_GRANT, ES_EVENT_TYPE_NOTIFY_SETUID] {
            emitMessage(path: "test1", signingID: "", teamID: "", event: event)
        }
        waitForExpectations()
        
        exp = expectation(description: "notify should not called")
        exp.isInverted = true
        c.suspend()
        for event in [ES_EVENT_TYPE_NOTIFY_PTY_GRANT, ES_EVENT_TYPE_NOTIFY_SETUID] {
            emitMessage(path: "test1", signingID: "", teamID: "", event: event)
        }
        waitForExpectations()
    }
    
    func test_controlDeinit() {
        var s = ESSubscription()
        s.events = [ES_EVENT_TYPE_NOTIFY_PTY_GRANT]
        var exp = expectation(description: "notify called")
        s.notifyMessageHandler = { _ in exp.fulfill() }
        var c: ESSubscriptionControl? = service.register(s)
        _ = c
        XCTAssertEqual(service.activate(), ES_NEW_CLIENT_RESULT_SUCCESS)
        
        emitMessage(path: "test1", signingID: "", teamID: "", event: ES_EVENT_TYPE_NOTIFY_PTY_GRANT)
        waitForExpectations()
        
        exp = expectation(description: "notify should not called")
        exp.isInverted = true
        c = nil
        
        emitMessage(path: "test1", signingID: "", teamID: "", event: ES_EVENT_TYPE_NOTIFY_PTY_GRANT)
        waitForExpectations()
    }
    
    private func emitMessage(path: String, signingID: String, teamID: String, event: es_event_type_t) {
        let message = createMessage(path: path, signingID: signingID, teamID: teamID, event: event, isAuth: false)
        Self.emitQueue.async { [self] in
            let messagePtr = ESMessagePtr(unowned: message.unsafeValue)
            let process = try! messagePtr.converted().process
            _ = es.pathInterestHandler?(process)
            _ = es.notifyMessageHandler?(messagePtr)
            Self.emitQueue.asyncAfter(deadline: .now() + 1, execute: message.cleanup)
        }
    }
}
