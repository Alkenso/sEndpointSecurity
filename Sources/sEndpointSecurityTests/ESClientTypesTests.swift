@testable import sEndpointSecurity

import EndpointSecurity
import Foundation
import SpellbookFoundation
import XCTest

class ESClientTypesTests: XCTestCase {
    func test_ESAuthResult_flags() {
        XCTAssertEqual(ESAuthResult.auth(true), .flags(.max))
        XCTAssertEqual(ESAuthResult.auth(false), .flags(0))
    }
    
    func test_ESAuthResult_equal() {
        XCTAssertEqual(ESAuthResult.flags(0), .auth(false))
        XCTAssertEqual(ESAuthResult.flags(.max), .auth(true))
    }
    
    func test_ESAuthResolution_combine() {
        XCTAssertEqual(
            ESAuthResolution.combine([]),
            ESAuthResolution(result: .auth(true), cache: false)
        )
        XCTAssertEqual(
            ESAuthResolution.combine([
                ESAuthResolution(result: .flags(123), cache: true),
            ]),
            ESAuthResolution(result: .flags(123), cache: true)
        )
        XCTAssertEqual(
            ESAuthResolution.combine([
                ESAuthResolution(result: .auth(true), cache: false),
                ESAuthResolution(result: .flags(123), cache: true),
            ]),
            ESAuthResolution(result: .flags(123), cache: false)
        )
        XCTAssertEqual(
            ESAuthResolution.combine([
                ESAuthResolution(result: .auth(false), cache: false),
                ESAuthResolution(result: .flags(123), cache: true),
            ]),
            ESAuthResolution(result: .auth(false), cache: false)
        )
        XCTAssertEqual(
            ESAuthResolution.combine([
                ESAuthResolution(result: .auth(true), cache: false),
                ESAuthResolution(result: .flags(0), cache: true),
            ]),
            ESAuthResolution(result: .auth(false), cache: false)
        )
    }
    
    func test_ESInterest() {
        XCTAssertEqual(ESInterest.listen(), ESInterest(events: ESEventSet.all.events))
        XCTAssertEqual(ESInterest.listen([ES_EVENT_TYPE_NOTIFY_OPEN]), ESInterest(events: [ES_EVENT_TYPE_NOTIFY_OPEN]))
        
        XCTAssertEqual(ESInterest.ignore(), ESInterest(events: []))
        XCTAssertEqual(
            ESInterest.ignore([ES_EVENT_TYPE_NOTIFY_OPEN]),
            ESInterest(events: ESEventSet(events: [ES_EVENT_TYPE_NOTIFY_OPEN]).inverted().events)
        )
    }
    
    func test_ESInterest_combine() {
        XCTAssertEqual(ESInterest.combine(.permissive, []), nil)
        XCTAssertEqual(ESInterest.combine(.restrictive, []), nil)
        
        XCTAssertEqual(ESInterest.combine(.permissive, [.listen()]), ESInterest(events: ESEventSet.all.events))
        XCTAssertEqual(ESInterest.combine(.restrictive, [.listen()]), ESInterest(events: ESEventSet.all.events))
        
        XCTAssertEqual(ESInterest.combine(.permissive, [.ignore()]), ESInterest(events: []))
        XCTAssertEqual(ESInterest.combine(.restrictive, [.ignore()]), ESInterest(events: []))
        
        XCTAssertEqual(
            ESInterest.combine(.permissive, [
                .listen([ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE]),
                .listen([ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXEC]),
            ]),
            ESInterest(events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXEC])
        )
        XCTAssertEqual(
            ESInterest.combine(.restrictive, [
                .listen([ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE]),
                .listen([ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXEC]),
            ]),
            ESInterest(events: [ES_EVENT_TYPE_NOTIFY_OPEN])
        )
    }
    
    func test_ESMultipleResolution() {
        let count = 3
        let exp = expectation(description: "")
        let group = ESMultipleResolution(count: count) {
            XCTAssertEqual($0, .allowOnce)
            exp.fulfill()
        }
        (0..<count).forEach { _ in group.resolve(.allowOnce) }
        
        waitForExpectations()
    }
}
