@testable import sEndpointSecurity

import Foundation
import SwiftConvenience
import XCTest


class EESClientTests: XCTestCase {
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
                ESAuthResolution(result: .flags(123), cache: true)
            ]),
            ESAuthResolution(result: .flags(123), cache: true)
        )
        XCTAssertEqual(
            ESAuthResolution.combine([
                ESAuthResolution(result: .auth(true), cache: false),
                ESAuthResolution(result: .flags(123), cache: true)
            ]),
            ESAuthResolution(result: .flags(123), cache: false)
        )
        XCTAssertEqual(
            ESAuthResolution.combine([
                ESAuthResolution(result: .auth(false), cache: false),
                ESAuthResolution(result: .flags(123), cache: true)
            ]),
            ESAuthResolution(result: .auth(false), cache: false)
        )
        XCTAssertEqual(
            ESAuthResolution.combine([
                ESAuthResolution(result: .auth(true), cache: false),
                ESAuthResolution(result: .flags(0), cache: true)
            ]),
            ESAuthResolution(result: .auth(false), cache: false)
        )
    }
}
