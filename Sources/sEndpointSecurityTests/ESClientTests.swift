
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
}
