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
}
