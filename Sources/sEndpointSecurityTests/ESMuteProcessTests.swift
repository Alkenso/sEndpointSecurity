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

class ESMuteProcessTests: XCTestCase {
    func process() throws -> ESProcess {
        try ESProcess(
            auditToken: .current(),
            ppid: 10,
            originalPpid: 20,
            groupID: 30,
            sessionID: 40,
            codesigningFlags: 50,
            isPlatformBinary: true,
            isESClient: true,
            cdHash: Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            signingID: "signing_id",
            teamID: "team_id",
            executable: ESFile(
                path: "/root/path/to/executable/test_process",
                truncated: false,
                stat: .random()
            ),
            tty: ESFile(
                path: "/root/other_path/to/tty",
                truncated: false,
                stat: .random()
            ),
            startTime: nil,
            responsibleAuditToken: nil,
            parentAuditToken: nil
        )
    }
    
    func test_mute_token() throws {
        let process = try process()
        XCTAssertFalse(ESMuteProcess.token(try .random()).matches(process: process))
        XCTAssertTrue(ESMuteProcess.token(process.auditToken).matches(process: process))
        
        XCTAssertFalse(ESMuteProcess.pid(1).matches(process: process))
        XCTAssertTrue(ESMuteProcess.pid(process.auditToken.pid).matches(process: process))
        
        XCTAssertFalse(ESMuteProcess.euid(1).matches(process: process))
        XCTAssertTrue(ESMuteProcess.euid(process.auditToken.euid).matches(process: process))
        
        XCTAssertFalse(ESMuteProcess.teamIdentifier("qwert").matches(process: process))
        XCTAssertTrue(ESMuteProcess.teamIdentifier(process.teamID).matches(process: process))
        
        XCTAssertFalse(ESMuteProcess.signingID("ssssq").matches(process: process))
        XCTAssertTrue(ESMuteProcess.signingID(process.signingID).matches(process: process))
        
        XCTAssertFalse(ESMuteProcess.path("/Volumes/usb", .prefix).matches(process: process))
        XCTAssertTrue(ESMuteProcess.path("/root", .prefix).matches(process: process))
        
        XCTAssertFalse(ESMuteProcess.path("/Volumes/usb", .literal).matches(process: process))
        XCTAssertFalse(ESMuteProcess.path("/root", .literal).matches(process: process))
        XCTAssertTrue(ESMuteProcess.path(process.executable.path, .literal).matches(process: process))
        
        XCTAssertFalse(ESMuteProcess.name("usb_", .prefix).matches(process: process))
        XCTAssertTrue(ESMuteProcess.name("test_", .prefix).matches(process: process))
        
        XCTAssertFalse(ESMuteProcess.name("some_process", .literal).matches(process: process))
        XCTAssertFalse(ESMuteProcess.name("test_process2", .literal).matches(process: process))
        XCTAssertTrue(ESMuteProcess.name(process.name, .literal).matches(process: process))
    }
}
