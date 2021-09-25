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
        
        XCTAssertFalse(ESMuteProcess.name("some_name").matches(process: process))
        XCTAssertTrue(ESMuteProcess.name("test_process").matches(process: process))
        
        XCTAssertFalse(ESMuteProcess.pathPrefix("/Volumes/usb").matches(process: process))
        XCTAssertTrue(ESMuteProcess.pathPrefix("/root").matches(process: process))
        
        XCTAssertFalse(ESMuteProcess.pathLiteral("/Volumes/usb").matches(process: process))
        XCTAssertFalse(ESMuteProcess.pathLiteral("/root").matches(process: process))
        XCTAssertTrue(ESMuteProcess.pathLiteral(process.executable.path).matches(process: process))
    }
}
