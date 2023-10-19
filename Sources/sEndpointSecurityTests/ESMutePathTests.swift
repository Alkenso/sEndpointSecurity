@testable import sEndpointSecurity

import EndpointSecurity
import Foundation
import SpellbookFoundation
import XCTest

@available(macOS 13.0, *)
class ESMutePathTests: XCTestCase {
    private let client = MockNativeClient()
    
    override func setUp() {
        client.pathMutes.removeAll()
    }
    
    func test_checkIgnored_mute() {
        func test(useAPIv12: Bool) {
            let mutes = ESMutePath(client: client, useAPIv12: useAPIv12)
            
            mutes.interestHandler = {
                switch $0.executable.path {
                case "path3": return .ignore([ES_EVENT_TYPE_NOTIFY_OPEN])
                case "path4": return .ignore([ES_EVENT_TYPE_NOTIFY_OPEN])
                default: return .listen()
                }
            }
            
            mutes.mute("path1", type: ES_MUTE_PATH_TYPE_LITERAL, events: ESEventSet.all.events)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_ACCESS, path: "path1", process: .test("path1")), true)
            
            mutes.mute("path2", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN])
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path1", process: .test("path1")), true)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path2", process: .test("path2")), true)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_EXEC, path: "path2", process: .test("path2")), false)
            
            mutes.mute("path3", type: ES_MUTE_PATH_TYPE_LITERAL, events: [])
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path3", process: .test("path3")), true)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_EXEC, path: "path3", process: .test("path3")), false)
            
            mutes.mute("path4", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_CLOSE])
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_CLOSE, path: "path4", process: .test("path4")), true)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path4", process: .test("path4")), true)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_EXEC, path: "path4", process: .test("path4")), false)
        }
        test(useAPIv12: true)
        test(useAPIv12: false)
    }
    
    func test_checkIgnored_unmute() {
        func test(useAPIv12: Bool) {
            let mutes = ESMutePath(client: client, useAPIv12: useAPIv12)
            
            mutes.interestHandler = {
                switch $0.executable.path {
                case "path1": return .ignore([ES_EVENT_TYPE_NOTIFY_RENAME])
                default: return .listen()
                }
            }
            
            mutes.mute("path1", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE])
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path1", process: .test("path1")), true)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_CLOSE, path: "path1", process: .test("path1")), true)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_RENAME, path: "path1", process: .test("path1")), true)
            
            /// The check always return `nil` if `Ignores` not set.
            mutes.clearIgnoreCache()
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_ACCESS, path: "path1", process: .test("path1")), false)
            
            /// Unmute in opposite way keeps check verdicts after unmute.
            mutes.unmute("path1", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN])
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path1", process: .test("path1")), false)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_CLOSE, path: "path1", process: .test("path1")), true)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_RENAME, path: "path1", process: .test("path1")), true)
            
            mutes.unmute("path1", type: ES_MUTE_PATH_TYPE_LITERAL, events: ESEventSet.all.events)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path1", process: .test("path1")), false)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_CLOSE, path: "path1", process: .test("path1")), false)
            XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_RENAME, path: "path1", process: .test("path1")), true)
        }
        
        test(useAPIv12: true)
        test(useAPIv12: false)
    }
    
    func test_checkIgnored_mute_inverted() {
        let mutes = ESMutePath(client: client)
        
        mutes.interestHandler = { _ in
            .ignore([ES_EVENT_TYPE_NOTIFY_EXEC])
        }
        
        mutes.mute("path1", type: ES_MUTE_PATH_TYPE_LITERAL, events: ESEventSet.all.events)
        mutes.mute("path2", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_CLOSE])
        
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path1", process: .test("path1")), true)
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_CLOSE, path: "path1", process: .test("path1")), true)
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_EXEC, path: "path1", process: .test("path1")), true)
        
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path2", process: .test("path2")), false)
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_CLOSE, path: "path2", process: .test("path2")), true)
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_EXEC, path: "path2", process: .test("path2")), true)
        
        XCTAssertTrue(mutes.invertMuting())
        
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path1", process: .test("path1")), false)
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_CLOSE, path: "path1", process: .test("path1")), false)
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_EXEC, path: "path1", process: .test("path1")), true)
        
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_OPEN, path: "path2", process: .test("path2")), true)
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_CLOSE, path: "path2", process: .test("path2")), false)
        XCTAssertEqual(mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_EXEC, path: "path2", process: .test("path2")), true)
    }
    
    func test_esmutes_v12() {
        let mutes = ESMutePath(client: client, useAPIv12: true)
        
        mutes.interestHandler = {
            switch $0.executable.path {
            case "path1":
                return .ignore([ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXEC], suggestNativeMuting: true)
            case "path2":
                return .ignore([ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXEC], suggestNativeMuting: false)
            default:
                return .listen()
            }
        }
        mutes.mute("path1", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXIT])
        mutes.mute("path2", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXIT])

        XCTAssertEqual(
            client.pathMutes["path1"],
            [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXIT]
        )
        XCTAssertEqual(
            client.pathMutes["path2"],
            [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXIT]
        )
        
        _ = mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_ACCESS, path: "path1", process: .test("path1"))
        _ = mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_ACCESS, path: "path2", process: .test("path2"))
        XCTAssertEqual(
            client.pathMutes["path1"],
            [
                ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE,
                ES_EVENT_TYPE_NOTIFY_EXIT,
                ES_EVENT_TYPE_NOTIFY_EXEC,
            ]
        )
        XCTAssertEqual(
            client.pathMutes["path2"],
            [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXIT]
        )
        
        mutes.unmute("path1", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT])
        mutes.unmute("path2", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT])
        XCTAssertEqual(
            client.pathMutes["path1"],
            [
                ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE,
                ES_EVENT_TYPE_NOTIFY_EXEC,
            ]
        )
        XCTAssertEqual(
            client.pathMutes["path2"],
            [ES_EVENT_TYPE_NOTIFY_CLOSE]
        )
        
        mutes.clearIgnoreCache()
        XCTAssertEqual(
            client.pathMutes["path1"],
            [ES_EVENT_TYPE_NOTIFY_CLOSE]
        )
        XCTAssertEqual(
            client.pathMutes["path2"],
            [ES_EVENT_TYPE_NOTIFY_CLOSE]
        )
        
        _ = mutes.unmuteAll()
        XCTAssertEqual(client.pathMutes["path1"] ?? [], [])
        XCTAssertEqual(client.pathMutes["path2"] ?? [], [])
    }
    
    func test_esmutes_v12_unmutePartial() {
        let mutes = ESMutePath(client: client, useAPIv12: true)
        
        mutes.mute("path1", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE])
        XCTAssertEqual(client.pathMutes["path1"], [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE])
        mutes.unmute("path1", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN])
        XCTAssertEqual(client.pathMutes["path1"], [ES_EVENT_TYPE_NOTIFY_CLOSE])
        
        mutes.mute("path2", type: ES_MUTE_PATH_TYPE_LITERAL, events: ESEventSet.all.events)
        XCTAssertEqual(client.pathMutes["path2"], ESEventSet.all.events)
        mutes.unmute("path2", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE])
        XCTAssertEqual(
            client.pathMutes["path2"],
            ESEventSet(events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE]).inverted().events
        )
    }
    
    func test_esmutes_legacy() {
        let mutes = ESMutePath(client: client, useAPIv12: false)
        
        mutes.interestHandler = {
            switch $0.executable.path {
            case "path1":
                return .ignore(.all, suggestNativeMuting: true)
            case "path2":
                return .ignore(.all, suggestNativeMuting: true)
            default:
                return .listen()
            }
        }
        mutes.mute("path1", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXIT])
        mutes.mute("path2", type: ES_MUTE_PATH_TYPE_LITERAL, events: ESEventSet.all.events)

        XCTAssertEqual(client.pathMutes["path1"] ?? [], [])
        XCTAssertEqual(client.pathMutes["path2"], ESEventSet.all.events)
        
        _ = mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_ACCESS, path: "path1", process: .test("path1"))
        _ = mutes.checkIgnored(ES_EVENT_TYPE_NOTIFY_ACCESS, path: "path2", process: .test("path2"))
        XCTAssertEqual(client.pathMutes["path1"] ?? [], [])
        XCTAssertEqual(client.pathMutes["path2"], ESEventSet.all.events)
    }
}
