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

import EndpointSecurity
import Foundation
import SwiftConvenience
import XCTest

class ESMutePathTests: XCTestCase {
    private let client = MockNativeClient()
    
    func test() {
        func test(mutes: ESMutePath) {
            mutes.mute(.path("path1", .prefix), events: .all)
            mutes.mute(.path("path2", .literal), events: .all)
            mutes.mute(.name("process", .literal), events: .all)
            mutes.mute(.name("group_", .prefix), events: .all)
            mutes.mute(.path("path_some", .literal), events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_COPYFILE])
            mutes.mute(.path("path_some/group", .prefix), events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE])
            
            XCTAssertTrue(mutes.checkMuted(.test("path1/some"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertTrue(mutes.checkMuted(.test("path1"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            
            XCTAssertTrue(mutes.checkMuted(.test("path2"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertTrue(mutes.checkMuted(.test("path2"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("/some/path2"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            
            XCTAssertTrue(mutes.checkMuted(.test("/some/test/process"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("/some/process/test"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("/some/process2"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            
            XCTAssertTrue(mutes.checkMuted(.test("/some/group_process"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            XCTAssertTrue(mutes.checkMuted(.test("/some/group_"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("/some/group_/proc"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            
            XCTAssertTrue(mutes.checkMuted(.test("path_some"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertTrue(mutes.checkMuted(.test("path_some"), event: ES_EVENT_TYPE_NOTIFY_COPYFILE, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("path_some"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            
            XCTAssertTrue(mutes.checkMuted(.test("path_some/groupA"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("path_some/groupA"), event: ES_EVENT_TYPE_NOTIFY_COPYFILE, additionalyMuted: .empty))
            XCTAssertTrue(mutes.checkMuted(.test("path_some/groupA"), event: ES_EVENT_TYPE_NOTIFY_WRITE, additionalyMuted: .empty))
            
            let additionallyMuted: ESEventSet = [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXEC]
            XCTAssertTrue(mutes.checkMuted(.test("/path/handler"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: additionallyMuted))
            XCTAssertTrue(mutes.checkMuted(.test("/path/handler"), event: ES_EVENT_TYPE_NOTIFY_EXEC, additionalyMuted: additionallyMuted))
            XCTAssertFalse(mutes.checkMuted(.test("/path/handler"), event: ES_EVENT_TYPE_NOTIFY_COPYFILE, additionalyMuted: additionallyMuted))
            
            // unmute
            mutes.unmute(.path("path1", .prefix), events: [ES_EVENT_TYPE_NOTIFY_EXIT])
            XCTAssertTrue(mutes.checkMuted(.test("path1"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("path1"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            
            mutes.unmute(.path("path2", .literal), events: .all)
            XCTAssertFalse(mutes.checkMuted(.test("path2"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("path2"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            
            mutes.clearAdditionalMutes()
            XCTAssertFalse(mutes.checkMuted(.test("/path/handler"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            
            mutes.unmuteAll()
            XCTAssertFalse(mutes.checkMuted(.test("path1"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("path2"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("process"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("group_"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("path_some"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("groupA"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test("handler"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
        }
        
        test(mutes: ESMutePath(client: client))
        test(mutes: ESMutePath(client: client, useAPIv12: false))
    }
    
    func test_partialMuteUnmute() {
        let mutes = ESMutePath(client: client)
        
        mutes.mute(.path("path1", .literal), events: [ES_EVENT_TYPE_NOTIFY_OPEN])
        mutes.mute(.path("path1", .literal), events: [ES_EVENT_TYPE_NOTIFY_EXIT])
        
        XCTAssertTrue(mutes.checkMuted(.test("path1"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
        XCTAssertTrue(mutes.checkMuted(.test("path1"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
        XCTAssertFalse(mutes.checkMuted(.test("path1"), event: ES_EVENT_TYPE_NOTIFY_WRITE, additionalyMuted: .empty))
        
        mutes.unmute(.path("path1", .literal), events: [ES_EVENT_TYPE_NOTIFY_EXIT])
        XCTAssertTrue(mutes.checkMuted(.test("path1"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
        XCTAssertFalse(mutes.checkMuted(.test("path1"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
    }
    
    func test_esmutes_v12() {
        let mutes = ESMutePath(client: client)
        
        mutes.mute(.path("path1", .prefix), events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE])
        mutes.mute(.path("path1", .literal), events: .all)
        mutes.mute(.path("path2", .literal), events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT])
        
        XCTAssertEqual(
            client.mutes[.init(path: "path1", type: ES_MUTE_PATH_TYPE_PREFIX)],
            [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE]
        )
        XCTAssertEqual(
            client.mutes[.init(path: "path1", type: ES_MUTE_PATH_TYPE_LITERAL)],
            ESEventSet.all.events
        )
        XCTAssertEqual(
            client.mutes[.init(path: "path2", type: ES_MUTE_PATH_TYPE_LITERAL)],
            [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT]
        )
        
        let additionallyMuted: ESEventSet = [ES_EVENT_TYPE_NOTIFY_EXIT]
        XCTAssertTrue(mutes.checkMuted(.test("handler"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: additionallyMuted))
        XCTAssertFalse(mutes.checkMuted(.test("handler"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: additionallyMuted))
        XCTAssertEqual(
            client.mutes[.init(path: "handler", type: ES_MUTE_PATH_TYPE_LITERAL)],
            [ES_EVENT_TYPE_NOTIFY_EXIT]
        )
        
        // unmute
        mutes.unmute(.path("path1", .prefix), events: [ES_EVENT_TYPE_NOTIFY_OPEN])
        XCTAssertEqual(
            client.mutes[.init(path: "path1", type: ES_MUTE_PATH_TYPE_PREFIX)],
            [ES_EVENT_TYPE_NOTIFY_WRITE]
        )
        
        // every unmute invalidates handler cache
        XCTAssertEqual(client.mutes[.init(path: "handler", type: ES_MUTE_PATH_TYPE_LITERAL)] ?? [], [])
        
        mutes.unmuteAll()
        XCTAssertEqual(client.mutes.isEmpty, true)
    }
    
    func test_esmutes_legacy() {
        let mutes = ESMutePath(client: client, useAPIv12: false)
        
        mutes.mute(.path("path1", .prefix), events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE])
        mutes.mute(.path("path1", .literal), events: .all)
        mutes.mute(.path("path2", .prefix), events: .all)
        
        XCTAssertEqual(
            client.mutes[.init(path: "path1", type: ES_MUTE_PATH_TYPE_PREFIX)],
            nil
        )
        XCTAssertEqual(client.mutes[.init(path: "path1", type: ES_MUTE_PATH_TYPE_LITERAL)], ESEventSet.all.events)
        XCTAssertEqual(client.mutes[.init(path: "path2", type: ES_MUTE_PATH_TYPE_PREFIX)], ESEventSet.all.events)
        
        XCTAssertTrue(mutes.checkMuted(.test("handler1"), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: [ES_EVENT_TYPE_NOTIFY_EXIT]))
        XCTAssertFalse(mutes.checkMuted(.test("handler1"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: [ES_EVENT_TYPE_NOTIFY_EXIT]))
        XCTAssertTrue(mutes.checkMuted(.test("handler2"), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .all))
        XCTAssertEqual(client.mutes[.init(path: "handler1", type: ES_MUTE_PATH_TYPE_LITERAL)], nil)
        XCTAssertEqual(client.mutes[.init(path: "handler2", type: ES_MUTE_PATH_TYPE_LITERAL)], ESEventSet.all.events)
        
        // partial unmute
        mutes.unmute(.path("path1", .literal), events: [ES_EVENT_TYPE_NOTIFY_OPEN])
        XCTAssertEqual(client.mutes[.init(path: "path1", type: ES_MUTE_PATH_TYPE_LITERAL)], nil)
        XCTAssertEqual(client.mutes[.init(path: "path2", type: ES_MUTE_PATH_TYPE_PREFIX)], ESEventSet.all.events)
        
        // any call to unmute invalidates handler cache
        XCTAssertEqual(client.mutes[.init(path: "handler1", type: ES_MUTE_PATH_TYPE_LITERAL)] ?? [], [])
        XCTAssertEqual(client.mutes[.init(path: "handler2", type: ES_MUTE_PATH_TYPE_LITERAL)] ?? [], [])
        
        mutes.unmuteAll()
        XCTAssertFalse(client.mutes.contains { !$0.value.isEmpty })
        XCTAssertEqual(client.mutes.isEmpty, true)
    }
    
    func test_muteRule() throws {
        let process = ESProcess.test("/root/path/to/executable/test_process")
        
        XCTAssertFalse(ESMutePathRule.teamIdentifier("qwert").matches(process: process))
        XCTAssertTrue(ESMutePathRule.teamIdentifier(process.teamID).matches(process: process))
        
        XCTAssertFalse(ESMutePathRule.signingID("ssssq").matches(process: process))
        XCTAssertTrue(ESMutePathRule.signingID(process.signingID).matches(process: process))
        
        XCTAssertFalse(ESMutePathRule.path("/Volumes/usb", .prefix).matches(process: process))
        XCTAssertTrue(ESMutePathRule.path("/root", .prefix).matches(process: process))
        
        XCTAssertFalse(ESMutePathRule.path("/Volumes/usb", .literal).matches(process: process))
        XCTAssertFalse(ESMutePathRule.path("/root", .literal).matches(process: process))
        XCTAssertTrue(ESMutePathRule.path(process.executable.path, .literal).matches(process: process))
        
        XCTAssertFalse(ESMutePathRule.name("usb_", .prefix).matches(process: process))
        XCTAssertTrue(ESMutePathRule.name("test_", .prefix).matches(process: process))
        
        XCTAssertFalse(ESMutePathRule.name("some_process", .literal).matches(process: process))
        XCTAssertFalse(ESMutePathRule.name("test_process2", .literal).matches(process: process))
        XCTAssertTrue(ESMutePathRule.name(process.name, .literal).matches(process: process))
    }
}

private class MockNativeClient: ESNativeClient {
    struct Key: Hashable {
        var path: String
        var type: es_mute_path_type_t
    }
    
    var mutes: [Key: Set<es_event_type_t>] = [:]
    
    func esMutePath(_ path: String, _ type: es_mute_path_type_t) -> es_return_t {
        mutes[Key(path: path, type: type), default: []] = ESEventSet.all.events
        return ES_RETURN_SUCCESS
    }
    
    func esUnmutePath(_ path: String, _ type: es_mute_path_type_t) -> es_return_t {
        mutes.removeValue(forKey: Key(path: path, type: type))
        return ES_RETURN_SUCCESS
    }
    
    func esMutePathEvents(_ path: String, _ type: es_mute_path_type_t, _ events: [es_event_type_t]) -> es_return_t {
        mutes[Key(path: path, type: type), default: []].formUnion(events)
        return ES_RETURN_SUCCESS
    }
    
    func esUnmutePathEvents(_ path: String, _ type: es_mute_path_type_t, _ events: [es_event_type_t]) -> es_return_t {
        mutes[Key(path: path, type: type), default: []].subtract(events)
        return ES_RETURN_SUCCESS
    }
    
    func esUnmuteAllPaths() -> es_return_t {
        mutes.removeAll()
        return ES_RETURN_SUCCESS
    }
    
    // MARK: Unused
    
    func esRespond(_ message: UnsafePointer<es_message_t>, flags: UInt32, cache: Bool) -> es_respond_result_t {
        XCTFail()
        return ES_RESPOND_RESULT_ERR_INTERNAL
    }
    
    func esSubscribe(_ events: [es_event_type_t]) -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
    
    func esUnsubscribe(_ events: [es_event_type_t]) -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
    
    func esUnsubscribeAll() -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
    
    func esClearCache() -> es_clear_cache_result_t {
        XCTFail()
        return ES_CLEAR_CACHE_RESULT_ERR_INTERNAL
    }
    
    func esMuteProcess(_ auditToken: audit_token_t) -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
    
    func esUnmuteProcess(_ auditToken: audit_token_t) -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
    
    func esMutedProcesses() -> [audit_token_t]? {
        XCTFail()
        return nil
    }
    
    func esMuteProcessEvents(_ auditToken: audit_token_t, _ events: [es_event_type_t]) -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
    
    func esUnmuteProcessEvents(_ auditToken: audit_token_t, _ events: [es_event_type_t]) -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
}
