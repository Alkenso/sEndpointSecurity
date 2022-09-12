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

class ESMuteProcessTests: XCTestCase {
    private let client = MockNativeClient()
    
    func test() {
        func test(mutes: ESMuteProcess) {
            let token1 = audit_token_t.random()
            let token2 = audit_token_t.random()
            let token3 = audit_token_t.random()
            let token4 = audit_token_t.random()
            let token5 = audit_token_t.random()
            
            mutes.mute(token1, events: .all)
            mutes.mute(token2, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT])
            mutes.mute(token3, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT])
            
            ESEventSet.all.events.forEach {
                XCTAssertTrue(mutes.checkMuted(.test(token1), event: $0, additionalyMuted: .empty))
            }
            
            XCTAssertTrue(mutes.checkMuted(.test(token2), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertTrue(mutes.checkMuted(.test(token2), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test(token2), event: ES_EVENT_TYPE_NOTIFY_WRITE, additionalyMuted: .empty))
            
            XCTAssertTrue(mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: [ES_EVENT_TYPE_NOTIFY_WRITE]))
            XCTAssertTrue(mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: [ES_EVENT_TYPE_NOTIFY_WRITE]))
            XCTAssertTrue(mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_WRITE, additionalyMuted: [ES_EVENT_TYPE_NOTIFY_WRITE]))
            XCTAssertFalse(mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_COPYFILE, additionalyMuted: [ES_EVENT_TYPE_NOTIFY_WRITE]))
            
            ESEventSet.all.events.forEach { XCTAssertTrue(mutes.checkMuted(.test(token4), event: $0, additionalyMuted: .all)) }
            ESEventSet.all.events.forEach { XCTAssertFalse(mutes.checkMuted(.test(token5), event: $0, additionalyMuted: .empty)) }
            
            // unmute
            mutes.unmute(token1, events: .all)
            mutes.unmute(token2, events: .all)
            ESEventSet.all.events.forEach { XCTAssertFalse(mutes.checkMuted(.test(token1), event: $0, additionalyMuted: .empty)) }
            ESEventSet.all.events.forEach { XCTAssertFalse(mutes.checkMuted(.test(token2), event: $0, additionalyMuted: .empty)) }
            
            mutes.clearAdditionalMutes()
            XCTAssertTrue(mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertTrue(mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_WRITE, additionalyMuted: .empty))
            
            mutes.unmute(token3, events: [ES_EVENT_TYPE_NOTIFY_EXIT])
            XCTAssertTrue(mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
            XCTAssertFalse(mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_EXIT, additionalyMuted: .empty))
            
            mutes.unmuteAll()
            for token in [token1, token2, token3, token4, token5] {
                ESEventSet.all.events.forEach { XCTAssertFalse(mutes.checkMuted(.test(token), event: $0, additionalyMuted: .empty)) }
            }
        }
        
        test(mutes: ESMuteProcess(client: client, environment: .init(useAPIv12: true, checkAlive: { _ in true })))
        test(mutes: ESMuteProcess(client: client, environment: .init(useAPIv12: false, checkAlive: { _ in true })))
    }
    
    func test_esmutes_v12() {
        let mutes = ESMuteProcess(client: client, environment: .init(useAPIv12: true, checkAlive: { _ in true }))
        let token1 = audit_token_t.random()
        let token2 = audit_token_t.random()
        let token3 = audit_token_t.random()
        
        mutes.mute(token1, events: .all)
        XCTAssertEqual(client.mutes[token1], ESEventSet.all.events)
        
        mutes.mute(token2, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE])
        XCTAssertEqual(
            client.mutes[token2],
            [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE]
        )
        
        let additionalyMuted: ESEventSet = [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT]
        _ = mutes.checkMuted(.test(token2), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: additionalyMuted)
        _ = mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: additionalyMuted)
        XCTAssertEqual(
            client.mutes[token2],
            [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_EXIT]
        )
        XCTAssertEqual(client.mutes[token3], [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT])
        
        // unmute
        mutes.unmute(token1, events: [ES_EVENT_TYPE_NOTIFY_OPEN])
        XCTAssertEqual(client.mutes[token1], ESEventSet.all.events.subtracting([ES_EVENT_TYPE_NOTIFY_OPEN]))
        
        mutes.unmute(token2, events: [ES_EVENT_TYPE_NOTIFY_OPEN])
        XCTAssertEqual(client.mutes[token2], [ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_WRITE])
        
        // clear additional mutes cache
        XCTAssertEqual(client.mutes[token3], [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT])
        mutes.clearAdditionalMutes()
        XCTAssertEqual(client.mutes[token2], [ES_EVENT_TYPE_NOTIFY_WRITE])
        XCTAssertEqual(client.mutes[token3] ?? [], [])
    }
    
    func test_esmutes_legacy() {
        let mutes = ESMuteProcess(client: client, environment: .init(useAPIv12: false, checkAlive: { _ in true }))
        let token1 = audit_token_t.random()
        let token2 = audit_token_t.random()
        let token3 = audit_token_t.random()
        
        mutes.mute(token1, events: .all)
        XCTAssertEqual(client.mutes[token1], ESEventSet.all.events)
        
        mutes.mute(token2, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE])
        XCTAssertEqual(client.mutes[token2], nil)
        
        _ = mutes.checkMuted(.test(token2), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .all)
        _ = mutes.checkMuted(.test(token3), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT])
        XCTAssertEqual(client.mutes[token2], ESEventSet.all.events)
        XCTAssertEqual(client.mutes[token3], nil)
        
        // unmute
        mutes.unmute(token1, events: [ES_EVENT_TYPE_NOTIFY_OPEN])
        XCTAssertEqual(client.mutes[token1], nil)
        
        // clear additional mutes cache
        mutes.clearAdditionalMutes()
        XCTAssertEqual(client.mutes[token2], nil)
        XCTAssertEqual(client.mutes[token3], nil)
    }
    
    func test_cleanupDied() {
        var deadToken: audit_token_t?
        let mutes = ESMuteProcess(
            client: client,
            cleanupDelay: 0.05,
            environment: .init(useAPIv12: true, checkAlive: { $0 != deadToken })
        )
        let token1 = audit_token_t.random()
        let token2 = audit_token_t.random()
        
        mutes.mute(token1, events: .all)
        mutes.mute(token2, events: .all)
        XCTAssertTrue(mutes.checkMuted(.test(token1), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
        XCTAssertTrue(mutes.checkMuted(.test(token2), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
        
        deadToken = token1
        Thread.sleep(forTimeInterval: 0.06)
        
        XCTAssertFalse(mutes.checkMuted(.test(token1), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
        XCTAssertTrue(mutes.checkMuted(.test(token2), event: ES_EVENT_TYPE_NOTIFY_OPEN, additionalyMuted: .empty))
    }
}

private class MockNativeClient: ESNativeClient {
    var mutes: [audit_token_t: Set<es_event_type_t>] = [:]
    
    func esMuteProcess(_ auditToken: audit_token_t) -> es_return_t {
        mutes[auditToken] = ESEventSet.all.events
        return ES_RETURN_SUCCESS
    }
    
    func esUnmuteProcess(_ auditToken: audit_token_t) -> es_return_t {
        mutes.removeValue(forKey: auditToken)
        return ES_RETURN_SUCCESS
    }
    
    func esMutedProcesses() -> [audit_token_t]? {
        Array(mutes.filter { $0.value == ESEventSet.all.events }.keys)
    }
    
    func esMuteProcessEvents(_ auditToken: audit_token_t, _ events: [es_event_type_t]) -> es_return_t {
        mutes[auditToken, default: []].formUnion(events)
        return ES_RETURN_SUCCESS
    }
    
    func esUnmuteProcessEvents(_ auditToken: audit_token_t, _ events: [es_event_type_t]) -> es_return_t {
        mutes[auditToken]?.subtract(events)
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
    
    func esMutePath(_ path: String, _ type: es_mute_path_type_t) -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
    
    func esUnmutePath(_ path: String, _ type: es_mute_path_type_t) -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
    
    func esMutePathEvents(_ path: String, _ type: es_mute_path_type_t, _ events: [es_event_type_t]) -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
    
    func esUnmutePathEvents(_ path: String, _ type: es_mute_path_type_t, _ events: [es_event_type_t]) -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
    
    func esUnmuteAllPaths() -> es_return_t {
        XCTFail()
        return ES_RETURN_ERROR
    }
}
