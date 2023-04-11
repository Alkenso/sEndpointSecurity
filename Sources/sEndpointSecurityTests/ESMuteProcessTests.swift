@testable import sEndpointSecurity

import EndpointSecurity
import Foundation
import SwiftConvenience
import XCTest

class ESMuteProcessTests: XCTestCase {
    private let client = MockNativeClient()
    private let token1 = audit_token_t.random()
    private let token2 = audit_token_t.random()
    private let token3 = audit_token_t.random()
    private let token4 = audit_token_t.random()
    private let token5 = audit_token_t.random()
    
    override func setUp() {
        client.processMutes.removeAll()
    }
    
    func test() {
        func test(useAPIv12: Bool) {
            let mutes = ESMuteProcess(client: client, environment: .init(useAPIv12: useAPIv12, checkAlive: { _ in true }))
            
            mutes.mute(token1, events: ESEventSet.all.events)
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_ACCESS, process: token1), true)
            
            mutes.mute(token2, events: [ES_EVENT_TYPE_NOTIFY_OPEN])
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_OPEN, process: token2), true)
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_EXEC, process: token2), false)
            
            mutes.mute(token3, events: [])
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_OPEN, process: token3), false)
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_EXEC, process: token3), false)
        }
        
        test(useAPIv12: true)
        test(useAPIv12: false)
    }
    
    func test_checkMuted_unmute() {
        func test(useAPIv12: Bool) {
            let mutes = ESMuteProcess(client: client, environment: .init(useAPIv12: useAPIv12, checkAlive: { _ in true }))
            
            mutes.mute(token1, events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE])
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_ACCESS, process: token1), false)
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_OPEN, process: token1), true)
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_CLOSE, process: token1), true)
            
            mutes.unmute(token1, events: [ES_EVENT_TYPE_NOTIFY_OPEN])
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_RENAME, process: token1), false)
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_OPEN, process: token1), false)
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_CLOSE, process: token1), true)
            
            mutes.unmute(token1, events: ESEventSet.all.events)
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_RENAME, process: token1), false)
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_OPEN, process: token1), false)
            XCTAssertEqual(mutes.checkMuted(ES_EVENT_TYPE_NOTIFY_CLOSE, process: token1), false)
        }
        
        test(useAPIv12: true)
        test(useAPIv12: false)
    }
    
    func test_esmutes_v12() {
        let mutes = ESMuteProcess(client: client, environment: .init(useAPIv12: true, checkAlive: { _ in true }))
        
        mutes.mute(token1, events: [ES_EVENT_TYPE_NOTIFY_EXEC])
        XCTAssertEqual(
            client.processMutes[token1],
            [ES_EVENT_TYPE_NOTIFY_EXEC]
        )
        
        mutes.mute(token1, events: [ES_EVENT_TYPE_NOTIFY_EXIT])
        XCTAssertEqual(
            client.processMutes[token1],
            [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT]
        )

        mutes.unmute(token1, events: [ES_EVENT_TYPE_NOTIFY_EXEC])
        XCTAssertEqual(
            client.processMutes[token1],
            [ES_EVENT_TYPE_NOTIFY_EXIT]
        )
        
        mutes.mute(token1, events: ESEventSet.all.events)
        XCTAssertEqual(
            client.processMutes[token1],
            ESEventSet.all.events
        )

        mutes.unmute(token1, events: ESEventSet.all.events)
        XCTAssertEqual(client.processMutes[token1], [])
    }

    func test_esmutes_legacy() {
        let mutes = ESMuteProcess(client: client, environment: .init(useAPIv12: false, checkAlive: { _ in true }))

        mutes.mute(token1, events: [ES_EVENT_TYPE_NOTIFY_EXEC])
        XCTAssertEqual(client.processMutes[token1] ?? [], [])
        
        mutes.mute(token1, events: [ES_EVENT_TYPE_NOTIFY_EXIT])
        XCTAssertEqual(client.processMutes[token1] ?? [], [])
        
        mutes.mute(token1, events: ESEventSet.all.events)
        XCTAssertEqual(
            client.processMutes[token1],
            ESEventSet.all.events
        )
        
        mutes.unmute(token1, events: [ES_EVENT_TYPE_NOTIFY_EXEC])
        XCTAssertEqual(client.processMutes[token1] ?? [], [])

        mutes.unmute(token1, events: ESEventSet.all.events)
        XCTAssertEqual(client.processMutes[token1] ?? [], [])
    }
}
