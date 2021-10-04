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


class EventSubscribeTests: XCTestCase {
    var subscribedEvents: [es_event_type_t] = []
    var subscribeFails = false
    var unsubscribeFails = false
    var unsubscribeAllFails = false
    
    lazy var subscriptions = EventSubscriptions(
        esSubscribe: {
            guard !self.subscribeFails else { return ES_RETURN_ERROR }
            self.subscribedEvents += $0
            return ES_RETURN_SUCCESS
        },
        esUnsubscribe: {
            guard !self.unsubscribeFails else { return ES_RETURN_ERROR }
            self.subscribedEvents.removeAll(where: $0.contains)
            return ES_RETURN_SUCCESS
        },
        esUnsubscribeAll: {
            guard !self.unsubscribeAllFails else { return ES_RETURN_ERROR }
            self.subscribedEvents.removeAll()
            return ES_RETURN_SUCCESS
        }
    )
    
    override func setUp() {
        subscribedEvents = []
        subscribeFails = false
        unsubscribeFails = false
        unsubscribeAllFails = false
    }
    
    func test_typicalUseCase() {
        //  mandatory subscribe for events
        let mandatory = [
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_REMOUNT,
            ES_EVENT_TYPE_NOTIFY_UNMOUNT,
        ]
        subscriptions.mandatoryEvents = mandatory
        
        //  Initially no events are subscribed
        XCTAssertTrue(subscribedEvents.isEmpty)
        
        let events = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_NOTIFY_REMOUNT, // exists also in 'mandatory'
            ES_EVENT_TYPE_NOTIFY_UNMOUNT, // exists also in 'mandatory'
        ]
        XCTAssertEqual(subscriptions.subscribe(events), ES_RETURN_SUCCESS)
        
        //  First subscription subscribes on events + mandatory events
        XCTAssertTrue(subscribedEvents.containsUniquely([
            ES_EVENT_TYPE_AUTH_EXEC, // exists in 'events'
            ES_EVENT_TYPE_NOTIFY_MOUNT, // exists in 'mandatory'
            ES_EVENT_TYPE_NOTIFY_REMOUNT, // exists also in 'events' and 'mandatory'
            ES_EVENT_TYPE_NOTIFY_UNMOUNT, // exists also in 'events' and 'mandatory'
        ]))
        
        XCTAssertTrue(subscriptions.isSubscribed(ES_EVENT_TYPE_AUTH_EXEC))
        XCTAssertTrue(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_REMOUNT))
        XCTAssertTrue(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_UNMOUNT))
        
        //  But as for usual point of view there is no subscription
        XCTAssertFalse(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_MOUNT))
        
        
        //  Unsubscribe on non-mandatory event
        XCTAssertEqual(subscriptions.unsubscribe([ES_EVENT_TYPE_AUTH_EXEC]), ES_RETURN_SUCCESS)
        XCTAssertFalse(subscriptions.isSubscribed(ES_EVENT_TYPE_AUTH_EXEC))
        XCTAssertFalse(subscribedEvents.contains(ES_EVENT_TYPE_AUTH_EXEC))
        
        //  Unsubscribe on mandatory event
        XCTAssertEqual(subscriptions.unsubscribe([ES_EVENT_TYPE_NOTIFY_REMOUNT]), ES_RETURN_SUCCESS)
        XCTAssertFalse(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_REMOUNT))
        XCTAssertTrue(subscribedEvents.contains(ES_EVENT_TYPE_NOTIFY_REMOUNT))
        
        //  Unsubscribe on last of subscribed event cause 'unsubscribeAll'
        XCTAssertEqual(subscriptions.unsubscribe([ES_EVENT_TYPE_NOTIFY_UNMOUNT]), ES_RETURN_SUCCESS)
        XCTAssertFalse(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_UNMOUNT))
        XCTAssertTrue(subscribedEvents.isEmpty)
    }
    
    func test_initialEmpty() {
        //  Initially not subscribed at all
        for rawType in 0..<ES_EVENT_TYPE_LAST.rawValue {
            XCTAssertFalse(subscriptions.isSubscribed(es_event_type_t(rawValue: rawType)))
        }
    }
    
    func test_subscribeUnsubscribe() {
        let events = [
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_REMOUNT,
            ES_EVENT_TYPE_NOTIFY_UNMOUNT,
        ]
        XCTAssertEqual(subscriptions.subscribe(events), ES_RETURN_SUCCESS)
        XCTAssertTrue(subscribedEvents.containsUniquely(events))
        
        XCTAssertEqual(
            subscriptions.unsubscribe(
                [ES_EVENT_TYPE_NOTIFY_UNMOUNT]
            ),
            ES_RETURN_SUCCESS
        )
        XCTAssertTrue(
            subscribedEvents.containsUniquely(
                [ES_EVENT_TYPE_NOTIFY_MOUNT, ES_EVENT_TYPE_NOTIFY_REMOUNT]
            )
        )
        
        XCTAssertEqual(subscriptions.unsubscribeAll(), ES_RETURN_SUCCESS)
        XCTAssertTrue(subscribedEvents.isEmpty)
    }
    
    func test_subscribeUnsubscribeAll() {
        subscriptions.mandatoryEvents = [ES_EVENT_TYPE_NOTIFY_MOUNT]
        let events = [
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_UNMOUNT,
        ]
        XCTAssertEqual(subscriptions.subscribe(events), ES_RETURN_SUCCESS)
        XCTAssertTrue(subscribedEvents.containsUniquely(events))
        
        XCTAssertEqual(subscriptions.unsubscribeAll(), ES_RETURN_SUCCESS)
        XCTAssertTrue(subscribedEvents.isEmpty)
    }
    
    func test_subscribeUnsubscribe_esFails() {
        let events = [
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_REMOUNT,
        ]
        XCTAssertEqual(subscriptions.subscribe(events), ES_RETURN_SUCCESS)
        XCTAssertTrue(subscribedEvents.containsUniquely(events))
        
        subscribeFails = true
        XCTAssertEqual(subscriptions.subscribe([ES_EVENT_TYPE_NOTIFY_EXIT]), ES_RETURN_ERROR)
        //  Event is not added to subscriptions
        XCTAssertFalse(subscribedEvents.contains(ES_EVENT_TYPE_NOTIFY_EXIT))
        XCTAssertFalse(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_EXIT))
        
        unsubscribeFails = true
        XCTAssertEqual(subscriptions.unsubscribe([ES_EVENT_TYPE_NOTIFY_MOUNT]), ES_RETURN_ERROR)
        //  Event is not removed from subscriptions
        XCTAssertTrue(subscribedEvents.contains(ES_EVENT_TYPE_NOTIFY_MOUNT))
        XCTAssertTrue(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_MOUNT))
        
        unsubscribeAllFails = true
        XCTAssertEqual(subscriptions.unsubscribeAll(), ES_RETURN_ERROR)
        //  Event is not removed from subscriptions
        XCTAssertTrue(subscribedEvents.containsUniquely(events))
        XCTAssertTrue(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_MOUNT))
        XCTAssertTrue(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_REMOUNT))
    }
}

private extension Array where Element == es_event_type_t {
    func count(of type: es_event_type_t) -> Int {
        filter { $0 == type }.count
    }
    
    func containsUniquely(_ events: [es_event_type_t]) -> Bool {
        for event in events {
            guard count(of: event) == 1 else { return false }
        }
        return true
    }
}
