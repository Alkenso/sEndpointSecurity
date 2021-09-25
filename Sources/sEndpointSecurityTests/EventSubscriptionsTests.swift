@testable import sEndpointSecurity

import EndpointSecurity
import Foundation
import SwiftConvenience
import XCTest
import sMock


class EventSubscribeTests: XCTestCase {
    var subscribedEvents: [es_event_type_t] = []
    var subscribeFails = false
    var unsubscribeFails = false
    
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
        }
    )
    
    override func setUp() {
        subscribedEvents = []
        subscribeFails = false
        unsubscribeFails = false
    }
    
    func test_typicalUseCase() {
        //  mandatory subscribe for events
        let mandatory = [
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_REMOUNT,
            ES_EVENT_TYPE_NOTIFY_UNMOUNT,
        ]
        XCTAssertEqual(subscriptions.subscribeMandatory(mandatory), ES_RETURN_SUCCESS)
        XCTAssertTrue(subscribedEvents.containsUniquely(mandatory))
        //  But as for usual point of view there is no subscriptions
        for event in mandatory {
            XCTAssertFalse(subscriptions.isSubscribed(event))
        }
        
        //  usual subscribe for events
        let usual = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_NOTIFY_REMOUNT, // exists also in 'mandatory'
            ES_EVENT_TYPE_NOTIFY_UNMOUNT, // exists also in 'mandatory'
        ]
        XCTAssertEqual(subscriptions.subscribe(usual), ES_RETURN_SUCCESS)
        XCTAssertTrue(subscribedEvents.containsUniquely(usual))
        for event in usual {
            XCTAssertTrue(subscriptions.isSubscribed(event))
        }
        
        //  usual unsubscribe affects only usual subscriptions
        XCTAssertEqual(subscriptions.unsubscribe([ES_EVENT_TYPE_NOTIFY_REMOUNT]), ES_RETURN_SUCCESS)
        //  but in general event is not unsubscribed (mandatory still holds a subscription)
        XCTAssertTrue(subscribedEvents.contains(ES_EVENT_TYPE_NOTIFY_REMOUNT))
        //  and subscription is not active anymore
        XCTAssertFalse(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_REMOUNT))
        //  when mandatory also unsubscribes, the event is fully unsubscribed
        XCTAssertEqual(subscriptions.unsubscribeMandatory([ES_EVENT_TYPE_NOTIFY_REMOUNT]), ES_RETURN_SUCCESS)
        XCTAssertFalse(subscribedEvents.contains(ES_EVENT_TYPE_NOTIFY_REMOUNT))
        
        //  mandatory unsubscribe affects only mandatory subscriptions
        XCTAssertEqual(subscriptions.unsubscribeMandatory([ES_EVENT_TYPE_NOTIFY_UNMOUNT]), ES_RETURN_SUCCESS)
        //  but in general event is not unsubscribed
        XCTAssertTrue(subscribedEvents.contains(ES_EVENT_TYPE_NOTIFY_UNMOUNT))
        //  and subscription is still active in general (for usual case)
        XCTAssertTrue(subscriptions.isSubscribed(ES_EVENT_TYPE_NOTIFY_UNMOUNT))
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
    
    func test_mandatory_subscribeUnsubscribe() {
        let events = [
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_REMOUNT,
            ES_EVENT_TYPE_NOTIFY_UNMOUNT,
        ]
        XCTAssertEqual(subscriptions.subscribeMandatory(events), ES_RETURN_SUCCESS)
        XCTAssertTrue(subscribedEvents.containsUniquely(events))
        
        XCTAssertEqual(
            subscriptions.unsubscribeMandatory(
                [ES_EVENT_TYPE_NOTIFY_UNMOUNT]
            ),
            ES_RETURN_SUCCESS
        )
        XCTAssertTrue(
            subscribedEvents.containsUniquely(
                [ES_EVENT_TYPE_NOTIFY_MOUNT, ES_EVENT_TYPE_NOTIFY_REMOUNT]
            )
        )
        
        XCTAssertEqual(subscriptions.unsubscribeMandatoryAll(), ES_RETURN_SUCCESS)
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
    }
    
    func test_mandatory_subscribeUnsubscribe_esFails() {
        let events = [
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_REMOUNT,
        ]
        XCTAssertEqual(subscriptions.subscribeMandatory(events), ES_RETURN_SUCCESS)
        XCTAssertTrue(subscribedEvents.containsUniquely(events))
        
        subscribeFails = true
        XCTAssertEqual(subscriptions.subscribeMandatory([ES_EVENT_TYPE_NOTIFY_EXIT]), ES_RETURN_ERROR)
        //  Event is not added to subscriptions
        XCTAssertFalse(subscribedEvents.contains(ES_EVENT_TYPE_NOTIFY_EXIT))
        
        unsubscribeFails = true
        XCTAssertEqual(subscriptions.unsubscribeMandatory([ES_EVENT_TYPE_NOTIFY_MOUNT]), ES_RETURN_ERROR)
        //  Event is not removed from subscriptions
        XCTAssertTrue(subscribedEvents.contains(ES_EVENT_TYPE_NOTIFY_MOUNT))
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
