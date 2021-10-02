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

import EndpointSecurity
import Foundation
import SwiftConvenience


class EventSubscriptions {
    private let _esSubscribe: ([es_event_type_t]) -> es_return_t
    private let _esUnsubscribe: ([es_event_type_t]) -> es_return_t
    private let _esUnsubscribeAll: () -> es_return_t
    
    private let _queue = DispatchQueue(label: "EventSubscribe.queue")
    private var _events: Set<es_event_type_t> = []
    
    var mandatoryEvents: [es_event_type_t] = []
    
    init(
        esSubscribe: @escaping ([es_event_type_t]) -> es_return_t,
        esUnsubscribe: @escaping ([es_event_type_t]) -> es_return_t,
        esUnsubscribeAll: @escaping () -> es_return_t
    ) {
        _esSubscribe = esSubscribe
        _esUnsubscribe = esUnsubscribe
        _esUnsubscribeAll = esUnsubscribeAll
    }
    
    
    // MARK: Usual
    
    func isSubscribed(_ event: es_event_type_t) -> Bool {
        _queue.sync { _events.contains(event) }
    }
    
    func subscribe(_ events: [es_event_type_t]) -> es_return_t {
        _queue.sync {
            let subscribedEvents = Set(events)
                .subtracting(_events)
                .union(_events.isEmpty ? mandatoryEvents : [])
            let result = _esSubscribe(Array(subscribedEvents))
            if result == ES_RETURN_SUCCESS {
                _events.formUnion(events)
            }
            return result
        }
    }
    
    func unsubscribe(_ events: [es_event_type_t]) -> es_return_t {
        _queue.sync {
            let unsubscribedEvents = _events.intersection(Set(events))
            guard _events != unsubscribedEvents else {
                return unsubscribeAllInternal()
            }
            
            let result = _esUnsubscribe(Array(unsubscribedEvents.subtracting(mandatoryEvents)))
            if result == ES_RETURN_SUCCESS {
                _events.subtract(unsubscribedEvents)
            }
            return result
        }
    }
    
    func unsubscribeAll() -> es_return_t {
        _queue.sync(execute: unsubscribeAllInternal)
    }
    
    
    private func unsubscribeAllInternal() -> es_return_t {
        let result = _esUnsubscribeAll()
        if result == ES_RETURN_SUCCESS {
            _events.removeAll()
        }
        return result
    }
}

extension EventSubscriptions {
    convenience init(esClient: OpaquePointer) {
        self.init(
            esSubscribe: esClient.esSubscribe,
            esUnsubscribe: esClient.esUnsubscribe,
            esUnsubscribeAll: { es_unsubscribe_all(esClient) }
        )
    }
}
