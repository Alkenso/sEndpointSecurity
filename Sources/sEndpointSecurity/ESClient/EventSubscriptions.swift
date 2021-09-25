import EndpointSecurity
import Foundation
import SwiftConvenience


class EventSubscriptions {
    private let _esSubscribe: ([es_event_type_t]) -> es_return_t
    private let _esUnsubscribe: ([es_event_type_t]) -> es_return_t
    
    private let _queue = DispatchQueue(label: "EventSubscribe.queue")
    private var _mandatoryEvents: Set<UInt32> = []
    private var _events: Set<UInt32> = []
    
    
    init(
        esSubscribe: @escaping ([es_event_type_t]) -> es_return_t,
        esUnsubscribe: @escaping ([es_event_type_t]) -> es_return_t
    ) {
        _esSubscribe = esSubscribe
        _esUnsubscribe = esUnsubscribe
    }
    
    
    // MARK: Mandatory
    
    func subscribeMandatory(_ events: [es_event_type_t]) -> es_return_t {
        subscribe(events, existing: &_mandatoryEvents, exclude: _events)
    }
    
    func unsubscribeMandatory(_ events: [es_event_type_t]) -> es_return_t {
        unsubscribe(events, existing: &_mandatoryEvents, exclude: _events)
    }
    
    func unsubscribeMandatoryAll() -> es_return_t {
        unsubscribe(nil, existing: &_mandatoryEvents, exclude: _events)
    }
    
    
    // MARK: Usual
    
    func isSubscribed(_ event: es_event_type_t) -> Bool {
        _queue.sync { _events.contains(event.rawValue) }
    }
    
    func subscribe(_ events: [es_event_type_t]) -> es_return_t {
        subscribe(events, existing: &_events, exclude: _mandatoryEvents)
    }
    
    func unsubscribe(_ events: [es_event_type_t]) -> es_return_t {
        unsubscribe(events, existing: &_events, exclude: _mandatoryEvents)
    }
    
    func unsubscribeAll() -> es_return_t {
        unsubscribe(nil, existing: &_events, exclude: _mandatoryEvents)
    }
    
    
    // MARK: Private
    
    private func subscribe(_ events: [es_event_type_t], existing: inout Set<UInt32>, exclude: Set<UInt32>) -> es_return_t {
        _queue.sync {
            let rawEvents = Set(events.map(\.rawValue))
            let subscribedEvents = rawEvents
                .subtracting(existing)
                .subtracting(exclude)
            let result = _esSubscribe(subscribedEvents.map(es_event_type_t.init(rawValue:)))
            if result == ES_RETURN_SUCCESS {
                existing.formUnion(rawEvents)
            }
            return result
        }
    }
    
    private func unsubscribe(_ events: [es_event_type_t]?, existing: inout Set<UInt32>, exclude: Set<UInt32>) -> es_return_t {
        _queue.sync {
            let rawEvents = events.flatMap { Set($0.map(\.rawValue)) } ?? existing
            let unsubscribedEvents = rawEvents
                .intersection(existing)
                .subtracting(exclude)
            let result = _esUnsubscribe(unsubscribedEvents.map(es_event_type_t.init(rawValue:)))
            if result == ES_RETURN_SUCCESS {
                existing.subtract(rawEvents)
            }
            return result
        }
    }
}

extension EventSubscriptions {
    convenience init(esClient: OpaquePointer) {
        self.init(esSubscribe: esClient.esSubscribe, esUnsubscribe: esClient.esUnsubscribe)
    }
}
