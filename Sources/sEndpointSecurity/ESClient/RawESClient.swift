//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 24.09.2021.
//

import EndpointSecurity


extension OpaquePointer {
    func esResolve(_ message: UnsafePointer<es_message_t>, flags: UInt32, cache: Bool) -> es_respond_result_t {
        switch message.pointee.event_type {
            // flags requests
        case ES_EVENT_TYPE_AUTH_OPEN:
            return es_respond_flags_result(self, message, flags, cache)
            // rest are auth requests
        default:
            return es_respond_auth_result(self, message, flags > 0 ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, cache)
        }
    }
    
    func esFallback(_ message: UnsafePointer<es_message_t>) -> es_respond_result_t {
        guard message.pointee.action_type == ES_ACTION_TYPE_AUTH else { return ES_RESPOND_RESULT_SUCCESS }
        return esResolve(message, flags: .max, cache: false)
    }
    
    func esSubscribe(_ events: [es_event_type_t]) -> es_return_t {
        withRawValues(events) { es_subscribe(self, $0, $1) }
    }
    
    func esUnsubscribe(_ events: [es_event_type_t]) -> es_return_t {
        withRawValues(events) { es_unsubscribe(self, $0, $1) }
    }
    
    private func withRawValues<T>(_ values: [T], body: (UnsafePointer<T>, UInt32) -> es_return_t) -> es_return_t {
        values.withUnsafeBufferPointer { buffer in
            if let ptr = buffer.baseAddress, !buffer.isEmpty {
                return body(ptr, UInt32(buffer.count))
            } else {
                return ES_RETURN_SUCCESS
            }
        }
    }
}
