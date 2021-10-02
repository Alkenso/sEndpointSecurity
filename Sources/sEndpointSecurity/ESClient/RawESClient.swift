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
        guard message.pointee.action_type == ES_ACTION_TYPE_AUTH else {
            return ES_RESPOND_RESULT_SUCCESS
        }
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
