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

import EndpointSecurity

public protocol ESNativeClient {
    func esRespond(_ message: UnsafePointer<es_message_t>, flags: UInt32, cache: Bool) -> es_respond_result_t
    
    func esSubscribe(_ events: [es_event_type_t]) -> es_return_t
    func esUnsubscribe(_ events: [es_event_type_t]) -> es_return_t
    func esUnsubscribeAll() -> es_return_t
    
    func esClearCache() -> es_clear_cache_result_t
    func esDeleteClient() -> es_return_t
    
    @available(macOS 13.0, *)
    func esInvertMuting(_ muteType: es_mute_inversion_type_t) -> es_return_t
    
    @available(macOS 13.0, *)
    func esMutingInverted(_ muteType: es_mute_inversion_type_t) -> es_mute_inverted_return_t
    
    // MARK: Mute by Process
    
    func esMuteProcess(_ auditToken: audit_token_t) -> es_return_t
    func esUnmuteProcess(_ auditToken: audit_token_t) -> es_return_t
    
    @available(macOS 12.0, *)
    func esMuteProcessEvents(_ auditToken: audit_token_t, _ events: [es_event_type_t]) -> es_return_t
    
    @available(macOS 12.0, *)
    func esUnmuteProcessEvents(_ auditToken: audit_token_t, _ events: [es_event_type_t]) -> es_return_t
    
    func esMutedProcesses() -> [audit_token_t: [es_event_type_t]]
    
    // MARK: Mute by Path
    
    func esMutePath(_ path: String, _ type: es_mute_path_type_t) -> es_return_t
    
    @available(macOS 12.0, *)
    func esUnmutePath(_ path: String, _ type: es_mute_path_type_t) -> es_return_t
    
    @available(macOS 12.0, *)
    func esMutePathEvents(_ path: String, _ type: es_mute_path_type_t, _ events: [es_event_type_t]) -> es_return_t
    
    @available(macOS 12.0, *)
    func esUnmutePathEvents(_ path: String, _ type: es_mute_path_type_t, _ events: [es_event_type_t]) -> es_return_t
    
    func esUnmuteAllPaths() -> es_return_t
    
    @available(macOS 13.0, *)
    func esUnmuteAllTargetPaths() -> es_return_t
    
    @available(macOS 12.0, *)
    func esMutedPaths() -> [(path: String, type: es_mute_path_type_t, events: [es_event_type_t])]
}

extension OpaquePointer: ESNativeClient {
    public func esRespond(_ message: UnsafePointer<es_message_t>, flags: UInt32, cache: Bool) -> es_respond_result_t {
        switch message.pointee.event_type {
        // flags requests
        case ES_EVENT_TYPE_AUTH_OPEN:
            return es_respond_flags_result(self, message, flags, cache)
            
        // rest are auth requests
        default:
            return es_respond_auth_result(self, message, flags > 0 ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, cache)
        }
    }
    
    public func esSubscribe(_ events: [es_event_type_t]) -> es_return_t {
        withRawValues(events) { es_subscribe(self, $0, $1) }
    }
    
    public func esUnsubscribe(_ events: [es_event_type_t]) -> es_return_t {
        withRawValues(events) { es_unsubscribe(self, $0, $1) }
    }
    
    public func esClearCache() -> es_clear_cache_result_t {
        es_clear_cache(self)
    }
    
    public func esDeleteClient() -> es_return_t {
        es_delete_client(self)
    }
    
    @available(macOS 13.0, *)
    public func esInvertMuting(_ muteType: es_mute_inversion_type_t) -> es_return_t {
        es_invert_muting(self, muteType)
    }
    
    @available(macOS 13.0, *)
    public func esMutingInverted(_ muteType: es_mute_inversion_type_t) -> es_mute_inverted_return_t {
        es_muting_inverted(self, muteType)
    }
    
    public func esUnsubscribeAll() -> es_return_t {
        es_unsubscribe_all(self)
    }
    
    public func esMuteProcess(_ auditToken: audit_token_t) -> es_return_t {
        withUnsafePointer(to: auditToken) { es_mute_process(self, $0) }
    }
    
    public func esUnmuteProcess(_ auditToken: audit_token_t) -> es_return_t {
        withUnsafePointer(to: auditToken) { es_unmute_process(self, $0) }
    }
    
    @available(macOS 12.0, *)
    public func esMuteProcessEvents(_ auditToken: audit_token_t, _ events: [es_event_type_t]) -> es_return_t {
        withRawValues(events) { eventsPtr, eventsCount in
            withUnsafePointer(to: auditToken) { es_mute_process_events(self, $0, eventsPtr, eventsCount) }
        }
    }
    
    @available(macOS 12.0, *)
    public func esUnmuteProcessEvents(_ auditToken: audit_token_t, _ events: [es_event_type_t]) -> es_return_t {
        withRawValues(events) { eventsPtr, eventsCount in
            withUnsafePointer(to: auditToken) { es_unmute_process_events(self, $0, eventsPtr, eventsCount) }
        }
    }
    
    public func esMutedProcesses() -> [audit_token_t: [es_event_type_t]] {
        if #available(macOS 12.0, *) {
            var processes: UnsafeMutablePointer<es_muted_processes_t>!
            guard es_muted_processes_events(self, &processes) == ES_RETURN_SUCCESS else { return [:] }
            defer { es_release_muted_processes(processes) }
            return Array(UnsafeBufferPointer(start: processes.pointee.processes, count: processes.pointee.count))
                .reduce(into: [:]) {
                    $0[$1.audit_token] = Array(UnsafeBufferPointer(start: $1.events, count: $1.event_count))
                }
        } else {
            var count: Int = 0
            var tokens: UnsafeMutablePointer<audit_token_t>!
            guard es_muted_processes(self, &count, &tokens) == ES_RETURN_SUCCESS else { return [:] }
            defer { tokens.deallocate() }
            return Array(UnsafeBufferPointer(start: tokens, count: count))
                .reduce(into: [:]) { $0[$1] = Array(ESEventSet.all.events) }
        }
    }
    
    public func esMutePath(_ path: String, _ type: es_mute_path_type_t) -> es_return_t {
        guard #unavailable(macOS 12.0) else {
            return es_mute_path(self, path, type)
        }
        
        switch type {
        case ES_MUTE_PATH_TYPE_PREFIX:
            return es_mute_path_prefix(self, path)
        case ES_MUTE_PATH_TYPE_LITERAL:
            return es_mute_path_literal(self, path)
        default:
            return ES_RETURN_ERROR
        }
    }
    
    public func esUnmuteAllPaths() -> es_return_t {
        es_unmute_all_paths(self)
    }
    
    @available(macOS 12.0, *)
    public func esUnmutePath(_ path: String, _ type: es_mute_path_type_t) -> es_return_t {
        es_unmute_path(self, path, type)
    }
    
    @available(macOS 12.0, *)
    public func esMutePathEvents(_ path: String, _ type: es_mute_path_type_t, _ events: [es_event_type_t]) -> es_return_t {
        withRawValues(events) {
            es_mute_path_events(self, path, type, $0, $1)
        }
    }
    
    @available(macOS 12.0, *)
    public func esUnmutePathEvents(_ path: String, _ type: es_mute_path_type_t, _ events: [es_event_type_t]) -> es_return_t {
        withRawValues(events) {
            es_unmute_path_events(self, path, type, $0, $1)
        }
    }
    
    @available(macOS 13.0, *)
    public func esUnmuteAllTargetPaths() -> es_return_t {
        es_unmute_all_target_paths(self)
    }
    
    @available(macOS 12.0, *)
    public func esMutedPaths() -> [(path: String, type: es_mute_path_type_t, events: [es_event_type_t])] {
        var paths: UnsafeMutablePointer<es_muted_paths_t>!
        guard es_muted_paths_events(self, &paths) == ES_RETURN_SUCCESS else { return [] }
        defer { es_release_muted_paths(paths) }
        
        return Array(UnsafeBufferPointer(start: paths.pointee.paths, count: paths.pointee.count))
            .map {
                let events = Array(UnsafeBufferPointer(start: $0.events, count: $0.event_count))
                let path = $0.path.length > 0 ? String(cString: $0.path.data) : ""
                return (path, $0.type, events)
            }
    }
    
    private func withRawValues<T, Count: BinaryInteger>(_ values: [T], body: (UnsafePointer<T>, Count) -> es_return_t) -> es_return_t {
        values.withUnsafeBufferPointer { buffer in
            if let ptr = buffer.baseAddress, !buffer.isEmpty {
                return body(ptr, Count(buffer.count))
            } else {
                return ES_RETURN_SUCCESS
            }
        }
    }
}
