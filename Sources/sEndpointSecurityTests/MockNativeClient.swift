//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 01.03.2023.
//

import EndpointSecurity
import Foundation
import sEndpointSecurity

class MockNativeClient: ESNativeClient {
    struct MutePathKey: Hashable {
        var path: String
        var type: es_mute_path_type_t
    }
    
    var subscriptions: Set<es_event_type_t> = []
    var invertMuting: [es_mute_inversion_type_t: Bool] = [:]
    var pathMutes: [String: Set<es_event_type_t>] = [:]
    var prefixMutes: [String: Set<es_event_type_t>] = [:]
    var processMutes: [audit_token_t: Set<es_event_type_t>] = [:]
    var responses: [UInt64: ESAuthResolution] = [:]
    
    func esRespond(_ message: UnsafePointer<es_message_t>, flags: UInt32, cache: Bool) -> es_respond_result_t {
        responses[message.pointee.global_seq_num] = ESAuthResolution(result: .flags(flags), cache: cache)
        return ES_RESPOND_RESULT_SUCCESS
    }
    
    func esSubscribe(_ events: [es_event_type_t]) -> es_return_t {
        subscriptions.formUnion(events)
        return ES_RETURN_SUCCESS
    }
    
    func esUnsubscribe(_ events: [es_event_type_t]) -> es_return_t {
        subscriptions.subtract(events)
        return ES_RETURN_SUCCESS
    }
    
    func esUnsubscribeAll() -> es_return_t {
        subscriptions.removeAll()
        return ES_RETURN_SUCCESS
    }
    
    func esClearCache() -> es_clear_cache_result_t {
        return ES_CLEAR_CACHE_RESULT_SUCCESS
    }
    
    func esInvertMuting(_ muteType: es_mute_inversion_type_t) -> es_return_t {
        invertMuting[muteType, default: false].toggle()
        return ES_RETURN_SUCCESS
    }
    
    func esMutingInverted(_ muteType: es_mute_inversion_type_t) -> es_mute_inverted_return_t {
        return invertMuting[muteType, default: false] ? ES_MUTE_INVERTED : ES_MUTE_NOT_INVERTED
    }
    
    func esDeleteClient() -> es_return_t {
        return ES_RETURN_SUCCESS
    }
    
    func esMutePath(_ path: String, _ type: es_mute_path_type_t) -> es_return_t {
        if type == ES_MUTE_PATH_TYPE_LITERAL {
            pathMutes[path, default: []] = ESEventSet.all.events
        } else {
            prefixMutes[path, default: []] = ESEventSet.all.events
        }
        return ES_RETURN_SUCCESS
    }
    
    func esUnmutePath(_ path: String, _ type: es_mute_path_type_t) -> es_return_t {
        if type == ES_MUTE_PATH_TYPE_LITERAL {
            pathMutes.removeValue(forKey: path)
        } else {
            prefixMutes.removeValue(forKey: path)
        }
        return ES_RETURN_SUCCESS
    }
    
    func esMutePathEvents(_ path: String, _ type: es_mute_path_type_t, _ events: [es_event_type_t]) -> es_return_t {
        if type == ES_MUTE_PATH_TYPE_LITERAL {
            pathMutes[path, default: []].formUnion(events)
        } else {
            prefixMutes[path, default: []].formUnion(events)
        }
        return ES_RETURN_SUCCESS
    }
    
    func esUnmutePathEvents(_ path: String, _ type: es_mute_path_type_t, _ events: [es_event_type_t]) -> es_return_t {
        if type == ES_MUTE_PATH_TYPE_LITERAL {
            pathMutes[path, default: []].subtract(events)
        } else {
            prefixMutes[path, default: []].subtract(events)
        }
        return ES_RETURN_SUCCESS
    }
    
    func esUnmuteAllPaths() -> es_return_t {
        pathMutes.removeAll()
        return ES_RETURN_SUCCESS
    }
    
    func esMutedPaths() -> [(path: String, type: es_mute_path_type_t, events: [es_event_type_t])] {
        pathMutes.map { ($0, ES_MUTE_PATH_TYPE_LITERAL, Array($1)) } + prefixMutes.map { ($0, ES_MUTE_PATH_TYPE_PREFIX, Array($1)) }
    }
    
    func esUnmuteAllTargetPaths() -> es_return_t {
        return ES_RETURN_SUCCESS
    }
    
    func esMuteProcess(_ auditToken: audit_token_t) -> es_return_t {
        processMutes[auditToken] = ESEventSet.all.events
        return ES_RETURN_SUCCESS
    }
    
    func esUnmuteProcess(_ auditToken: audit_token_t) -> es_return_t {
        processMutes.removeValue(forKey: auditToken)
        return ES_RETURN_SUCCESS
    }
    
    func esMutedProcesses() -> [audit_token_t]? {
        Array(processMutes.filter { $0.value == ESEventSet.all.events }.keys)
    }
    
    func esMuteProcessEvents(_ auditToken: audit_token_t, _ events: [es_event_type_t]) -> es_return_t {
        processMutes[auditToken, default: []].formUnion(events)
        return ES_RETURN_SUCCESS
    }
    
    func esUnmuteProcessEvents(_ auditToken: audit_token_t, _ events: [es_event_type_t]) -> es_return_t {
        processMutes[auditToken]?.subtract(events)
        return ES_RETURN_SUCCESS
    }
    
    func esMutedProcesses() -> [audit_token_t : [es_event_type_t]] {
        processMutes.mapValues { Array($0) }
    }
}
