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
import Foundation
import SwiftConvenience

private let log = SCLogger.internalLog(.client)

public struct ESAuthResolution: Equatable, Codable {
    public var result: ESAuthResult
    public var cache: Bool
    
    public init(result: ESAuthResult, cache: Bool) {
        self.result = result
        self.cache = cache
    }
}

extension ESAuthResolution {
    public static let allow = ESAuthResolution(result: .auth(true), cache: true)
    public static let allowOnce = ESAuthResolution(result: .auth(true), cache: false)
    public static let deny = ESAuthResolution(result: .auth(false), cache: true)
    public static let denyOnce = ESAuthResolution(result: .auth(false), cache: false)
}

public struct ESClientCreateError: Error, Codable {
    public var status: es_new_client_result_t
}

extension ESAuthResolution {
    static func combine(_ resolutions: [ESAuthResolution]) -> ESAuthResolution {
        guard let first = resolutions.first else { return .allowOnce }
        guard resolutions.count > 1 else { return first }
        
        let flags = resolutions.map(\.result.rawValue).reduce(UInt32.max) { $0 & $1 }
        let cache = resolutions.map(\.cache).reduce(true) { $0 && $1 }
        
        return ESAuthResolution(result: .flags(flags), cache: cache)
    }
}

public struct ESEventSet: Equatable, Codable {
    public var events: Set<es_event_type_t>
}

extension ESEventSet {
    public static let empty = ESEventSet(events: [])
    public static let all = ESEventSet(events: (0..<ES_EVENT_TYPE_LAST.rawValue).map(es_event_type_t.init(rawValue:)))
}

extension ESEventSet {
    public func reverted() -> ESEventSet { ESEventSet(events: ESEventSet.all.events.subtracting(events)) }
}

extension ESEventSet: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: es_event_type_t...) {
        self.events = Set(elements)
    }
    
    public init(events: [es_event_type_t]) {
        self.init(events: Set(events))
    }
}

public struct ESMuteResolution: Equatable, Codable {
    public var muteEvents: ESEventSet
    public var mutePath: Bool
}

extension ESMuteResolution {
    /// Do NOT mute process events. Events are NOT muted only for current instance of related process.
    public static let allowThis = ESMuteResolution(muteEvents: .empty, mutePath: false)
    
    /// Do NOT mute process events. Events are NOT muted for all instances of related process.
    public static let allowAll = ESMuteResolution(muteEvents: .empty, mutePath: true)
    
    /// Mute set of events. Events ARE muted only for current instance of related process.
    public static func muteThis(_ events: ESEventSet) -> ESMuteResolution { .init(muteEvents: events, mutePath: false) }
    
    /// Mute set of events. Events ARE muted for all instances of related process.
    public static func muteAll(_ events: ESEventSet) -> ESMuteResolution { .init(muteEvents: events, mutePath: true) }
}

extension ESMuteResolution {
    internal var mutePathEvents: ESEventSet {
        mutePath ? muteEvents : .empty
    }
    
    internal var muteProcessEvents: ESEventSet {
        mutePath ? .empty : muteEvents
    }
}

public enum ESMutePathType: Hashable, Codable {
    case prefix
    case literal
}

extension ESMutePathType {
    public var process: es_mute_path_type_t {
        switch self {
        case .prefix: return ES_MUTE_PATH_TYPE_PREFIX
        case .literal: return ES_MUTE_PATH_TYPE_LITERAL
        }
    }
    
    public var targetPath: es_mute_path_type_t {
        switch self {
        case .prefix: return ES_MUTE_PATH_TYPE_TARGET_PREFIX
        case .literal: return ES_MUTE_PATH_TYPE_TARGET_LITERAL
        }
    }
}

public struct ESReturnError: Error {
    public var value: es_return_t
    public var action: String?
    
    public init(_ action: String? = nil, value: es_return_t = ES_RETURN_ERROR) {
        self.value = value
        self.action = action
    }
}
