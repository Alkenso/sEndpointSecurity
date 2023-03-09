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
    /// Restrictive combine of multiple `ESAuthResolution` values.
    ///
    /// Deny has precedence over allow. Non-cache has precedence over cache.
    public static func combine(_ resolutions: [ESAuthResolution]) -> ESAuthResolution {
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
    public init(events: [es_event_type_t]) {
        self.init(events: Set(events))
    }
}

extension ESEventSet: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: es_event_type_t...) {
        self.init(events: Set(elements))
    }
}

extension ESEventSet {
    public static let empty = ESEventSet(events: [])
    public static let all = ESEventSet(events: (0..<ES_EVENT_TYPE_LAST.rawValue).map(es_event_type_t.init(rawValue:)))
}

extension ESEventSet {
    public func inverted() -> ESEventSet { ESEventSet(events: ESEventSet.all.events.subtracting(events)) }
}

public struct ESInterest: Equatable, Codable {
    public var events: Set<es_event_type_t>
    public internal(set) var nativeMuteIgnored = false
}

extension ESInterest {
    public static func listen(_ events: ESEventSet = .all) -> ESInterest {
        ESInterest(events: events.events)
    }
    
    public static func ignore(_ events: ESEventSet = .all) -> ESInterest {
        ESInterest(events: events.inverted().events)
    }
    
    /// Ignore set of events.
    /// Additionally performs native muting of the path literal / process.
    /// - Warning: muting natively too many paths or processes (200+) may cause performance degradation
    /// because of implementation specifics of `es_client` on some versions of macOS.
    @available(macOS 12.0, *)
    public static func ignore(_ events: ESEventSet, suggestNativeMuting: Bool) -> ESInterest {
        ESInterest(events: events.inverted().events, nativeMuteIgnored: suggestNativeMuting)
    }
}

extension ESInterest {
    public static func combine(_ type: CombineType, _ resolutions: [ESInterest]) -> ESInterest? {
        guard let first = resolutions.first else { return nil }
        guard resolutions.count > 1 else { return first }
        
        let events = resolutions.dropFirst().reduce(into: first.events) {
            switch type {
            case .restrictive: $0.formIntersection($1.events)
            case .permissive: $0.formUnion($1.events)
            }
        }
        let nativeMute = resolutions.map(\.nativeMuteIgnored).reduce(true) { $0 && $1 }
        
        return ESInterest(events: events, nativeMuteIgnored: nativeMute)
    }
    
    public enum CombineType: Equatable, Codable {
        /// Interest in intersection of events in resolutions.
        case restrictive
        
        /// Interest in union of events in resolutions.
        case permissive
    }
}

public enum ESMuteProcessRule: Hashable, Codable {
    case token(audit_token_t)
    case pid(pid_t)
}

public struct ESReturnError: Error {
    public var value: es_return_t
    public var action: String?
    
    public init(_ action: String? = nil, value: es_return_t = ES_RETURN_ERROR) {
        self.value = value
        self.action = action
    }
}
