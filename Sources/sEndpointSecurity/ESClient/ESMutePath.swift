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

import Foundation
import EndpointSecurity
import SwiftConvenience

private let log = SCLogger.internalLog(.client)

public enum ESMutePathRule: Hashable, Codable {
    case path(String, ESMutePathType)
    case name(String, ESMutePathType)
    
    //  Codesign Team Identifier (DEVELOPMENT_TEAM in Xcode)
    case teamIdentifier(String)
    
    //  Usually equals to application bundle identifier
    case signingID(String)
}

internal class ESMutePath {
    private let client: ESNativeClient
    private let useAPIv12: Bool
    private var muteRules: [ESMutePathRule: ESEventSet] = [:]
    private var cache: [String: ESEventSet] = [:]
    private var cacheLock = os_unfair_lock_s()
    
    init(client: ESNativeClient, useAPIv12: Bool = true) {
        self.client = client
        self.useAPIv12 = useAPIv12
    }
    
    // MARK: Mute check
    
    func checkMutedByCache(_ path: String, event: es_event_type_t) -> Bool? {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        if let mutedEvents = cache[path] {
            return mutedEvents.events.contains(event)
        } else {
            return nil
        }
    }
    
    func checkMuted(_ process: ESProcess, event: es_event_type_t, additionalyMuted: ESEventSet?) -> Bool {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        let path = process.executable.path
        if let mutedEvents = cache[path] {
            return mutedEvents.events.contains(event)
        }
        
        let mutedEvents = muteRules
            .filter { $0.key.matches(process: process) }
            .reduce(into: Set()) { $0.formUnion($1.value.events) }
            .union(additionalyMuted?.events ?? [])
        if additionalyMuted != nil {
            if !mutedEvents.isEmpty {
                muteNative(.path(path, .literal), events: ESEventSet(events: mutedEvents))
            }
            cache[path] = ESEventSet(events: mutedEvents)
        }
        
        return mutedEvents.contains(event)
    }
    
    // MARK: Mute management
    
    func clearAdditionalMutes() {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        invalidateCache()
    }
    
    func mute(_ mute: ESMutePathRule, events: ESEventSet) {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        muteRules[mute, default: []].events.formUnion(events.events)
        muteNative(mute, events: events)
        
        if useAPIv12 {
            invalidateCache()
        } else {
            invalidateCache(nativeUnmute: false)
        }
    }
    
    func unmute(_ mute: ESMutePathRule, events: ESEventSet) {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        if let muteRule = muteRules[mute] {
            let newMutedEvents = muteRule.events.subtracting(events.events)
            if newMutedEvents.isEmpty {
                muteRules.removeValue(forKey: mute)
            } else {
                muteRules[mute] = ESEventSet(events: newMutedEvents)
            }
        }
        if useAPIv12 {
            unmuteNative(mute, events: events)
        }
        
        invalidateCache()
    }
    
    func unmuteAll() {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        muteRules.removeAll()
        cache.removeAll()
        if client.esUnmuteAllPaths() != ES_RETURN_SUCCESS {
            log.warning("Failed to unmute all paths")
        }
    }
    
    private func invalidateCache(nativeUnmute: Bool = true) {
        guard !cache.isEmpty else { return }
        
        var unmute: [String: ESEventSet] = [:]
        for (mutedPath, cacheEvents) in cache {
            let ruleEvents = muteRules[.path(mutedPath, .literal)]
            let coveredByRule = ruleEvents?.events.isSuperset(of: cacheEvents.events) == true
            if !coveredByRule {
                cache.removeValue(forKey: mutedPath)
                unmute[mutedPath] = cacheEvents
            }
        }
        
        guard nativeUnmute else { return }
        
        if useAPIv12 {
            unmute.forEach { unmuteNative(.path($0.key, .literal), events: $0.value) }
            return
        }
        
        guard client.esUnmuteAllPaths() == ES_RETURN_SUCCESS else {
            log.warning("Failed to unmute all paths")
            return
        }
        muteRules.forEach { muteNative($0.key, events: $0.value) }
        cache.forEach { muteNative(.path($0.key, .literal), events: $0.value) }
    }
    
    private func muteNative(_ mute: ESMutePathRule, events: ESEventSet) {
        switch mute {
        case .path(let path, let type):
            if useAPIv12, #available(macOS 12.0, *) {
                if client.esMutePathEvents(path, type.process, Array(events.events)) != ES_RETURN_SUCCESS {
                    log.warning("Failed to mute path events: type = \(type), path = \(path)")
                }
            } else if events == .all {
                if client.esMutePath(path, type.process) != ES_RETURN_SUCCESS {
                    log.warning("Failed to mute path: type = \(type), path = \(path)")
                }
            }
        case .name, .teamIdentifier, .signingID:
            break
        }
    }
    
    private func unmuteNative(_ mute: ESMutePathRule, events: ESEventSet) {
        guard #available(macOS 12.0, *) else { return }
        
        switch mute {
        case .path(let path, let type):
            if client.esUnmutePathEvents(path, type.process, Array(events.events)) != ES_RETURN_SUCCESS {
                log.warning("Failed to unmute path events: type = \(type), path = \(path)")
            }
        case .name, .teamIdentifier, .signingID:
            break
        }
    }
}

extension ESMutePathRule {
    func matches(process: ESProcess) -> Bool {
        switch self {
        case .path(let path, let type):
            return type.match(string: process.executable.path, pattern: path)
        case .name(let name, let type):
            return type.match(string: process.name, pattern: name)
        case .teamIdentifier(let value):
            return process.teamID == value
        case .signingID(let value):
            return process.signingID == value
        }
    }
}

extension ESMutePathType {
    fileprivate func match(string: String, pattern: String) -> Bool {
        switch self {
        case .prefix:
            return string.hasPrefix(pattern)
        case .literal:
            return string == pattern
        }
    }
}
