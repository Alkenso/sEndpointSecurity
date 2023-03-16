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

internal final class ESMutePath {
    private let client: ESNativeClient
    private let useAPIv12: Bool
    
    private var cache: [String: CacheEntry] = [:]
    private var pathMutes: [MutePathKey: Set<es_event_type_t>] = [:]
    private var pathMutesInverted = false
    private var lock = os_unfair_lock_s()
    
    init(client: ESNativeClient, useAPIv12: Bool = true) {
        self.client = client
        self.useAPIv12 = useAPIv12
    }
    
    // MARK: Ignore
    
    var interestHandler: (ESProcess) -> ESInterest = { _ in .listen() }
    
    func checkIgnored(_ event: es_event_type_t, path: String, process: @autoclosure () -> ESProcess) -> Bool {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        let entry = findEntry(path: path, interest: nil)
        guard entry.muted.contains(event) == pathMutesInverted else { return true }
        
        if let ignored = entry.ignored {
            return ignored.contains(event)
        }
        
        os_unfair_lock_unlock(&lock)
        let interest = interestHandler(process())
        os_unfair_lock_lock(&lock)
        
        return findEntry(path: path, interest: interest).ignored?.contains(event) == true
    }
    
    private func findEntry(path: String, interest: ESInterest?) -> CacheEntry {
        let entry: CacheEntry
        if let cached = cache[path] {
            entry = cached
        } else {
            entry = CacheEntry(muted: mutedEventsByRule(path: path))
            cache[path] = entry
        }
        
        if let interest {
            entry.ignored = ESEventSet(events: interest.events).inverted().events
            entry.muteIgnoredNatively = interest.suggestNativeMuting
            updateMutedIgnores(entry, path: path, mute: true)
        }
        
        return entry
    }
    
    /// May be called from:
    /// - `findEntry` on event check
    /// - `clearIgnoreCache`
    /// - `invertMuting`
    private func updateMutedIgnores(_ entry: CacheEntry, path: String, mute: Bool) {
        guard entry.muteIgnoredNatively else { return }
        guard #available(macOS 12.0, *), useAPIv12 else { return }
        
        if !mute {
            let unmute = (entry.ignored ?? []).subtracting(entry.muted)
            nativeUnmute(path, type: ES_MUTE_PATH_TYPE_LITERAL, events: unmute)
        } else if !pathMutesInverted, let ignored = entry.ignored, !ignored.isEmpty {
            muteNative(path, type: ES_MUTE_PATH_TYPE_LITERAL, events: ignored)
        }
    }
    
    func clearIgnoreCache() {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        for (path, entry) in cache {
            updateMutedIgnores(entry, path: path, mute: false)
            entry.ignored = nil
        }
    }
    
    // MARK: Mute
    
    func mute(_ path: String, type: es_mute_path_type_t, events: Set<es_event_type_t>) {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        let key = MutePathKey(pattern: path, type: type)
        pathMutes[key, default: []].formUnion(events)
        muteNative(path, type: type, events: events)
        
        for (entryPath, entry) in cache {
            guard key.match(path: entryPath) else { continue }
            entry.muted = mutedEventsByRule(path: entryPath)
        }
    }
    
    @available(macOS 12.0, *)
    func unmute(_ path: String, type: es_mute_path_type_t, events: Set<es_event_type_t>) {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        let key = MutePathKey(pattern: path, type: type)
        pathMutes[key]?.subtract(events)
        
        var events = events
        if type == ES_MUTE_PATH_TYPE_LITERAL, !pathMutesInverted, let entry = cache[path], entry.muteIgnoredNatively {
            events.subtract(entry.ignored ?? [])
        }
        nativeUnmute(path, type: type, events: events)
        
        for (entryPath, entry) in cache {
            guard key.match(path: entryPath) else { continue }
            entry.muted = mutedEventsByRule(path: entryPath)
        }
    }
    
    func unmuteAll() -> Bool {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        guard client.esUnmuteAllPaths() == ES_RETURN_SUCCESS else { return false }
        cache.removeAll()
        pathMutes.removeAll()
        return true
    }
    
    private func mutedEventsByRule(path: String) -> Set<es_event_type_t> {
        pathMutes
            .filter { $0.key.match(path: path) }
            .reduce(into: Set()) { $0.formUnion($1.value) }
    }
    
    // MARK: Mute - Native
    
    private func muteNative(_ path: String, type: es_mute_path_type_t, events: Set<es_event_type_t>) {
        if useAPIv12, #available(macOS 12.0, *) {
            if client.esMutePathEvents(path, type, Array(events)) != ES_RETURN_SUCCESS {
                log.warning("Failed to mute path events: type = \(type), path = \(path)")
            }
        } else if events == ESEventSet.all.events {
            if client.esMutePath(path, type) != ES_RETURN_SUCCESS {
                log.warning("Failed to mute path: type = \(type), path = \(path)")
            }
        }
    }
    
    @available(macOS 12.0, *)
    private func nativeUnmute(_ path: String, type: es_mute_path_type_t, events: Set<es_event_type_t>) {
        guard useAPIv12 else { return }
        
        if client.esUnmutePathEvents(path, type, Array(events)) != ES_RETURN_SUCCESS {
            log.warning("Failed to unmute path events: type = \(type), path = \(path)")
        }
    }
    
    // MARK: Other
    
    @available(macOS 13.0, *)
    func invertMuting() -> Bool {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        guard client.esInvertMuting(ES_MUTE_INVERSION_TYPE_PATH) == ES_RETURN_SUCCESS else { return false }
        
        pathMutesInverted.toggle()
        cache.forEach { path, entry in
            guard entry.muteIgnoredNatively else { return }
            updateMutedIgnores(entry, path: path, mute: !pathMutesInverted)
        }
        
        return true
    }
}

extension ESMutePath {
    private class CacheEntry {
        var muted: Set<es_event_type_t>
        var ignored: Set<es_event_type_t>?
        var muteIgnoredNatively = false
        
        init(muted: Set<es_event_type_t>) {
            self.muted = muted
        }
    }
    
    private struct MutePathKey: Hashable {
        var pattern: String
        var type: es_mute_path_type_t
        
        func match(path: String) -> Bool {
            switch type {
            case ES_MUTE_PATH_TYPE_LITERAL: return path == pattern
            case ES_MUTE_PATH_TYPE_PREFIX: return path.starts(with: pattern)
            default: return false
            }
        }
    }
}
