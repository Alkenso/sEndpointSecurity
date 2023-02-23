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

public enum ESMuteProcessRule: Hashable, Codable {
    case token(audit_token_t)
    case pid(pid_t)
}

internal class ESMuteProcess {
    private let client: ESNativeClient
    private let cleanupDelay: TimeInterval
    private let environment: Environment
    private var muteRules: [audit_token_t: ESEventSet] = [:]
    private var cache: [audit_token_t: ESEventSet] = [:]
    private var cacheLock = os_unfair_lock_s()
    
    
    init(client: ESNativeClient, cleanupDelay: TimeInterval = 60.0, environment: Environment = .init()) {
        self.client = client
        self.cleanupDelay = cleanupDelay
        self.environment = environment
        
        scheduleCleanupUndead()
    }
    
    private func scheduleCleanupUndead() {
        DispatchQueue.global().asyncAfter(deadline: .now() + cleanupDelay) { [weak self] in
            guard let self = self else { return }
            self.cleanupUndead()
            self.scheduleCleanupUndead()
        }
    }
    
    private func cleanupUndead() {
        let tokens: Set<audit_token_t>
        os_unfair_lock_lock(&cacheLock)
        tokens = Set(cache.keys).union(muteRules.keys)
        os_unfair_lock_unlock(&cacheLock)
        
        let tokensToRemove = tokens.filter { !environment.checkAlive($0) }
        os_unfair_lock_lock(&cacheLock)
        tokensToRemove.forEach {
            cache.removeValue(forKey: $0)
            muteRules.removeValue(forKey: $0)
        }
        os_unfair_lock_unlock(&cacheLock)
    }
    
    // MARK: Mute check
    
    func checkMutedByCache(_ token: audit_token_t, event: es_event_type_t) -> Bool? {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        if let mutedEvents = cache[token] {
            return mutedEvents.events.contains(event)
        } else {
            return nil
        }
    }
    
    func checkMuted(_ process: ESProcess, event: es_event_type_t, additionalyMuted: ESEventSet?) -> Bool {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        if let mutedEvents = cache[process.auditToken] {
            return mutedEvents.events.contains(event)
        }
        
        let mutedEvents = (muteRules[process.auditToken]?.events ?? []).union(additionalyMuted?.events ?? [])
        if additionalyMuted != nil {
            if !mutedEvents.isEmpty {
                muteNative(process.auditToken, events: ESEventSet(events: mutedEvents))
            }
            cache[process.auditToken] = ESEventSet(events: mutedEvents)
        }
        
        return mutedEvents.contains(event)
    }
    
    // MARK: Mute management
    
    func clearAdditionalMutes() {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        var unmute: [audit_token_t: ESEventSet] = [:]
        for (token, cacheEvents) in cache {
            guard let ruleEvents = muteRules[token] else {
                cache.removeValue(forKey: token)
                unmute[token] = cacheEvents
                continue
            }
            
            let unmuteEvents = cacheEvents.events.subtracting(ruleEvents.events)
            if !unmuteEvents.isEmpty {
                cache[token] = ruleEvents
                unmute[token] = ESEventSet(events: unmuteEvents)
            }
        }
        
        unmute.forEach { unmuteNative($0.key, events: $0.value) }
    }
    
    func mute(_ token: audit_token_t, events: ESEventSet) {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        muteRules[token, default: []].events.formUnion(events.events)
        muteNative(token, events: events)
        cache.removeValue(forKey: token)
    }
    
    func unmute(_ token: audit_token_t, events: ESEventSet) {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        unmute(token, events: events, keyPath: \.muteRules)
        unmute(token, events: events, keyPath: \.cache)
        
        unmuteNative(token, events: events)
    }
    
    private func unmute(_ token: audit_token_t, events: ESEventSet, keyPath: ReferenceWritableKeyPath<ESMuteProcess, [audit_token_t: ESEventSet]>) {
        guard let muteRule = self[keyPath: keyPath][token] else { return }
        
        let newMutedEvents = muteRule.events.subtracting(events.events)
        if newMutedEvents.isEmpty {
            self[keyPath: keyPath].removeValue(forKey: token)
        } else {
            self[keyPath: keyPath][token] = ESEventSet(events: newMutedEvents)
        }
    }
    
    func unmuteAll() {
        os_unfair_lock_lock(&cacheLock)
        defer { os_unfair_lock_unlock(&cacheLock) }
        
        Set(cache.keys).union(muteRules.keys).forEach { unmuteNative($0, events: .all) }
        cache.removeAll()
        muteRules.removeAll()
    }
    
    private func muteNative(_ token: audit_token_t, events: ESEventSet) {
        if environment.useAPIv12, #available(macOS 12.0, *) {
            if client.esMuteProcessEvents(token, Array(events.events)) != ES_RETURN_SUCCESS {
                log.warning("Failed to mute process events: pid = \(token.pid)")
            }
        } else if events == .all {
            if client.esMuteProcess(token) != ES_RETURN_SUCCESS {
                log.warning("Failed to mute process: pid = \(token.pid)")
            }
        }
    }
    
    private func unmuteNative(_ token: audit_token_t, events: ESEventSet) {
        if environment.useAPIv12, #available(macOS 12.0, *) {
            if client.esUnmuteProcessEvents(token, Array(events.events)) != ES_RETURN_SUCCESS {
                log.warning("Failed to unmute process events: pid = \(token.pid)")
            }
        } else {
            if client.esUnmuteProcess(token) != ES_RETURN_SUCCESS {
                log.warning("Failed to unmute process: pid = \(token.pid)")
            }
        }
    }
}

extension ESMuteProcess {
    internal struct Environment {
        var useAPIv12 = true
        var checkAlive: (audit_token_t) -> Bool = { $0.checkAlive() }
    }
}

extension ESMuteProcessRule {
    var token: audit_token_t? {
        switch self {
        case .token(let token):
            return token
        case .pid(let pid):
            do {
                return try audit_token_t(pid: pid)
            } catch {
                log.warning("Failed to get auditToken for pid = \(pid)")
                return nil
            }
        }
    }
}

private extension audit_token_t {
    func checkAlive() -> Bool {
        (try? audit_token_t(pid: pid) == self) == true
    }
}
