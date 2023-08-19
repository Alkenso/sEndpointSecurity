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

internal final class ESMuteProcess {
    private let client: ESNativeClient
    private let cleanupDelay: TimeInterval
    private let environment: Environment
    private var processMutes: [audit_token_t: Set<es_event_type_t>] = [:]
    private var lock = os_unfair_lock_s()
    private var processMutesInverted = false
    
    init(client: ESNativeClient, cleanupDelay: TimeInterval = 60.0, environment: Environment = .init()) {
        self.client = client
        self.cleanupDelay = cleanupDelay
        self.environment = environment
        
        scheduleCleanupDiedProcesses()
    }
    
    private func scheduleCleanupDiedProcesses() {
        DispatchQueue.global().asyncAfter(deadline: .now() + cleanupDelay) { [weak self] in
            guard let self else { return }
            self.cleanupDiedProcesses()
            self.scheduleCleanupDiedProcesses()
        }
    }
    
    private func cleanupDiedProcesses() {
        os_unfair_lock_lock(&lock)
        let processMutesCopy = processMutes
        os_unfair_lock_unlock(&lock)
        
        let tokensToRemove = processMutesCopy.keys.filter { !environment.checkAlive($0) }
        os_unfair_lock_lock(&lock)
        tokensToRemove.forEach { processMutes.removeValue(forKey: $0) }
        os_unfair_lock_unlock(&lock)
    }
    
    // MARK: Mute check
    
    func checkMuted(_ event: es_event_type_t, process token: audit_token_t) -> Bool {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        guard let processMuted = processMutes[token]?.contains(event) else { return false }
        return processMuted != processMutesInverted
    }
    
    // MARK: Mute management
    
    func mute(_ token: audit_token_t, events: Set<es_event_type_t>) {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        processMutes[token, default: []].formUnion(events)
        muteNative(token, events: events)
    }
    
    func unmute(_ token: audit_token_t, events: Set<es_event_type_t>) {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        if var cachedEvents = processMutes[token] {
            cachedEvents.subtract(events)
            if cachedEvents.isEmpty {
                processMutes.removeValue(forKey: token)
            } else {
                processMutes[token] = cachedEvents
            }
        }
        unmuteNative(token, events: events)
    }
    
    func unmuteAll() {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        processMutes.keys.forEach { unmuteNative($0, events: ESEventSet.all.events) }
        processMutes.removeAll()
    }
    
    private func muteNative(_ token: audit_token_t, events: Set<es_event_type_t>) {
        if environment.useAPIv12, #available(macOS 12.0, *) {
            if client.esMuteProcessEvents(token, Array(events)) != ES_RETURN_SUCCESS {
                log.warning("Failed to mute process events: pid = \(token.pid)")
            }
        } else if events == ESEventSet.all.events {
            if client.esMuteProcess(token) != ES_RETURN_SUCCESS {
                log.warning("Failed to mute process: pid = \(token.pid)")
            }
        }
    }
    
    private func unmuteNative(_ token: audit_token_t, events: Set<es_event_type_t>) {
        if environment.useAPIv12, #available(macOS 12.0, *) {
            if client.esUnmuteProcessEvents(token, Array(events)) != ES_RETURN_SUCCESS {
                log.warning("Failed to unmute process events: pid = \(token.pid)")
            }
        } else {
            if client.esUnmuteProcess(token) != ES_RETURN_SUCCESS {
                log.warning("Failed to unmute process: pid = \(token.pid)")
            }
        }
    }
    
    // MARK: Other
    
    @available(macOS 13.0, *)
    func invertMuting() -> Bool {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        
        guard client.esInvertMuting(ES_MUTE_INVERSION_TYPE_PROCESS) == ES_RETURN_SUCCESS else { return false }
        
        processMutesInverted.toggle()
        
        return true
    }
}

extension ESMuteProcess {
    internal struct Environment {
        var useAPIv12 = true
        var checkAlive: (audit_token_t) -> Bool = { $0.checkAlive() }
    }
}

private extension audit_token_t {
    func checkAlive() -> Bool {
        (try? audit_token_t(pid: pid) == self) == true
    }
}
