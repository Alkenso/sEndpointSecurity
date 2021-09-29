//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 27.09.2021.
//

import EndpointSecurity
import Foundation


typealias ESMessagePtrXPC = Data
typealias ESMuteProcessXPC = Data

@objc(ESClientXPCProtocol)
protocol ESClientXPCProtocol {
    func create(completion: @escaping (es_new_client_result_t) -> Void)
    
    func subscribe(_ events: [NSNumber], reply: @escaping (Bool) -> Void)
    func unsubscribe(_ events: [NSNumber], reply: @escaping (Bool) -> Void)
    func unsubscribeAll(reply: @escaping (Bool) -> Void)
    func clearCache(reply: @escaping (es_clear_cache_result_t) -> Void)
    func muteProcess(_ mute: ESMuteProcessXPC, reply: @escaping (Bool) -> Void)
    func unmuteProcess(_ mute: ESMuteProcessXPC, reply: @escaping (Bool) -> Void)
    func mutePath(prefix: String, reply: @escaping (Bool) -> Void)
    func mutePath(literal: String, reply: @escaping (Bool) -> Void)
    func unmuteAllPaths(reply: @escaping (Bool) -> Void)
    
    func custom(id: UUID, payload: Data, isReply: Bool, reply: @escaping () -> Void)
}

@objc(ESClientXPCDelegateProtocol)
protocol ESClientXPCDelegateProtocol {
    func handleAuth(_ message: ESMessagePtrXPC, reply: @escaping (UInt32, Bool) -> Void)
    func handleNotify(_ message: ESMessagePtrXPC)
    
    func custom(id: UUID, payload: Data, isReply: Bool, reply: @escaping () -> Void)
}

extension NSXPCInterface {
    static var esClient: NSXPCInterface {
        let interface = NSXPCInterface(with: ESClientXPCProtocol.self)
        return interface
    }
    
    static var esClientDelegate: NSXPCInterface {
        let interface = NSXPCInterface(with: ESClientXPCDelegateProtocol.self)
        return interface
    }
}
