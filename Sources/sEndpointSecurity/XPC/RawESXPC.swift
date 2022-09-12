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
