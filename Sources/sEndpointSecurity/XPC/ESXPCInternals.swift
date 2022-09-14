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

typealias ESMessageXPC = Data
typealias ESEventSetXPC = Data
typealias ESMuteProcessRuleXPC = Data
typealias ESMutePathRuleXPC = Data
typealias ESConverterConfigXPC = Data

@objc(ESClientXPCProtocol)
internal protocol ESClientXPCProtocol {
    func create(converterConfig: ESConverterConfigXPC, completion: @escaping (es_new_client_result_t) -> Void)
    
    func subscribe(_ events: [NSNumber], reply: @escaping (Bool) -> Void)
    func unsubscribe(_ events: [NSNumber], reply: @escaping (Bool) -> Void)
    func unsubscribeAll(reply: @escaping (Bool) -> Void)
    func clearCache(reply: @escaping (es_clear_cache_result_t) -> Void)
    func muteProcess(_ mute: ESMuteProcessRuleXPC, events: ESEventSetXPC, reply: @escaping (Error?) -> Void)
    func unmuteProcess(_ mute: ESMuteProcessRuleXPC, events: ESEventSetXPC, reply: @escaping (Error?) -> Void)
    func unmuteAllProcesses(reply: @escaping (Error?) -> Void)
    func mutePath(_ mute: ESMutePathRuleXPC, events: ESEventSetXPC, reply: @escaping (Error?) -> Void)
    func unmutePath(_ mute: ESMutePathRuleXPC, events: ESEventSetXPC, reply: @escaping (Error?) -> Void)
    func unmuteAllPaths(reply: @escaping (Error?) -> Void)
    
    func custom(id: UUID, payload: Data, isReply: Bool, reply: @escaping () -> Void)
}

@objc(ESClientXPCDelegateProtocol)
internal protocol ESClientXPCDelegateProtocol {
    func handleAuth(_ message: ESMessageXPC, reply: @escaping (UInt32, Bool) -> Void)
    func handleNotify(_ message: ESMessageXPC)
    
    func custom(id: UUID, payload: Data, isReply: Bool, reply: @escaping () -> Void)
}

extension NSXPCInterface {
    internal static var esClient: NSXPCInterface {
        let interface = NSXPCInterface(with: ESClientXPCProtocol.self)
        return interface
    }
    
    internal static var esClientDelegate: NSXPCInterface {
        let interface = NSXPCInterface(with: ESClientXPCDelegateProtocol.self)
        return interface
    }
}

internal let xpcEncoder = JSONEncoder()
internal let xpcDecoder = JSONDecoder()
