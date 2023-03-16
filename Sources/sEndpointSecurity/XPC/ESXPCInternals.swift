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

@objc(ESClientXPCProtocol)
internal protocol ESClientXPCProtocol {
    func create(converterConfig: Data, completion: @escaping (es_new_client_result_t) -> Void)
    
    func clearPathInterestCache(reply: @escaping (Bool) -> Void)
    
    func mute(process mute: Data, events: [NSNumber], reply: @escaping (Bool) -> Void)
    func unmute(process mute: Data, events: [NSNumber], reply: @escaping (Bool) -> Void)
    func unmuteAllProcesses(reply: @escaping (Bool) -> Void)
    func mute(path: String, type: es_mute_path_type_t, events: [NSNumber], reply: @escaping (Bool) -> Void)
    func unmute(path: String, type: es_mute_path_type_t, events: [NSNumber], reply: @escaping (Bool) -> Void)
    func unmuteAllPaths(reply: @escaping (Bool) -> Void)
    func unmuteAllTargetPaths(reply: @escaping (Bool) -> Void)
    
    func subscribe(_ events: [NSNumber], reply: @escaping (Bool) -> Void)
    func unsubscribe(_ events: [NSNumber], reply: @escaping (Bool) -> Void)
    func unsubscribeAll(reply: @escaping (Bool) -> Void)
    func clearCache(reply: @escaping (es_clear_cache_result_t) -> Void)
    
    
    func invertMuting(_ muteType: es_mute_inversion_type_t, reply: @escaping (Bool) -> Void)
    func mutingInverted(_ muteType: es_mute_inversion_type_t, reply: @escaping (Bool) -> Void)
    
    func sendCustomMessage(_ data: Data, reply: @escaping (Data?, Error?) -> Void)
}

@objc(ESClientXPCDelegateProtocol)
internal protocol ESClientXPCDelegateProtocol {
    func handlePathInterest(_ process: Data, reply: @escaping (Data?) -> Void)
    func handleAuth(_ message: Data, reply: @escaping (UInt32, Bool) -> Void)
    func handleNotify(_ message: Data)
    
    func receiveCustomMessage(_ data: Data, completion: @escaping (Data?, Error?) -> Void)
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
