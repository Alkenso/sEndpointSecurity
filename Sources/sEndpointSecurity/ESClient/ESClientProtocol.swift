//  MIT License
//
//  Copyright (c) 2023 Alkenso (Vladimir Vashurkin)
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

import Combine
import EndpointSecurity
import Foundation

public protocol ESClientProtocol: AnyObject {
    var config: ESClient.Config { get set }
    var queue: DispatchQueue? { get set }
    
    var authMessageHandler: ((ESMessagePtr, @escaping (ESAuthResolution) -> Void) -> Void)? { get set }
    var postAuthMessageHandler: ((ESMessagePtr, ESClient.ResponseInfo) -> Void)? { get set }
    var notifyMessageHandler: ((ESMessagePtr) -> Void)? { get set }
    
    func subscribe(_ events: [es_event_type_t]) -> Bool
    func unsubscribe(_ events: [es_event_type_t]) -> Bool
    func unsubscribeAll() -> Bool
    func clearCache() -> es_clear_cache_result_t
    
    var pathInterestHandler: ((ESProcess) -> ESInterest)? { get set }
    func clearPathInterestCache()
    
    func mute(process rule: ESMuteProcessRule, events: ESEventSet)
    func unmute(process rule: ESMuteProcessRule, events: ESEventSet)
    func unmuteAllProcesses()
    func mute(path: String, type: es_mute_path_type_t, events: ESEventSet) -> Bool
    @available(macOS 12.0, *)
    func unmute(path: String, type: es_mute_path_type_t, events: ESEventSet) -> Bool
    func unmuteAllPaths() -> Bool
    @available(macOS 13.0, *)
    func unmuteAllTargetPaths() -> Bool
    
    @available(macOS 13.0, *)
    func invertMuting(_ muteType: es_mute_inversion_type_t) -> Bool
    @available(macOS 13.0, *)
    func mutingInverted(_ muteType: es_mute_inversion_type_t) -> Bool
}
