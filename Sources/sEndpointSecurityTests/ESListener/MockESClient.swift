import sEndpointSecurity

import EndpointSecurity
import Foundation

class MockESClient: ESClientProtocol {
    var config = ESClient.Config()
    var queue: DispatchQueue?
    
    var authMessageHandler: ((ESMessagePtr, @escaping (ESAuthResolution) -> Void) -> Void)?
    var postAuthMessageHandler: ((ESMessagePtr, ESClient.ResponseInfo) -> Void)?
    var notifyMessageHandler: ((ESMessagePtr) -> Void)?
    
    func subscribe(_ events: [es_event_type_t]) -> Bool {
        true
    }
    
    func unsubscribe(_ events: [es_event_type_t]) -> Bool {
        true
    }
    
    func unsubscribeAll() -> Bool {
        true
    }
    
    func clearCache() -> es_clear_cache_result_t {
        ES_CLEAR_CACHE_RESULT_SUCCESS
    }
    
    var pathInterestHandler: ((ESProcess) -> ESInterest)?
    
    func clearPathInterestCache() {
        
    }
    
    func mute(process rule: ESMuteProcessRule, events: ESEventSet) {
        
    }
    
    func unmute(process rule: ESMuteProcessRule, events: ESEventSet) {
        
    }
    
    func unmuteAllProcesses() {
        
    }
    
    func mute(path: String, type: es_mute_path_type_t, events: ESEventSet) -> Bool {
        true
    }
    
    func unmute(path: String, type: es_mute_path_type_t, events: ESEventSet) -> Bool {
        true
    }
    
    func unmuteAllPaths() -> Bool {
        true
    }
    
    func unmuteAllTargetPaths() -> Bool {
        true
    }
    
    func invertMuting(_ muteType: es_mute_inversion_type_t) -> Bool {
        false
    }
    
    func mutingInverted(_ muteType: es_mute_inversion_type_t) -> Bool {
        false
    }
}
