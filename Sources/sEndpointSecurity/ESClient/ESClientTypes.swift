//
//  File.swift
//  
//
//  Created by Alkenso (Vladimir Vashurkin) on 27.09.2021.
//

import EndpointSecurity
import Foundation


public struct ESAuthResolution: Equatable, Codable {
    public var result: ESAuthResult
    public var cache: Bool
}

public extension ESAuthResolution {
    static let allow = ESAuthResolution(result: .auth(true), cache: true)
    static let allowOnce = ESAuthResolution(result: .auth(true), cache: false)
    static let deny = ESAuthResolution(result: .auth(false), cache: true)
    static let denyOnce = ESAuthResolution(result: .auth(false), cache: false)
}

public enum ESMuteProcess: Hashable, Codable {
    // - Exact process
    case token(audit_token_t)
    case pid(pid_t)
    
    // - Patterns
    case euid(uid_t)
    
    case name(String)
    case pathPrefix(String)
    case pathLiteral(String)
    
    //  Codesign Team Identifier (DEVELOPMENT_TEAM in Xcode)
    case teamIdentifier(String)
    
    //  Usually equals to application bundle identifier
    case signingID(String)
}

public enum ESClientCreateError: Error {
    case create(es_new_client_result_t)
    case subscribe
    case other(Error)
}


extension ESAuthResolution {
    static func combine(_ resolutions: [ESAuthResolution]) -> ESAuthResolution {
        guard let first = resolutions.first else { return .allowOnce }
        guard resolutions.count > 1 else { return first }
        
        let flags = resolutions.map(\.result.rawValue).reduce(UInt32.max) { $0 & $1 }
        let cache = resolutions.map(\.cache).reduce(true) { $0 && $1 }
        
        return ESAuthResolution(result: .flags(flags), cache: cache)
    }
}
