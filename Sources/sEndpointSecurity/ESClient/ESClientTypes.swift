//  MIT License
//
//  Copyright (c) 2021 Alkenso (Vladimir Vashurkin)
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


public struct ESAuthResolution: Equatable, Codable {
    public var result: ESAuthResult
    public var cache: Bool
    
    public init(result: ESAuthResult, cache: Bool) {
        self.result = result
        self.cache = cache
    }
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

public struct ESClientCreateError: Error {
    public var status: es_new_client_result_t
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
