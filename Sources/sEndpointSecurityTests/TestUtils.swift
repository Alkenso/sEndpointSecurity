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

extension stat {
    static func random() throws -> stat {
        try FileManager.default.statItem(at: Bundle.main.bundleURL)
    }
}

extension audit_token_t {
    static func random() throws -> audit_token_t {
        var data = Data(pod: audit_token_t())
        data.withUnsafeMutableBytes {
            guard let ptr = $0.baseAddress else { return }
            _ = SecRandomCopyBytes(kSecRandomDefault, $0.count, ptr)
        }
        return data.pod(exactly: audit_token_t.self)!
    }
}

extension attrlist {
    static var random: attrlist {
        .init(bitmapcount: 1, reserved: 2, commonattr: 3, volattr: 4, dirattr: 5, fileattr: 6, forkattr: 7)
    }
}

extension statfs {
    static var random: statfs {
        var value = statfs()
        withUnsafeMutablePointer(to: &value) { pointer in
            _ = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<statfs>.size, pointer)
        }
        return value
    }
}
