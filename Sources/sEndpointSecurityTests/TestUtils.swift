import Foundation


extension stat {
    static func random() throws -> stat {
        try Bundle.main.bundleURL.stat()
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
