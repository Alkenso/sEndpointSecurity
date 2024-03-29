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
import SpellbookFoundation

extension es_event_exec_t {
    public var args: [String] {
        parse(valueFn: es_exec_arg, countFn: es_exec_arg_count).map(Self.dummyConverter.esString)
    }
    
    public var env: [String] {
        parse(valueFn: es_exec_env, countFn: es_exec_env_count).map(Self.dummyConverter.esString)
    }
    
    private static let dummyConverter = ESConverter(version: 0)
    
    private func parse<T>(
        valueFn: (UnsafePointer<es_event_exec_t>, UInt32) -> T,
        countFn: (UnsafePointer<es_event_exec_t>) -> UInt32
    ) -> [T] {
        withUnsafePointer(to: self) {
            var values: [T] = []
            let count = countFn($0)
            for i in 0..<count {
                let value = valueFn($0, i)
                values.append(value)
            }
            return values
        }
    }
}

internal func validESEvents(_ client: ESNativeClient) -> Set<es_event_type_t> {
    guard #available(macOS 12.0, *) else { return fallbackESEvents }
    
    return validESEventsCacheLock.withLock {
        if let validESEventsCache { return validESEventsCache }
        
        let dummyPath = "/dummy_\(UUID())"
        guard client.esMutePath(dummyPath, ES_MUTE_PATH_TYPE_LITERAL) == ES_RETURN_SUCCESS else {
            return fallbackESEvents
        }
        defer { _ = client.esUnmutePath(dummyPath, ES_MUTE_PATH_TYPE_LITERAL) }
        
        guard let allMutes = client.esMutedPaths().first(where: { $0.path == dummyPath })?.events,
              !allMutes.isEmpty
        else {
            return fallbackESEvents
        }
        
        validESEventsCache = Set(allMutes)
        
        return validESEventsCache!
    }
}

private var validESEventsCache: Set<es_event_type_t>?
private var validESEventsCacheLock = UnfairLock()

private let fallbackESEvents: Set<es_event_type_t> = {
    let lastEvent: UInt32
    if #available(macOS 14.0, *) {
        lastEvent = ES_EVENT_TYPE_LAST.rawValue
    } else if #available(macOS 13.0, *) {
        lastEvent = ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE.rawValue
    } else if #available(macOS 12.0, *) {
        lastEvent = ES_EVENT_TYPE_NOTIFY_COPYFILE.rawValue
    } else if #available(macOS 11.3, *) {
        lastEvent = ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT.rawValue + 1
    } else {
        lastEvent = ES_EVENT_TYPE_NOTIFY_REMOUNT.rawValue + 1
    }
    return Set((0..<lastEvent).map(es_event_type_t.init(rawValue:)))
}()
