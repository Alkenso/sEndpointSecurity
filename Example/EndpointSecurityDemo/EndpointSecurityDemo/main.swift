import sEndpointSecurity

import Combine
import EndpointSecurity
import Foundation
import SwiftConvenience

class Main {
    init() {
        SCLogger.default.destinations.append {
            print($0)
        }
    }
    
    var client: ESClient!
    func start() throws {
        client = try ESClient()
        _ = try client.muteProcess(.token(.current()))
        
        client.processFilterHandler = {
            // Filter out messages from 'mdworker_shared'
            !$0.executable.path.contains("mdworker_shared")
        }
        
        client.authMessageHandler = { raw, callback in
            let message = try! raw.converted()
            
            let process = message.process.executable.path.lastPathComponent
            switch message.event {
            case .rename(let rename):
                var filePath = rename.source.path + " -> "
                switch rename.destination {
                case .existingFile(let file):
                    filePath += file.path
                case .newPath(let dir, let filename):
                    filePath += dir.path.appendingPathComponent(filename)
                }
                print("AUTH-RENAME by \(process): \(filePath)")
                callback(.allowOnce)
            default:
                callback(.allow)
                print("AUTH-ERROR: unexpected event: \(message.eventType)")
            }
        }
        
        client.notifyMessageHandler = {
            let message = try! $0.converted()
            
            let process = message.process.executable.path.lastPathComponent
            switch message.event {
            case .create(let create):
                let filePath: String
                switch create.destination {
                case .existingFile(let file):
                    filePath = file.path
                case .newPath(let dir, let filename, _):
                    filePath = dir.path.appendingPathComponent(filename)
                }
                print("NOTIFY-RENAME by \(process): \(filePath)")
            case .exec(let exec):
                let target = exec.target.executable.path.lastPathComponent
                print("NOTIFY-EXEC by \(process): \(target)")
            case .exit(let exit):
                print("NOTIFY-EXIT by \(process): exit status = \(exit.status)")
            default:
                print("NOTIFY-ERROR: unexpected event type = \(message.eventType)")
            }
        }
        
        let events = [
            ES_EVENT_TYPE_AUTH_RENAME,
            
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
        ]
        guard client.subscribe(events) else {
            throw CommonError.unexpected("Subscribe to ES events fails")
        }
    }
}

let main = Main()
do {
    try main.start()
    print("Started")
    withExtendedLifetime(main) { RunLoop.main.run() }
} catch {
    print("Failed to start demo. Error: \(error)")
}
