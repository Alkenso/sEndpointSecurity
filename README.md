# sEndpointSecurity

# Intro
With macOS 10.15 Catalina, Apple released beautiful framework EndpointSecurity. It is a usermode replacement for kAuth and MACF mechanisms previously available only from the Kernel.

The framework provides lots functionality...but is plain C

# Motivation

sEndpointSecurity is Swift wrapper around ES C API and was written with three main goals is mind
- provide convenient, Swift-style approach to EndpointSecurity API
- keep in a single place all parsing and interoperations within C data types
- solve the biggest problem dealing with file authentication events: debugging

If first two are obvious, the third one requires a bit of additional explanation.
When you subscribes to file authentication events, that means **nobody** can access the file before the client returns resolution for it.
And what debugger does? On breakpoint, it suspends the application (the client) and prevent it from responding any events.
This cause whole OS to hang until the client is killed by EndpontSecurity.kext from the Kernel.

sEndpointSecurity provides approach to deal with debugging - XPC wrapper around ES client.
So we move events receiving and responding to another process and deal with it over XPC. That allows us to debug the application.

# API
The rare one likes ReadMe without code samples. Here they are

## ESClient

ESClient is a Swift wrapper around EndpointSecurity C API with a bit extended functional for convenience

```
import sEndpointSecurity

//  Create ESClient
var status: es_new_client_result_t = ES_NEW_CLIENT_RESULT_ERR_INTERNAL
guard let client = ESClient(status: &status) else {
    print("Failed to create ESClient. Status = \(status)")
    exit(1)
}

//  Register message handlers
var cancellables: [AnyCancellable] = []
client.authMessage.register { message, callback in
    print("Auth message: \(try! message.converted())")
    callback(.allowOnce)
}
.store(in: &cancellables)

client.notifyMessage.register { message in
    print("Notify message: \(try! message.converted())")
}
.store(in: &cancellables)

//  Start receiving messages
guard client.subscribe([ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT]) else {
    print("Failed to subscribe to ES messages")
    exit(2)
}


withExtendedLifetime(cancellables) { RunLoop.main.run() }
withExtendedLifetime(client) {}
```

## ES over XPC
### ESXPCClient
ESXPCClient is client counterpart of ES over XPC implementation. It looks very close to ESClient, but have some differences due to asynchronous XPC nature

```
import sEndpointSecurity

//  Create ESXPCClient
let client = ESXPCClient(NSXPCConnection(serviceName: "com.alkenso.ESXPC"))
let status = try! client.activate()
guard status == ES_NEW_CLIENT_RESULT_SUCCESS else {
    print("Failed to activate ESXPCClient. Status = \(status)")
    exit(1)
}

//  Register message handlers
var cancellables: [AnyCancellable] = []
client.authMessage.register { message, callback in
    print("Auth message: \(try! message.converted())")
    callback(.allowOnce)
}
.store(in: &cancellables)

client.notifyMessage.register { message in
    print("Notify message: \(try! message.converted())")
}
.store(in: &cancellables)

//  Start receiving messages
client.subscribe([ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT]) { result in
    guard result.success == true else {
        print("Failed to subscribe to ES events")
        exit(2)
    }
    print("Successfully subscribed to ES events")
}


withExtendedLifetime(cancellables) { RunLoop.main.run() }
withExtendedLifetime(client) {}
```

### ESXPCService
ESXPCService is service counterpart of ES over XPC implementation. It is created in the process that actually works with ES framework.

```
import sEndpointSecurity

let service = ESXPCService(
    listener: NSXPCListener.service(),
    createClient: ESClient.init
)
service.activate()

withExtendedLifetime(service) { RunLoop.main.run() }
```

# Dependencies
The package is designed with the minimum dependencies. At the moment, it it the only one utility library SwiftConvenience (no additional dependencies)
