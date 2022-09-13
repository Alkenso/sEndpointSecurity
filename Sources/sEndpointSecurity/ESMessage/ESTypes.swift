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
import SwiftConvenience

public struct ESMessage: Equatable, Codable {
    public var version: UInt32
    public var time: timespec
    public var machTime: UInt64
    public var deadline: UInt64
    public var process: ESProcess
    public var seqNum: UInt64? /* field available only if message version >= 2 */
    public var action: Action
    public var event: ESEvent
    public var eventType: es_event_type_t
    public var thread: ESThread? /* field available only if message version >= 4 */
    public var globalSeqNum: UInt64? /* field available only if message version >= 4 */
    
    public enum Action: Equatable, Codable {
        case auth
        case notify(ESAuthResult)
    }
    
    public init(version: UInt32, time: timespec, machTime: UInt64, deadline: UInt64, process: ESProcess, seqNum: UInt64? = nil, action: ESMessage.Action, event: ESEvent, eventType: es_event_type_t, thread: ESThread? = nil, globalSeqNum: UInt64? = nil) {
        self.version = version
        self.time = time
        self.machTime = machTime
        self.deadline = deadline
        self.process = process
        self.seqNum = seqNum
        self.action = action
        self.event = event
        self.eventType = eventType
        self.thread = thread
        self.globalSeqNum = globalSeqNum
    }
}

public struct ESProcess: Equatable, Codable {
    public var auditToken: audit_token_t
    public var ppid: pid_t
    public var originalPpid: pid_t
    public var groupID: pid_t
    public var sessionID: pid_t
    public var codesigningFlags: UInt32
    public var isPlatformBinary: Bool
    public var isESClient: Bool
    public var cdHash: Data
    public var signingID: String
    public var teamID: String
    public var executable: ESFile
    public var tty: ESFile? /* field available only if message version >= 2 */
    public var startTime: timeval? /* field available only if message version >= 3 */
    public var responsibleAuditToken: audit_token_t? /* field available only if message version >= 4 */
    public var parentAuditToken: audit_token_t? /* field available only if message version >= 4 */
    
    public init(auditToken: audit_token_t, ppid: pid_t, originalPpid: pid_t, groupID: pid_t, sessionID: pid_t, codesigningFlags: UInt32, isPlatformBinary: Bool, isESClient: Bool, cdHash: Data, signingID: String, teamID: String, executable: ESFile, tty: ESFile? = nil, startTime: timeval? = nil, responsibleAuditToken: audit_token_t? = nil, parentAuditToken: audit_token_t? = nil) {
        self.auditToken = auditToken
        self.ppid = ppid
        self.originalPpid = originalPpid
        self.groupID = groupID
        self.sessionID = sessionID
        self.codesigningFlags = codesigningFlags
        self.isPlatformBinary = isPlatformBinary
        self.isESClient = isESClient
        self.cdHash = cdHash
        self.signingID = signingID
        self.teamID = teamID
        self.executable = executable
        self.tty = tty
        self.startTime = startTime
        self.responsibleAuditToken = responsibleAuditToken
        self.parentAuditToken = parentAuditToken
    }
}

extension ESProcess {
    public var name: String { executable.path.lastPathComponent }
}

public struct ESFile: Equatable, Codable {
    public var path: String
    public var truncated: Bool
    public var stat: stat
    
    public init(path: String, truncated: Bool, stat: stat) {
        self.path = path
        self.truncated = truncated
        self.stat = stat
    }
}

public struct ESThread: Equatable, Codable {
    public var threadID: UInt64
    
    public init(threadID: UInt64) {
        self.threadID = threadID
    }
}

public struct ESThreadState: Equatable, Codable {
    public var flavor: Int32
    public var state: Data
    
    public init(flavor: Int32, state: Data) {
        self.flavor = flavor
        self.state = state
    }
}

public struct ESAuthResult: Equatable, Codable, RawRepresentable {
    public static func auth(_ auth: Bool) -> ESAuthResult { .init(rawValue: auth ? .max : 0) }
    public static func flags(_ flags: UInt32) -> ESAuthResult { .init(rawValue: flags) }
    
    public var rawValue: UInt32
    
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
}

public enum ESEvent: Equatable, Codable {
    case access(Access)
    case chdir(Chdir)
    case chroot(Chroot)
    case clone(Clone)
    case copyfile(CopyFile)
    case close(Close)
    case create(Create)
    case csInvalidated
    case deleteextattr(DeleteExtAttr)
    case dup(Dup)
    case exchangedata(ExchangeData)
    case exec(Exec)
    case exit(Exit)
    case fileProviderMaterialize(FileProviderMaterialize)
    case fileProviderUpdate(FileProviderUpdate)
    case fcntl(Fcntl)
    case fork(Fork)
    case fsgetpath(FsGetPath)
    case getTask(GetTask)
    case getTaskRead(GetTaskRead)
    case getTaskInspect(GetTaskInspect)
    case getTaskName(GetTaskName)
    case getattrlist(GetAttrList)
    case getextattr(GetExtAttr)
    case iokitOpen(IOKitOpen)
    case kextload(KextLoad)
    case kextunload(KextUnload)
    case link(Link)
    case listextattr(ListExtAttr)
    case lookup(Lookup)
    case mmap(MMap)
    case mount(Mount)
    case mprotect(MProtect)
    case open(Open)
    case procCheck(ProcCheck)
    case procSuspendResume(ProcSuspendResume)
    case ptyClose(PtyClose)
    case ptyGrant(PtyGrant)
    case readdir(Readdir)
    case readlink(Readlink)
    case remoteThreadCreate(RemoteThreadCreate)
    case remount(Remount)
    case rename(Rename)
    case searchfs(SearchFS)
    case setacl(SetACL)
    case setattrlist(SetAttrList)
    case setextattr(SetExtAttr)
    case setflags(SetFlags)
    case setmode(SetMode)
    case setowner(SetOwner)
    case setuid(SetUID)
    case setreuid(SetREUID)
    case settime
    case signal(Signal)
    case stat(Stat)
    case trace(Trace)
    case truncate(Truncate)
    case uipcBind(UipcBind)
    case uipcConnect(UipcConnect)
    case unlink(Unlink)
    case unmount(Unmount)
    case utimes(Utimes)
    case write(Write)
}

public extension ESEvent {
    struct Access: Equatable, Codable {
        public var mode: Int32
        public var target: ESFile
        
        public init(mode: Int32, target: ESFile) {
            self.mode = mode
            self.target = target
        }
    }
    
    struct Chdir: Equatable, Codable {
        public var target: ESFile
        
        public init(target: ESFile) {
            self.target = target
        }
    }
    
    struct Chroot: Equatable, Codable {
        public var target: ESFile
        
        public init(target: ESFile) {
            self.target = target
        }
    }
    
    struct Clone: Equatable, Codable {
        public var source: ESFile
        public var targetDir: ESFile
        public var targetName: String
        
        public init(source: ESFile, targetDir: ESFile, targetName: String) {
            self.source = source
            self.targetDir = targetDir
            self.targetName = targetName
        }
    }
    
    struct CopyFile: Equatable, Codable {
        public var source: ESFile
        public var targetFile: ESFile?
        public var targetDir: ESFile
        public var targetName: String
        public var mode: mode_t
        public var flags: Int32
        
        public init(source: ESFile, targetFile: ESFile? = nil, targetDir: ESFile, targetName: String, mode: mode_t, flags: Int32) {
            self.source = source
            self.targetFile = targetFile
            self.targetDir = targetDir
            self.targetName = targetName
            self.mode = mode
            self.flags = flags
        }
    }
    
    struct Close: Equatable, Codable {
        public var modified: Bool
        public var target: ESFile
        
        public init(modified: Bool, target: ESFile) {
            self.modified = modified
            self.target = target
        }
    }
    
    struct Create: Equatable, Codable {
        public var destination: Destination
        
        /// - Note: field available only if message version >= 2
        /// - Note: `acl` is present only in original message.
        /// If structure is re-encoded, this field will be lost.
        public var acl: Resource<acl_t>?
        
        public enum Destination: Equatable, Codable {
            case existingFile(ESFile)
            case newPath(dir: ESFile, filename: String, mode: mode_t)
        }
        
        public init(destination: ESEvent.Create.Destination, acl: acl_t?) {
            self.destination = destination
            if let acl = acl, let dup = acl_dup(acl) {
                self.acl = .raii(dup) { acl_free(.init($0)) }
            }
        }
        
        enum CodingKeys: String, CodingKey {
            case destination
        }
    }
    
    struct DeleteExtAttr: Equatable, Codable {
        public var target: ESFile
        public var extattr: String
        
        public init(target: ESFile, extattr: String) {
            self.target = target
            self.extattr = extattr
        }
    }
    
    struct Dup: Equatable, Codable {
        public var target: ESFile
        
        public init(target: ESFile) {
            self.target = target
        }
    }
    
    struct ExchangeData: Equatable, Codable {
        public var file1: ESFile
        public var file2: ESFile
        
        public init(file1: ESFile, file2: ESFile) {
            self.file1 = file1
            self.file2 = file2
        }
    }
    
    struct Exec: Equatable, Codable {
        public var target: ESProcess
        public var script: ESFile? /* field available only if message version >= 2 */
        public var cwd: ESFile? /* field available only if message version >= 3 */
        public var lastFD: Int32? /* field available only if message version >= 4 */
        
        public var args: [String]? // present if ESConverter.Config.execArgs == true
        public var env: [String]? // present if ESConverter.Config.execEnv == true
        
        public init(target: ESProcess, script: ESFile? = nil, cwd: ESFile? = nil, lastFD: Int32? = nil) {
            self.target = target
            self.script = script
            self.cwd = cwd
            self.lastFD = lastFD
        }
    }
    
    struct Exit: Equatable, Codable {
        public var status: Int32
        
        public init(status: Int32) {
            self.status = status
        }
    }
    
    struct FileProviderMaterialize: Equatable, Codable {
        public var instigator: ESProcess
        public var source: ESFile
        public var target: ESFile
        
        public init(instigator: ESProcess, source: ESFile, target: ESFile) {
            self.instigator = instigator
            self.source = source
            self.target = target
        }
    }
    
    struct FileProviderUpdate: Equatable, Codable {
        public var source: ESFile
        public var targetPath: String
        
        public init(source: ESFile, targetPath: String) {
            self.source = source
            self.targetPath = targetPath
        }
    }
    
    struct Fcntl: Equatable, Codable {
        public var target: ESFile
        public var cmd: Int32
        
        public init(target: ESFile, cmd: Int32) {
            self.target = target
            self.cmd = cmd
        }
    }
    
    struct Fork: Equatable, Codable {
        public var child: ESProcess
        
        public init(child: ESProcess) {
            self.child = child
        }
    }
    
    struct FsGetPath: Equatable, Codable {
        public var target: ESFile
        
        public init(target: ESFile) {
            self.target = target
        }
    }
    
    struct GetTask: Equatable, Codable {
        public var target: ESProcess
        
        public init(target: ESProcess) {
            self.target = target
        }
    }
    
    struct GetTaskRead: Equatable, Codable {
        public var target: ESProcess
        
        public init(target: ESProcess) {
            self.target = target
        }
    }
    
    struct GetTaskInspect: Equatable, Codable {
        public var target: ESProcess
        
        public init(target: ESProcess) {
            self.target = target
        }
    }
    
    struct GetTaskName: Equatable, Codable {
        public var target: ESProcess
        
        public init(target: ESProcess) {
            self.target = target
        }
    }
    
    struct GetAttrList: Equatable, Codable {
        public var attrlist: attrlist
        public var target: ESFile
        
        public init(attrlist: attrlist, target: ESFile) {
            self.attrlist = attrlist
            self.target = target
        }
    }
    
    struct GetExtAttr: Equatable, Codable {
        public var target: ESFile
        public var extattr: String
        
        public init(target: ESFile, extattr: String) {
            self.target = target
            self.extattr = extattr
        }
    }
    
    struct IOKitOpen: Equatable, Codable {
        public var userClientType: UInt32
        public var userClientClass: String
        
        public init(userClientType: UInt32, userClientClass: String) {
            self.userClientType = userClientType
            self.userClientClass = userClientClass
        }
    }
    
    struct KextLoad: Equatable, Codable {
        public var identifier: String
        
        public init(identifier: String) {
            self.identifier = identifier
        }
    }
    
    struct KextUnload: Equatable, Codable {
        public var identifier: String
        
        public init(identifier: String) {
            self.identifier = identifier
        }
    }
    
    struct Link: Equatable, Codable {
        public var source: ESFile
        public var targetDir: ESFile
        public var targetFilename: String
        
        public init(source: ESFile, targetDir: ESFile, targetFilename: String) {
            self.source = source
            self.targetDir = targetDir
            self.targetFilename = targetFilename
        }
    }
    
    struct ListExtAttr: Equatable, Codable {
        public var target: ESFile
        
        public init(target: ESFile) {
            self.target = target
        }
    }
    
    struct Lookup: Equatable, Codable {
        public var sourceDir: ESFile
        public var relativeTarget: String
        
        public init(sourceDir: ESFile, relativeTarget: String) {
            self.sourceDir = sourceDir
            self.relativeTarget = relativeTarget
        }
    }
    
    struct MMap: Equatable, Codable {
        public var protection: Int32
        public var maxProtection: Int32
        public var flags: Int32
        public var filePos: UInt64
        public var source: ESFile
        
        public init(protection: Int32, maxProtection: Int32, flags: Int32, filePos: UInt64, source: ESFile) {
            self.protection = protection
            self.maxProtection = maxProtection
            self.flags = flags
            self.filePos = filePos
            self.source = source
        }
    }
    
    struct Mount: Equatable, Codable {
        public var statfs: statfs
        
        public init(statfs: statfs) {
            self.statfs = statfs
        }
    }
    
    struct MProtect: Equatable, Codable {
        public var protection: Int32
        public var address: user_addr_t
        public var size: user_size_t
        
        public init(protection: Int32, address: user_addr_t, size: user_size_t) {
            self.protection = protection
            self.address = address
            self.size = size
        }
    }
    
    struct Open: Equatable, Codable {
        public var fflag: Int32
        public var file: ESFile
        
        public init(fflag: Int32, file: ESFile) {
            self.fflag = fflag
            self.file = file
        }
    }
    
    struct ProcCheck: Equatable, Codable {
        public var target: ESProcess?
        public var type: es_proc_check_type_t
        public var flavor: Int32
        
        public init(target: ESProcess? = nil, type: es_proc_check_type_t, flavor: Int32) {
            self.target = target
            self.type = type
            self.flavor = flavor
        }
    }
    
    struct ProcSuspendResume: Equatable, Codable {
        public var target: ESProcess?
        public var type: es_proc_suspend_resume_type_t
        
        public init(target: ESProcess? = nil, type: es_proc_suspend_resume_type_t) {
            self.target = target
            self.type = type
        }
    }
    
    struct PtyClose: Equatable, Codable {
        public var dev: dev_t
        
        public init(dev: dev_t) {
            self.dev = dev
        }
    }
    
    struct PtyGrant: Equatable, Codable {
        public var dev: dev_t
        
        public init(dev: dev_t) {
            self.dev = dev
        }
    }
    
    struct Readdir: Equatable, Codable {
        public var target: ESFile
        
        public init(target: ESFile) {
            self.target = target
        }
    }
    
    struct Readlink: Equatable, Codable {
        public var source: ESFile
        
        public init(source: ESFile) {
            self.source = source
        }
    }
    
    struct RemoteThreadCreate: Equatable, Codable {
        public var target: ESProcess
        public var threadState: ESThreadState?
        
        public init(target: ESProcess, threadState: ESThreadState? = nil) {
            self.target = target
            self.threadState = threadState
        }
    }
    
    struct Remount: Equatable, Codable {
        public var statfs: statfs
        
        public init(statfs: statfs) {
            self.statfs = statfs
        }
    }
    
    struct Rename: Equatable, Codable {
        public var source: ESFile
        public var destination: Destination
        
        public enum Destination: Equatable, Codable {
            case existingFile(ESFile)
            case newPath(dir: ESFile, filename: String)
        }
        
        public init(source: ESFile, destination: ESEvent.Rename.Destination) {
            self.source = source
            self.destination = destination
        }
    }
    
    struct SearchFS: Equatable, Codable {
        public var attrlist: attrlist
        public var target: ESFile
        
        public init(attrlist: attrlist, target: ESFile) {
            self.attrlist = attrlist
            self.target = target
        }
    }
    
    struct SetACL: Equatable, Codable {
        public var target: ESFile
        public var setOrClear: es_set_or_clear_t
        
        /// - Note: `acl` is present only in original message.
        /// If structure is re-encoded, this field will be lost.
        public var acl: Resource<acl_t>?
        
        public init(target: ESFile, setOrClear: es_set_or_clear_t, acl: acl_t?) {
            self.target = target
            self.setOrClear = setOrClear
            if let acl = acl, let dup = acl_dup(acl) {
                self.acl = .raii(dup) { acl_free(.init($0)) }
            }
        }
        
        enum CodingKeys: String, CodingKey {
            case target
            case setOrClear
        }
    }
    
    struct SetAttrList: Equatable, Codable {
        public var attrlist: attrlist
        public var target: ESFile
        
        public init(attrlist: attrlist, target: ESFile) {
            self.attrlist = attrlist
            self.target = target
        }
    }
    
    struct SetExtAttr: Equatable, Codable {
        public var target: ESFile
        public var extattr: String
        
        public init(target: ESFile, extattr: String) {
            self.target = target
            self.extattr = extattr
        }
    }
    
    struct SetFlags: Equatable, Codable {
        public var flags: UInt32
        public var target: ESFile
        
        public init(flags: UInt32, target: ESFile) {
            self.flags = flags
            self.target = target
        }
    }
    
    struct SetMode: Equatable, Codable {
        public var mode: mode_t
        public var target: ESFile
        
        public init(mode: mode_t, target: ESFile) {
            self.mode = mode
            self.target = target
        }
    }
    
    struct SetOwner: Equatable, Codable {
        public var uid: uid_t
        public var gid: gid_t
        public var target: ESFile
        
        public init(uid: uid_t, gid: gid_t, target: ESFile) {
            self.uid = uid
            self.gid = gid
            self.target = target
        }
    }
    
    struct SetUID: Equatable, Codable {
        public var uid: uid_t
        
        public init(uid: uid_t) {
            self.uid = uid
        }
    }
    
    struct SetREUID: Equatable, Codable {
        public var ruid: uid_t
        public var euid: uid_t
        
        public init(ruid: uid_t, euid: uid_t) {
            self.ruid = ruid
            self.euid = euid
        }
    }
    
    struct Signal: Equatable, Codable {
        public var sig: Int32
        public var target: ESProcess
        
        public init(sig: Int32, target: ESProcess) {
            self.sig = sig
            self.target = target
        }
    }
    
    struct Stat: Equatable, Codable {
        public var target: ESFile
        
        public init(target: ESFile) {
            self.target = target
        }
    }
    
    struct Trace: Equatable, Codable {
        public var target: ESProcess
        
        public init(target: ESProcess) {
            self.target = target
        }
    }
    
    struct Truncate: Equatable, Codable {
        public var target: ESFile
        
        public init(target: ESFile) {
            self.target = target
        }
    }
    
    struct UipcBind: Equatable, Codable {
        public var dir: ESFile
        public var filename: String
        public var mode: mode_t
        
        public init(dir: ESFile, filename: String, mode: mode_t) {
            self.dir = dir
            self.filename = filename
            self.mode = mode
        }
    }
    
    struct UipcConnect: Equatable, Codable {
        public var file: ESFile
        public var domain: Int32
        public var type: Int32
        public var `protocol`: Int32
        
        public init(file: ESFile, domain: Int32, type: Int32, protocol: Int32) {
            self.file = file
            self.domain = domain
            self.type = type
            self.protocol = `protocol`
        }
    }
    
    struct Unlink: Equatable, Codable {
        public var target: ESFile
        public var parentDir: ESFile
        
        public init(target: ESFile, parentDir: ESFile) {
            self.target = target
            self.parentDir = parentDir
        }
    }
    
    struct Unmount: Equatable, Codable {
        public var statfs: statfs
        
        public init(statfs: statfs) {
            self.statfs = statfs
        }
    }
    
    struct Utimes: Equatable, Codable {
        public var target: ESFile
        public var aTime: timespec
        public var mTime: timespec
        
        public init(target: ESFile, aTime: timespec, mTime: timespec) {
            self.target = target
            self.aTime = aTime
            self.mTime = mTime
        }
    }
    
    struct Write: Equatable, Codable {
        public var target: ESFile
        
        public init(target: ESFile) {
            self.target = target
        }
    }
}

extension ESEvent.Create.Destination {
    public var path: String {
        switch self {
        case .existingFile(let file):
            return file.path
        case .newPath(let dir, let filename, _):
            return dir.path.appendingPathComponent(filename)
        }
    }
}

extension ESEvent.Rename.Destination {
    public var path: String {
        switch self {
        case .existingFile(let file):
            return file.path
        case .newPath(let dir, let filename):
            return dir.path.appendingPathComponent(filename)
        }
    }
}
