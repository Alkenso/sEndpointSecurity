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
    
    public init(version: UInt32, time: timespec, machTime: UInt64, deadline: UInt64, process: ESProcess, seqNum: UInt64?, action: ESMessage.Action, event: ESEvent, eventType: es_event_type_t, thread: ESThread?, globalSeqNum: UInt64?) {
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
    
    public init(auditToken: audit_token_t, ppid: pid_t, originalPpid: pid_t, groupID: pid_t, sessionID: pid_t, codesigningFlags: UInt32, isPlatformBinary: Bool, isESClient: Bool, cdHash: Data, signingID: String, teamID: String, executable: ESFile, tty: ESFile?, startTime: timeval?, responsibleAuditToken: audit_token_t?, parentAuditToken: audit_token_t?) {
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

public struct BTMLaunchItem: Equatable, Codable {
    public var itemType: es_btm_item_type_t
    public var legacy: Bool
    public var managed: Bool
    public var uid: uid_t
    public var itemURL: String
    public var appURL: String
    
    public init(itemType: es_btm_item_type_t, legacy: Bool, managed: Bool, uid: uid_t, itemURL: String, appURL: String) {
        self.itemType = itemType
        self.legacy = legacy
        self.managed = managed
        self.uid = uid
        self.itemURL = itemURL
        self.appURL = appURL
    }
}

public enum ESEvent: Equatable, Codable {
    case access(Access)
    case authentication(Authentication)
    case btmLaunchItemAdd(BTMLaunchItemAdd)
    case btmLaunchItemRemove(BTMLaunchItemRemove)
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
    case loginLogin(LoginLogin)
    case loginLogout(LoginLogout)
    case lookup(Lookup)
    case lwSessionLogin(LWSessionLogin)
    case lwSessionLogout(LWSessionLogout)
    case lwSessionLock(LWSessionLock)
    case lwSessionUnlock(LWSessionUnlock)
    case mmap(MMap)
    case mount(Mount)
    case mprotect(MProtect)
    case open(Open)
    case opensshLogin(OpensshLogin)
    case opensshLogout(OpensshLogout)
    case procCheck(ProcCheck)
    case procSuspendResume(ProcSuspendResume)
    case ptyClose(PtyClose)
    case ptyGrant(PtyGrant)
    case readdir(Readdir)
    case readlink(Readlink)
    case remoteThreadCreate(RemoteThreadCreate)
    case remount(Remount)
    case rename(Rename)
    case screensharingAttach(ScreensharingAttach)
    case screensharingDetach(ScreensharingDetach)
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
    case xpMalwareDetected(XPMalwareDetected)
    case xpMalwareRemediated(XPMalwareRemediated)
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
    
    struct Authentication: Equatable, Codable {
        public var success: Bool
        public var type: AuthenticationType
        
        public init(success: Bool, type: AuthenticationType) {
            self.success = success
            self.type = type
        }
    }
    
    enum AuthenticationType: Equatable, Codable {
        case od(OD)
        case touchID(TouchID)
        case token(Token)
        case autoUnlock(AutoUnlock)
        
        public struct OD: Equatable, Codable {
            public var instigator: ESProcess
            public var recordType: String
            public var recordName: String
            public var nodeName: String
            public var dbPath: String
            
            public init(instigator: ESProcess, recordType: String, recordName: String, nodeName: String, dbPath: String) {
                self.instigator = instigator
                self.recordType = recordType
                self.recordName = recordName
                self.nodeName = nodeName
                self.dbPath = dbPath
            }
        }
        
        public struct TouchID: Equatable, Codable {
            public var instigator: ESProcess
            public var touchIDMode: es_touchid_mode_t
            public var uid: uid_t?
            
            public init(instigator: ESProcess, touchIDMode: es_touchid_mode_t, uid: uid_t?) {
                self.instigator = instigator
                self.touchIDMode = touchIDMode
                self.uid = uid
            }
        }
        
        public struct Token: Equatable, Codable {
            public var instigator: ESProcess
            public var pubkeyHash: String
            public var tokenID: String
            public var kerberosPrincipal: String
            
            public init(instigator: ESProcess, pubkeyHash: String, tokenID: String, kerberosPrincipal: String) {
                self.instigator = instigator
                self.pubkeyHash = pubkeyHash
                self.tokenID = tokenID
                self.kerberosPrincipal = kerberosPrincipal
            }
        }
        
        public struct AutoUnlock: Equatable, Codable {
            public var username: String
            public var type: es_auto_unlock_type_t
            
            public init(username: String, type: es_auto_unlock_type_t) {
                self.username = username
                self.type = type
            }
        }
    }
    
    struct BTMLaunchItemAdd: Equatable, Codable {
        public var instigator: ESProcess?
        public var app: ESProcess?
        public var item: BTMLaunchItem
        public var executablePath: String
        
        public init(instigator: ESProcess?, app: ESProcess?, item: BTMLaunchItem, executablePath: String) {
            self.instigator = instigator
            self.app = app
            self.item = item
            self.executablePath = executablePath
        }
    }
    
    struct BTMLaunchItemRemove: Equatable, Codable {
        public var instigator: ESProcess?
        public var app: ESProcess?
        public var item: BTMLaunchItem
        
        public init(instigator: ESProcess?, app: ESProcess?, item: BTMLaunchItem) {
            self.instigator = instigator
            self.app = app
            self.item = item
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
        
        public init(source: ESFile, targetFile: ESFile?, targetDir: ESFile, targetName: String, mode: mode_t, flags: Int32) {
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
        
        public init(target: ESProcess, script: ESFile?, cwd: ESFile?, lastFD: Int32?) {
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
    
    struct LoginLogin: Equatable, Codable {
        public var success: Bool
        public var failureMessage: String
        public var username: String
        public var uid: uid_t?
        
        public init(success: Bool, failureMessage: String, username: String, uid: uid_t?) {
            self.success = success
            self.failureMessage = failureMessage
            self.username = username
            self.uid = uid
        }
    }
    
    struct LoginLogout: Equatable, Codable {
        public var username: String
        public var uid: uid_t
        
        public init(username: String, uid: uid_t) {
            self.username = username
            self.uid = uid
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
    
    struct LWSessionLogin: Equatable, Codable {
        public var username: String
        public var graphicalSessionID: es_graphical_session_id_t
        
        public init(username: String, graphicalSessionID: es_graphical_session_id_t) {
            self.username = username
            self.graphicalSessionID = graphicalSessionID
        }
    }
    
    typealias LWSessionLogout = LWSessionLogin
    typealias LWSessionLock = LWSessionLogin
    typealias LWSessionUnlock = LWSessionLogin
    
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
    
    struct OpensshLogin: Equatable, Codable {
        public var success: Bool
        public var resultType: es_openssh_login_result_type_t
        public var sourceAddressType: es_address_type_t
        public var sourceAddress: String
        public var username: String
        public var uid: uid_t?
        
        public init(success: Bool, resultType: es_openssh_login_result_type_t, sourceAddressType: es_address_type_t, sourceAddress: String, username: String, uid: uid_t?) {
            self.success = success
            self.resultType = resultType
            self.sourceAddressType = sourceAddressType
            self.sourceAddress = sourceAddress
            self.username = username
            self.uid = uid
        }
    }
    
    struct OpensshLogout: Equatable, Codable {
        public var sourceAddressType: es_address_type_t
        public var sourceAddress: String
        public var username: String
        public var uid: uid_t
        
        public init(sourceAddressType: es_address_type_t, sourceAddress: String, username: String, uid: uid_t) {
            self.sourceAddressType = sourceAddressType
            self.sourceAddress = sourceAddress
            self.username = username
            self.uid = uid
        }
    }
    
    struct ProcCheck: Equatable, Codable {
        public var target: ESProcess?
        public var type: es_proc_check_type_t
        public var flavor: Int32
        
        public init(target: ESProcess?, type: es_proc_check_type_t, flavor: Int32) {
            self.target = target
            self.type = type
            self.flavor = flavor
        }
    }
    
    struct ProcSuspendResume: Equatable, Codable {
        public var target: ESProcess?
        public var type: es_proc_suspend_resume_type_t
        
        public init(target: ESProcess?, type: es_proc_suspend_resume_type_t) {
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
        
        public init(target: ESProcess, threadState: ESThreadState?) {
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
    
    struct ScreensharingAttach: Equatable, Codable {
        public var success: Bool
        public var sourceAddressType: es_address_type_t
        public var sourceAddress: String
        public var viewerAppleID: String
        public var authenticationType: String
        public var authenticationUsername: String
        public var sessionUsername: String
        public var existingSession: Bool
        public var graphicalSessionID: es_graphical_session_id_t
        
        public init(success: Bool, sourceAddressType: es_address_type_t, sourceAddress: String, viewerAppleID: String, authenticationType: String, authenticationUsername: String, sessionUsername: String, existingSession: Bool, graphicalSessionID: es_graphical_session_id_t) {
            self.success = success
            self.sourceAddressType = sourceAddressType
            self.sourceAddress = sourceAddress
            self.viewerAppleID = viewerAppleID
            self.authenticationType = authenticationType
            self.authenticationUsername = authenticationUsername
            self.sessionUsername = sessionUsername
            self.existingSession = existingSession
            self.graphicalSessionID = graphicalSessionID
        }
    }
    
    struct ScreensharingDetach: Equatable, Codable {
        public var sourceAddressType: es_address_type_t
        public var sourceAddress: String
        public var viewerAppleID: String
        public var graphicalSessionID: es_graphical_session_id_t
        
        public init(sourceAddressType: es_address_type_t, sourceAddress: String, viewerAppleID: String, graphicalSessionID: es_graphical_session_id_t) {
            self.sourceAddressType = sourceAddressType
            self.sourceAddress = sourceAddress
            self.viewerAppleID = viewerAppleID
            self.graphicalSessionID = graphicalSessionID
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
    
    struct XPMalwareDetected: Equatable, Codable {
        public var signatureVersion: String
        public var malwareIdentifier: String
        public var incidentIdentifier: String
        public var detectedPath: String
        
        public init(signatureVersion: String, malwareIdentifier: String, incidentIdentifier: String, detectedPath: String) {
            self.signatureVersion = signatureVersion
            self.malwareIdentifier = malwareIdentifier
            self.incidentIdentifier = incidentIdentifier
            self.detectedPath = detectedPath
        }
    }
    
    struct XPMalwareRemediated: Equatable, Codable {
        public var signatureVersion: String
        public var malwareIdentifier: String
        public var incidentIdentifier: String
        public var actionType: String
        public var success: Bool
        public var resultDescription: String
        public var remediatedPath: String
        public var remediatedProcessAuditToken: audit_token_t?
        
        public init(signatureVersion: String, malwareIdentifier: String, incidentIdentifier: String, actionType: String, success: Bool, resultDescription: String, remediatedPath: String, remediatedProcessAuditToken: audit_token_t?) {
            self.signatureVersion = signatureVersion
            self.malwareIdentifier = malwareIdentifier
            self.incidentIdentifier = incidentIdentifier
            self.actionType = actionType
            self.success = success
            self.resultDescription = resultDescription
            self.remediatedPath = remediatedPath
            self.remediatedProcessAuditToken = remediatedProcessAuditToken
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
