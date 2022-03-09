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
import SwiftConvenience


public struct ESMessage: Equatable {
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
    
    public enum Action: Equatable {
        case auth
        case notify(ESAuthResult)
    }
}

public struct ESFile: Equatable {
    public var path: String
    public var truncated: Bool
    public var stat: stat
}

public struct ESProcess: Equatable {
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
}

public struct ESAuthResult: Equatable, Codable, RawRepresentable {
    public static func auth(_ auth: Bool) -> ESAuthResult { .init(rawValue: auth ? .max : 0) }
    public static func flags(_ flags: UInt32) -> ESAuthResult { .init(rawValue: flags) }
    
    public var rawValue: UInt32
    
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
}

public struct ESThread: Equatable {
    public var threadID: UInt64
}

public struct ESThreadState: Equatable {
    public var flavor: Int32
    public var state: Data
}

public enum ESEvent: Equatable {
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
    struct Access: Equatable {
        public var mode: Int32
        public var target: ESFile
    }
    
    struct Chdir: Equatable {
        public var target: ESFile
    }
    
    struct Chroot: Equatable {
        public var target: ESFile
    }
    
    struct Clone: Equatable {
        public var source: ESFile
        public var targetDir: ESFile
        public var targetName: String
    }
    
    struct CopyFile: Equatable {
        public var source: ESFile
        public var targetFile: ESFile?
        public var targetDir: ESFile
        public var targetName: String
        public var mode: mode_t
        public var flags: Int32
    }
    
    struct Close: Equatable {
        public var modified: Bool
        public var target: ESFile
    }
    
    struct Create: Equatable {
        public var destination: Destination
        
        // currently not supported
        // public var acl: acl_t? /* field available only if message version >= 2 */
        
        public enum Destination: Equatable {
            case existingFile(ESFile)
            case newPath(dir: ESFile, filename: String, mode: mode_t)
        }
    }
    
    struct DeleteExtAttr: Equatable {
        public var target: ESFile
        public var extattr: String
    }
    
    struct Dup: Equatable {
        public var target: ESFile
    }
    
    struct ExchangeData: Equatable {
        public var file1: ESFile
        public var file2: ESFile
    }
    
    struct Exec: Equatable {
        public var target: ESProcess
        public var script: ESFile? /* field available only if message version >= 2 */
        public var cwd: ESFile? /* field available only if message version >= 3 */
        public var lastFD: Int32? /* field available only if message version >= 4 */
    }
    
    struct Exit: Equatable {
        public var status: Int32
    }
    
    struct FileProviderMaterialize: Equatable {
        public var instigator: ESProcess
        public var source: ESFile
        public var target: ESFile
    }
    
    struct FileProviderUpdate: Equatable {
        public var source: ESFile
        public var targetPath: String
    }
    
    struct Fcntl: Equatable {
        public var target: ESFile
        public var cmd: Int32
    }
    
    struct Fork: Equatable {
        public var child: ESProcess
    }
    
    struct FsGetPath: Equatable {
        public var target: ESFile
    }
    
    struct GetTask: Equatable {
        public var target: ESProcess
    }
    
    struct GetTaskRead: Equatable {
        public var target: ESProcess
    }
    
    struct GetTaskInspect: Equatable {
        public var target: ESProcess
    }
    
    struct GetTaskName: Equatable {
        public var target: ESProcess
    }
    
    struct GetAttrList: Equatable {
        public var attrlist: attrlist
        public var target: ESFile
    }
    
    struct GetExtAttr: Equatable {
        public var target: ESFile
        public var extattr: String
    }
    
    struct IOKitOpen: Equatable {
        public var userClientType: UInt32
        public var userClientClass: String
    }
    
    struct KextLoad: Equatable {
        public var identifier: String
    }
    
    struct KextUnload: Equatable {
        public var identifier: String
    }
    
    struct Link: Equatable {
        public var source: ESFile
        public var targetDir: ESFile
        public var targetFilename: String
    }
    
    struct ListExtAttr: Equatable {
        public var target: ESFile
    }
    
    struct Lookup: Equatable {
        public var sourceDir: ESFile
        public var relativeTarget: String
    }
    
    struct MMap: Equatable {
        public var protection: Int32
        public var maxProtection: Int32
        public var flags: Int32
        public var filePos: UInt64
        public var source: ESFile
    }
    
    struct Mount: Equatable {
        public var statfs: statfs
    }
    
    struct MProtect: Equatable {
        public var protection: Int32
        public var address: user_addr_t
        public var size: user_size_t
    }
    
    struct Open: Equatable {
        public var fflag: Int32
        public var file: ESFile
    }
    
    struct ProcCheck: Equatable {
        public var target: ESProcess?
        public var type: es_proc_check_type_t
        public var flavor: Int32
    }
    
    struct ProcSuspendResume: Equatable {
        public var target: ESProcess?
        public var type: es_proc_suspend_resume_type_t
    }
    
    struct PtyClose: Equatable {
        public var dev: dev_t
    }
    
    struct PtyGrant: Equatable {
        public var dev: dev_t
    }
    
    struct Readdir: Equatable {
        public var target: ESFile
    }
    
    struct Readlink: Equatable {
        public var source: ESFile
    }
    
    struct RemoteThreadCreate: Equatable {
        public var target: ESProcess
        public var threadState: ESThreadState?
    }
    
    struct Remount: Equatable {
        public var statfs: statfs
    }
    
    struct Rename: Equatable {
        public var source: ESFile
        public var destination: Destination
        
        public enum Destination: Equatable {
            case existingFile(ESFile)
            case newPath(dir: ESFile, filename: String)
        }
    }
    
    struct SearchFS: Equatable {
        public var attrlist: attrlist
        public var target: ESFile
    }
    
    struct SetACL: Equatable {
        public var target: ESFile
        public var setOrClear: es_set_or_clear_t
        
        //  currently not supported
        //  public var acl: acl_t
    }
    
    struct SetAttrList: Equatable {
        public var attrlist: attrlist
        public var target: ESFile
    }
    
    struct SetExtAttr: Equatable {
        public var target: ESFile
        public var extattr: String
    }
    
    struct SetFlags: Equatable {
        public var flags: UInt32
        public var target: ESFile
    }
    
    struct SetMode: Equatable {
        public var mode: mode_t
        public var target: ESFile
    }
    
    struct SetOwner: Equatable {
        public var uid: uid_t
        public var gid: gid_t
        public var target: ESFile
    }
    
    struct SetUID: Equatable {
        public var uid: uid_t
    }
    
    struct SetREUID: Equatable {
        public var ruid: uid_t
        public var euid: uid_t
    }
    
    struct Signal: Equatable {
        public var sig: Int32
        public var target: ESProcess
    }
    
    struct Stat: Equatable {
        public var target: ESFile
    }
    
    struct Trace: Equatable {
        public var target: ESProcess
    }
    
    struct Truncate: Equatable {
        public var target: ESFile
    }
    
    struct UipcBind: Equatable {
        public var dir: ESFile
        public var filename: String
        public var mode: mode_t
    }
    
    struct UipcConnect: Equatable {
        public var file: ESFile
        public var domain: Int32
        public var type: Int32
        public var `protocol`: Int32
    }
    
    struct Unlink: Equatable {
        public var target: ESFile
        public var parentDir: ESFile
    }
    
    struct Unmount: Equatable {
        public var statfs: statfs;
    }
    
    struct Utimes: Equatable {
        public var target: ESFile
        public var aTime: timespec;
        public var mTime: timespec;
    }
    
    struct Write: Equatable {
        public var target: ESFile
    }
}
