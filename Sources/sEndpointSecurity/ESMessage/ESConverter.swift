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

public struct ESConverter {
    public var version: UInt32
    public var config: Config
    
    public init(version: UInt32, config: Config = .default) {
        self.version = version
        self.config = config
    }
}

extension ESConverter {
    public struct Config: Equatable, Codable {
        public var execArgs: Bool
        public var execEnv: Bool
        
        public init(execArgs: Bool, execEnv: Bool) {
            self.execArgs = execArgs
            self.execEnv = execEnv
        }
    }
}

extension ESConverter.Config {
    public static let `default` = Self(execArgs: false, execEnv: false)
    public static let full = Self(execArgs: true, execEnv: true)
}

public extension ESConverter {
    static func esMessage(_ es: es_message_t, config: Config) throws -> ESMessage {
        let version = es.version
        let converter = ESConverter(version: version, config: config)
        return try ESMessage(
            version: es.version,
            time: es.time,
            machTime: es.mach_time,
            deadline: es.deadline,
            process: converter.esProcess(es.process.pointee),
            seqNum: version >= 2 ? es.seq_num : nil, /* field available only if message version >= 2 */
            action: converter.esAction(es.action_type, es.action),
            event: converter.esEvent(es.event_type, es.event),
            eventType: es.event_type,
            thread: version >= 4 ? es.thread.map(\.pointee).flatMap(converter.esThread) : nil, /* field available only if message version >= 4 */
            globalSeqNum: version >= 4 ? es.global_seq_num : nil /* field available only if message version >= 4 */
        )
    }
}

public extension ESConverter {
    func esString(_ es: es_string_token_t) -> String {
        es.length > 0 ? String(cString: es.data) : ""
    }
    
    func esToken(_ es: es_token_t) -> Data {
        Data(bytes: es.data, count: es.size)
    }
    
    func esFile(_ es: es_file_t) -> ESFile {
        let path = esString(es.path)
        return ESFile(path: path, truncated: es.path_truncated, stat: es.stat)
    }
    
    func esFile(_ es: UnsafeMutablePointer<es_file_t>) -> ESFile {
        esFile(es.pointee)
    }
    
    func esProcess(_ es: es_process_t) -> ESProcess {
        ESProcess(
            auditToken: es.audit_token,
            ppid: es.ppid,
            originalPpid: es.original_ppid,
            groupID: es.group_id,
            sessionID: es.session_id,
            codesigningFlags: es.codesigning_flags,
            isPlatformBinary: es.is_platform_binary,
            isESClient: es.is_es_client,
            cdHash: withUnsafeBytes(of: es.cdhash) { Data($0) },
            signingID: esString(es.signing_id),
            teamID: esString(es.team_id),
            executable: esFile(es.executable),
            tty: version >= 2 ? es.tty.flatMap(esFile) : nil, /* field available only if message version >= 2 */
            startTime: version >= 3 ? es.start_time : nil, /* field available only if message version >= 3 */
            responsibleAuditToken: version >= 4 ? es.responsible_audit_token : nil, /* field available only if message version >= 4 */
            parentAuditToken: version >= 4 ? es.parent_audit_token : nil /* field available only if message version >= 4 */
        )
    }
    
    func esProcess(_ es: UnsafeMutablePointer<es_process_t>) -> ESProcess {
        esProcess(es.pointee)
    }
    
    func esThread(_ es: es_thread_t) -> ESThread {
        ESThread(threadID: es.thread_id)
    }
    
    func esThreadState(_ es: es_thread_state_t) throws -> ESThreadState {
        ESThreadState(flavor: es.flavor, state: esToken(es.state))
    }
    
    func esAuthResult(_ es: es_result_t) throws -> ESAuthResult {
        switch es.result_type {
        case ES_RESULT_TYPE_AUTH:
            switch es.result.auth {
            case ES_AUTH_RESULT_ALLOW:
                return .auth(true)
            case ES_AUTH_RESULT_DENY:
                return .auth(false)
            default:
                throw CommonError.invalidArgument(arg: "es_auth_result_t", invalidValue: es.result.auth)
            }
        case ES_RESULT_TYPE_FLAGS:
            return .flags(es.result.flags)
        default:
            throw CommonError.invalidArgument(arg: "es_result_type_t", invalidValue: es.result_type)
        }
    }
    
    func esAction(_ type: es_action_type_t, _ action: es_message_t.__Unnamed_union_action) throws -> ESMessage.Action {
        switch type {
        case ES_ACTION_TYPE_AUTH:
            return .auth
        case ES_ACTION_TYPE_NOTIFY:
            return try .notify(esAuthResult(action.notify))
        default:
            throw CommonError.invalidArgument(arg: "es_action_type_t", invalidValue: type)
        }
    }
    
    func esBTMLaunchItem(_ es: UnsafePointer<es_btm_launch_item_t>) -> BTMLaunchItem {
        .init(
            itemType: es.pointee.item_type,
            legacy: es.pointee.legacy,
            managed: es.pointee.managed,
            uid: es.pointee.uid,
            itemURL: esString(es.pointee.item_url),
            appURL: esString(es.pointee.app_url)
        )
    }

    func esProfile(_ es: es_profile_t) -> ESProfile {
        .init(
            identifier: esString(es.identifier),
            uuid: esString(es.uuid),
            installSource: es.install_source,
            organization: esString(es.organization),
            displayName: esString(es.display_name),
            scope: esString(es.scope)
        )
    }
    
    func esODMemberID(_ es: UnsafePointer<es_od_member_id_t>) throws -> ESODMemberID {
        switch es.pointee.member_type {
        case ES_OD_MEMBER_TYPE_USER_NAME:
            return .userName(esString(es.pointee.member_value.name))
        case ES_OD_MEMBER_TYPE_USER_UUID:
            return .userUUID(UUID(uuid: es.pointee.member_value.uuid))
        case ES_OD_MEMBER_TYPE_GROUP_UUID:
            return .groupUUID(UUID(uuid: es.pointee.member_value.uuid))
        default:
            throw CommonError.invalidArgument(arg: "es_od_member_id_t", invalidValue: es.pointee.member_type)
        }
    }
    
    func esODMemberIDs(_ es: UnsafePointer<es_od_member_id_array_t>) throws -> [ESODMemberID] {
        switch es.pointee.member_type {
        case ES_OD_MEMBER_TYPE_USER_NAME:
            return UnsafeBufferPointer(start: es.pointee.member_array.names, count: es.pointee.member_count).map {
                .userName(esString($0))
            }
        case ES_OD_MEMBER_TYPE_USER_UUID:
            return UnsafeBufferPointer(start: es.pointee.member_array.uuids, count: es.pointee.member_count).map {
                .userUUID(UUID(uuid: $0))
            }
        case ES_OD_MEMBER_TYPE_GROUP_UUID:
            return UnsafeBufferPointer(start: es.pointee.member_array.uuids, count: es.pointee.member_count).map {
                .groupUUID(UUID(uuid: $0))
            }
        default:
            throw CommonError.invalidArgument(arg: "es_od_member_id_t", invalidValue: es.pointee.member_type)
        }
    }
    
    func esEvent(_ type: es_event_type_t, _ event: es_events_t) throws -> ESEvent {
        switch type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            return .exec(esEvent(exec: event.exec))
        case ES_EVENT_TYPE_AUTH_OPEN:
            return .open(esEvent(open: event.open))
        case ES_EVENT_TYPE_AUTH_KEXTLOAD:
            return .kextload(esEvent(kextload: event.kextload))
        case ES_EVENT_TYPE_AUTH_MMAP:
            return .mmap(esEvent(mmap: event.mmap))
        case ES_EVENT_TYPE_AUTH_MPROTECT:
            return .mprotect(esEvent(mprotect: event.mprotect))
        case ES_EVENT_TYPE_AUTH_MOUNT:
            return .mount(esEvent(mount: event.mount))
        case ES_EVENT_TYPE_AUTH_RENAME:
            return try .rename(esEvent(rename: event.rename))
        case ES_EVENT_TYPE_AUTH_SIGNAL:
            return .signal(esEvent(signal: event.signal))
        case ES_EVENT_TYPE_AUTH_UNLINK:
            return .unlink(esEvent(unlink: event.unlink))
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            return .exec(esEvent(exec: event.exec))
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            return .open(esEvent(open: event.open))
        case ES_EVENT_TYPE_NOTIFY_FORK:
            return .fork(esEvent(fork: event.fork))
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            return .close(esEvent(close: event.close))
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            return try .create(esEvent(create: event.create))
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            return .exchangedata(esEvent(exchangedata: event.exchangedata))
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return .exit(esEvent(exit: event.exit))
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            return .getTask(esEvent(get_task: event.get_task))
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            return .kextload(esEvent(kextload: event.kextload))
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            return .kextunload(esEvent(kextunload: event.kextunload))
        case ES_EVENT_TYPE_NOTIFY_LINK:
            return .link(esEvent(link: event.link))
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            return .mmap(esEvent(mmap: event.mmap))
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            return .mprotect(esEvent(mprotect: event.mprotect))
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            return .mount(esEvent(mount: event.mount))
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            return .unmount(esEvent(unmount: event.unmount))
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            return .iokitOpen(esEvent(iokit_open: event.iokit_open))
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            return try .rename(esEvent(rename: event.rename))
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            return .setattrlist(esEvent(setattrlist: event.setattrlist))
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            return .setextattr(esEvent(setextattr: event.setextattr))
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            return .setflags(esEvent(setflags: event.setflags))
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            return .setmode(esEvent(setmode: event.setmode))
        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            return .setowner(esEvent(setowner: event.setowner))
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            return .signal(esEvent(signal: event.signal))
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            return .unlink(esEvent(unlink: event.unlink))
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            return .write(esEvent(write: event.write))
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE:
            return .fileProviderMaterialize(esEvent(file_provider_materialize: event.file_provider_materialize))
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
            return .fileProviderMaterialize(esEvent(file_provider_materialize: event.file_provider_materialize))
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE:
            return .fileProviderUpdate(esEvent(file_provider_update: event.file_provider_update))
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
            return .fileProviderUpdate(esEvent(file_provider_update: event.file_provider_update))
        case ES_EVENT_TYPE_AUTH_READLINK:
            return .readlink(esEvent(readlink: event.readlink))
        case ES_EVENT_TYPE_NOTIFY_READLINK:
            return .readlink(esEvent(readlink: event.readlink))
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            return .truncate(esEvent(truncate: event.truncate))
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            return .truncate(esEvent(truncate: event.truncate))
        case ES_EVENT_TYPE_AUTH_LINK:
            return .link(esEvent(link: event.link))
        case ES_EVENT_TYPE_NOTIFY_LOOKUP:
            return .lookup(esEvent(lookup: event.lookup))
        case ES_EVENT_TYPE_AUTH_CREATE:
            return try .create(esEvent(create: event.create))
        case ES_EVENT_TYPE_AUTH_SETATTRLIST:
            return .setattrlist(esEvent(setattrlist: event.setattrlist))
        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
            return .setextattr(esEvent(setextattr: event.setextattr))
        case ES_EVENT_TYPE_AUTH_SETFLAGS:
            return .setflags(esEvent(setflags: event.setflags))
        case ES_EVENT_TYPE_AUTH_SETMODE:
            return .setmode(esEvent(setmode: event.setmode))
        case ES_EVENT_TYPE_AUTH_SETOWNER:
            return .setowner(esEvent(setowner: event.setowner))
        case ES_EVENT_TYPE_AUTH_CHDIR:
            return .chdir(esEvent(chdir: event.chdir))
        case ES_EVENT_TYPE_NOTIFY_CHDIR:
            return .chdir(esEvent(chdir: event.chdir))
        case ES_EVENT_TYPE_AUTH_GETATTRLIST:
            return .getattrlist(esEvent(getattrlist: event.getattrlist))
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
            return .getattrlist(esEvent(getattrlist: event.getattrlist))
        case ES_EVENT_TYPE_NOTIFY_STAT:
            return .stat(esEvent(stat: event.stat))
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            return .access(esEvent(access: event.access))
        case ES_EVENT_TYPE_AUTH_CHROOT:
            return .chroot(esEvent(chroot: event.chroot))
        case ES_EVENT_TYPE_NOTIFY_CHROOT:
            return .chroot(esEvent(chroot: event.chroot))
        case ES_EVENT_TYPE_AUTH_UTIMES:
            return .utimes(esEvent(utimes: event.utimes))
        case ES_EVENT_TYPE_NOTIFY_UTIMES:
            return .utimes(esEvent(utimes: event.utimes))
        case ES_EVENT_TYPE_AUTH_CLONE:
            return .clone(esEvent(clone: event.clone))
        case ES_EVENT_TYPE_NOTIFY_CLONE:
            return .clone(esEvent(clone: event.clone))
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            return .fcntl(esEvent(fcntl: event.fcntl))
        case ES_EVENT_TYPE_AUTH_GETEXTATTR:
            return .getextattr(esEvent(getextattr: event.getextattr))
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
            return .getextattr(esEvent(getextattr: event.getextattr))
        case ES_EVENT_TYPE_AUTH_LISTEXTATTR:
            return .listextattr(esEvent(listextattr: event.listextattr))
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
            return .listextattr(esEvent(listextattr: event.listextattr))
        case ES_EVENT_TYPE_AUTH_READDIR:
            return .readdir(esEvent(readdir: event.readdir))
        case ES_EVENT_TYPE_NOTIFY_READDIR:
            return .readdir(esEvent(readdir: event.readdir))
        case ES_EVENT_TYPE_AUTH_DELETEEXTATTR:
            return .deleteextattr(esEvent(deleteextattr: event.deleteextattr))
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            return .deleteextattr(esEvent(deleteextattr: event.deleteextattr))
        case ES_EVENT_TYPE_AUTH_FSGETPATH:
            return .fsgetpath(esEvent(fsgetpath: event.fsgetpath))
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
            return .fsgetpath(esEvent(fsgetpath: event.fsgetpath))
        case ES_EVENT_TYPE_NOTIFY_DUP:
            return .dup(esEvent(dup: event.dup))
        case ES_EVENT_TYPE_AUTH_SETTIME:
            return .settime
        case ES_EVENT_TYPE_NOTIFY_SETTIME:
            return .settime
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
            return .uipcBind(esEvent(uipc_bind: event.uipc_bind))
        case ES_EVENT_TYPE_AUTH_UIPC_BIND:
            return .uipcBind(esEvent(uipc_bind: event.uipc_bind))
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            return .uipcConnect(esEvent(uipc_connect: event.uipc_connect))
        case ES_EVENT_TYPE_AUTH_UIPC_CONNECT:
            return .uipcConnect(esEvent(uipc_connect: event.uipc_connect))
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            return .exchangedata(esEvent(exchangedata: event.exchangedata))
        case ES_EVENT_TYPE_AUTH_SETACL:
            return .setacl(esEvent(setacl: event.setacl))
        case ES_EVENT_TYPE_NOTIFY_SETACL:
            return .setacl(esEvent(setacl: event.setacl))
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
            return .ptyGrant(esEvent(pty_grant: event.pty_grant))
        case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
            return .ptyClose(esEvent(pty_close: event.pty_close))
        case ES_EVENT_TYPE_AUTH_PROC_CHECK:
            return .procCheck(esEvent(proc_check: event.proc_check))
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            return .procCheck(esEvent(proc_check: event.proc_check))
        case ES_EVENT_TYPE_AUTH_GET_TASK:
            return .getTask(esEvent(get_task: event.get_task))
        case ES_EVENT_TYPE_AUTH_SEARCHFS:
            return .searchfs(esEvent(searchfs: event.searchfs))
        case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
            return .searchfs(esEvent(searchfs: event.searchfs))
        case ES_EVENT_TYPE_AUTH_FCNTL:
            return .fcntl(esEvent(fcntl: event.fcntl))
        case ES_EVENT_TYPE_AUTH_IOKIT_OPEN:
            return .iokitOpen(esEvent(iokit_open: event.iokit_open))
        case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
            return .procSuspendResume(esEvent(proc_suspend_resume: event.proc_suspend_resume))
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
            return .procSuspendResume(esEvent(proc_suspend_resume: event.proc_suspend_resume))
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            return .csInvalidated
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
            return .getTaskName(esEvent(get_task_name: event.get_task_name))
        case ES_EVENT_TYPE_NOTIFY_TRACE:
            return .trace(esEvent(trace: event.trace))
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            return try .remoteThreadCreate(esEvent(remote_thread_create: event.remote_thread_create))
        case ES_EVENT_TYPE_AUTH_REMOUNT:
            return .remount(esEvent(remount: event.remount))
        case ES_EVENT_TYPE_NOTIFY_REMOUNT:
            return .remount(esEvent(remount: event.remount))
        case ES_EVENT_TYPE_AUTH_GET_TASK_READ:
            return .getTaskRead(esEvent(get_task_read: event.get_task_read))
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            return .getTaskRead(esEvent(get_task_read: event.get_task_read))
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
            return .getTaskInspect(esEvent(get_task_inspect: event.get_task_inspect))
        case ES_EVENT_TYPE_NOTIFY_SETUID:
            return .setuid(esEvent(setuid: event.setuid))
        case ES_EVENT_TYPE_NOTIFY_SETGID:
            return .setuid(esEvent(setgid: event.setgid))
        case ES_EVENT_TYPE_NOTIFY_SETEUID:
            return .setuid(esEvent(seteuid: event.seteuid))
        case ES_EVENT_TYPE_NOTIFY_SETEGID:
            return .setuid(esEvent(setegid: event.setegid))
        case ES_EVENT_TYPE_NOTIFY_SETREUID:
            return .setreuid(esEvent(setreuid: event.setreuid))
        case ES_EVENT_TYPE_NOTIFY_SETREGID:
            return .setreuid(esEvent(setregid: event.setregid))
        case ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_NOTIFY_COPYFILE:
            return .copyfile(esEvent(copyfile: event.copyfile))
        // macOS 13.0:
        case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION:
            return try .authentication(esEvent(authentication: event.authentication))
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
            return .xpMalwareDetected(esEvent(xpMalwareDetected: event.xp_malware_detected))
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
            return .xpMalwareRemediated(esEvent(xpMalwareRemediated: event.xp_malware_remediated))
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN:
            return .lwSessionLogin(esEvent(lwSessionLogin: event.lw_session_login))
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT:
            return .lwSessionLogout(esEvent(lwSessionLogout: event.lw_session_logout))
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK:
            return .lwSessionLock(esEvent(lwSessionLock: event.lw_session_lock))
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK:
            return .lwSessionUnlock(esEvent(lwSessionUnlock: event.lw_session_unlock))
        case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH:
            return .screensharingAttach(esEvent(screensharingAttach: event.screensharing_attach))
        case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH:
            return .screensharingDetach(esEvent(screensharingDetach: event.screensharing_detach))
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
            return .opensshLogin(esEvent(opensshLogin: event.openssh_login))
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
            return .opensshLogout(esEvent(opensshLogout: event.openssh_logout))
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
            return .loginLogin(esEvent(loginLogin: event.login_login))
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT:
            return .loginLogout(esEvent(loginLogout: event.login_logout))
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            return .btmLaunchItemAdd(esEvent(btmLaunchItemAdd: event.btm_launch_item_add))
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
            return .btmLaunchItemRemove(esEvent(btmLaunchItemRemove: event.btm_launch_item_remove))
        // macOS 14.0:
        case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD:
            return .profileAdd(esEvent(profileAdd: event.profile_add.pointee))
        case ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE:
            return .profileRemove(esEvent(profileRemove: event.profile_remove.pointee))
        case ES_EVENT_TYPE_NOTIFY_SU:
            return .su(esEvent(su: event.su.pointee))
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
            return .authorizationPetition(esEvent(authorizationPetition: event.authorization_petition.pointee))
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
            return .authorizationJudgement(esEvent(authorizationJudgement: event.authorization_judgement.pointee))
        case ES_EVENT_TYPE_NOTIFY_SUDO:
            return .sudo(esEvent(sudo: event.sudo.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD:
            return try .odGroupAdd(esEvent(odGroupAdd: event.od_group_add.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE:
            return try .odGroupRemove(esEvent(odGroupRemove: event.od_group_remove.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET:
            return try .odGroupSet(esEvent(odGroupSet: event.od_group_set.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD:
            return .odModifyPassword(esEvent(odModifyPassword: event.od_modify_password.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER:
            return .odDisableUser(esEvent(odDisableUser: event.od_disable_user.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER:
            return .odEnableUser(esEvent(odEnableUser: event.od_enable_user.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD:
            return .odAttributeValueAdd(esEvent(odAttributeValueAdd: event.od_attribute_value_add.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE:
            return .odAttributeValueRemove(esEvent(odAttributeValueRemove: event.od_attribute_value_remove.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET:
            return .odAttributeSet(esEvent(odAttributeSet: event.od_attribute_set.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER:
            return .odCreateUser(esEvent(odCreateUser: event.od_create_user.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP:
            return .odCreateGroup(esEvent(odCreateGroup: event.od_create_group.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER:
            return .odDeleteUser(esEvent(odDeleteUser: event.od_delete_user.pointee))
        case ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP:
            return .odDeleteGroup(esEvent(odDeleteGroup: event.od_delete_group.pointee))
        case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
            return .xpcConnect(esEvent(xpcConnect: event.xpc_connect.pointee))
        default:
            throw CommonError.invalidArgument(arg: "es_event_type_t", invalidValue: type)
        }
    }
    
    func esEvent(access es: es_event_access_t) -> ESEvent.Access {
        .init(mode: es.mode, target: esFile(es.target))
    }
    
    func esEvent(chdir es: es_event_chdir_t) -> ESEvent.Chdir {
        .init(target: esFile(es.target))
    }
    
    func esEvent(chroot es: es_event_chroot_t) -> ESEvent.Chroot {
        .init(target: esFile(es.target))
    }
    
    func esEvent(clone es: es_event_clone_t) -> ESEvent.Clone {
        .init(source: esFile(es.source), targetDir: esFile(es.target_dir), targetName: esString(es.target_name))
    }
    
    func esEvent(copyfile es: es_event_copyfile_t) -> ESEvent.CopyFile {
        .init(source: esFile(es.source), targetFile: es.target_file.flatMap(esFile), targetDir: esFile(es.target_dir), targetName: esString(es.target_name), mode: es.mode, flags: es.flags)
    }
    
    func esEvent(close es: es_event_close_t) -> ESEvent.Close {
        .init(modified: es.modified, target: esFile(es.target))
    }
    
    func esEvent(create es: es_event_create_t) throws -> ESEvent.Create {
        let destination: ESEvent.Create.Destination
        switch es.destination_type {
        case ES_DESTINATION_TYPE_NEW_PATH:
            destination = .newPath(
                dir: esFile(es.destination.new_path.dir),
                filename: esString(es.destination.new_path.filename),
                mode: es.destination.new_path.mode
            )
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            destination = .existingFile(esFile(es.destination.existing_file))
        default:
            throw CommonError.invalidArgument(arg: "es_destination_type_t", invalidValue: es.destination_type)
        }
        
        var acl: acl_t?
        if version >= 2 { /* field available only if message version >= 2 */
            acl = es.acl
        }
        
        return .init(destination: destination, acl: acl)
    }
    
    func esEvent(deleteextattr es: es_event_deleteextattr_t) -> ESEvent.DeleteExtAttr {
        ESEvent.DeleteExtAttr(target: esFile(es.target), extattr: esString(es.extattr))
    }
    
    func esEvent(dup es: es_event_dup_t) -> ESEvent.Dup {
        ESEvent.Dup(target: esFile(es.target))
    }
    
    func esEvent(exchangedata es: es_event_exchangedata_t) -> ESEvent.ExchangeData {
        ESEvent.ExchangeData(file1: esFile(es.file1), file2: esFile(es.file2))
    }
    
    func esEvent(exec es: es_event_exec_t) -> ESEvent.Exec {
        var event = ESEvent.Exec(
            target: esProcess(es.target),
            script: version >= 2 ? es.script.flatMap(esFile) : nil, /* field available only if message version >= 2 */
            cwd: version >= 3 ? esFile(es.cwd.pointee) : nil, /* field available only if message version >= 3 */
            lastFD: version >= 4 ? es.last_fd : nil /* field available only if message version >= 4 */
        )
        if config.execArgs {
            event.args = es.args
        }
        if config.execEnv {
            event.env = es.env
        }
        
        return event
    }
    
    func esEvent(exit es: es_event_exit_t) -> ESEvent.Exit {
        .init(status: es.stat)
    }
    
    func esEvent(file_provider_materialize es: es_event_file_provider_materialize_t) -> ESEvent.FileProviderMaterialize {
        .init(instigator: esProcess(es.instigator), source: esFile(es.source), target: esFile(es.target))
    }
    
    func esEvent(file_provider_update es: es_event_file_provider_update_t) -> ESEvent.FileProviderUpdate {
        .init(source: esFile(es.source), targetPath: esString(es.target_path))
    }
    
    func esEvent(fcntl es: es_event_fcntl_t) -> ESEvent.Fcntl {
        .init(target: esFile(es.target), cmd: es.cmd)
    }
    
    func esEvent(fork es: es_event_fork_t) -> ESEvent.Fork {
        .init(child: esProcess(es.child))
    }
    
    func esEvent(fsgetpath es: es_event_fsgetpath_t) -> ESEvent.FsGetPath {
        .init(target: esFile(es.target))
    }
    
    func esEvent(get_task es: es_event_get_task_t) -> ESEvent.GetTask {
        .init(target: esProcess(es.target))
    }
    
    func esEvent(get_task_read es: es_event_get_task_read_t) -> ESEvent.GetTaskRead {
        .init(target: esProcess(es.target))
    }
    
    func esEvent(get_task_inspect es: es_event_get_task_inspect_t) -> ESEvent.GetTaskInspect {
        .init(target: esProcess(es.target))
    }
    
    func esEvent(get_task_name es: es_event_get_task_name_t) -> ESEvent.GetTaskName {
        .init(target: esProcess(es.target))
    }
    
    func esEvent(getattrlist es: es_event_getattrlist_t) -> ESEvent.GetAttrList {
        .init(attrlist: es.attrlist, target: esFile(es.target))
    }
    
    func esEvent(getextattr es: es_event_getextattr_t) -> ESEvent.GetExtAttr {
        .init(target: esFile(es.target), extattr: esString(es.extattr))
    }
    
    func esEvent(iokit_open es: es_event_iokit_open_t) -> ESEvent.IOKitOpen {
        .init(userClientType: es.user_client_type, userClientClass: esString(es.user_client_class))
    }
    
    func esEvent(kextload es: es_event_kextload_t) -> ESEvent.KextLoad {
        .init(identifier: esString(es.identifier))
    }
    
    func esEvent(kextunload es: es_event_kextunload_t) -> ESEvent.KextUnload {
        .init(identifier: esString(es.identifier))
    }
    
    func esEvent(link es: es_event_link_t) -> ESEvent.Link {
        .init(source: esFile(es.source), targetDir: esFile(es.target_dir), targetFilename: esString(es.target_filename))
    }
    
    func esEvent(listextattr es: es_event_listextattr_t) -> ESEvent.ListExtAttr {
        .init(target: esFile(es.target))
    }
    
    func esEvent(lookup es: es_event_lookup_t) -> ESEvent.Lookup {
        .init(sourceDir: esFile(es.source_dir), relativeTarget: esString(es.relative_target))
    }
    
    func esEvent(mmap es: es_event_mmap_t) -> ESEvent.MMap {
        .init(protection: es.protection, maxProtection: es.max_protection, flags: es.flags, filePos: es.file_pos, source: esFile(es.source))
    }
    
    func esEvent(mount es: es_event_mount_t) -> ESEvent.Mount {
        .init(statfs: es.statfs.pointee)
    }
    
    func esEvent(mprotect es: es_event_mprotect_t) -> ESEvent.MProtect {
        .init(protection: es.protection, address: es.address, size: es.size)
    }
    
    func esEvent(open es: es_event_open_t) -> ESEvent.Open {
        .init(fflag: es.fflag, file: esFile(es.file))
    }
    
    func esEvent(proc_check es: es_event_proc_check_t) -> ESEvent.ProcCheck {
        .init(target: es.target.flatMap(esProcess), type: es.type, flavor: es.flavor)
    }
    
    func esEvent(proc_suspend_resume es: es_event_proc_suspend_resume_t) -> ESEvent.ProcSuspendResume {
        .init(target: es.target.flatMap(esProcess), type: es.type)
    }
    
    func esEvent(pty_close es: es_event_pty_close_t) -> ESEvent.PtyClose {
        .init(dev: es.dev)
    }
    
    func esEvent(pty_grant es: es_event_pty_grant_t) -> ESEvent.PtyGrant {
        .init(dev: es.dev)
    }
    
    func esEvent(readdir es: es_event_readdir_t) -> ESEvent.Readdir {
        .init(target: esFile(es.target))
    }
    
    func esEvent(readlink es: es_event_readlink_t) -> ESEvent.Readlink {
        .init(source: esFile(es.source))
    }
    
    func esEvent(remote_thread_create es: es_event_remote_thread_create_t) throws -> ESEvent.RemoteThreadCreate {
        try .init(target: esProcess(es.target), threadState: es.thread_state.map(\.pointee).flatMap(esThreadState))
    }
    
    func esEvent(remount es: es_event_remount_t) -> ESEvent.Remount {
        .init(statfs: es.statfs.pointee)
    }
    
    func esEvent(rename es: es_event_rename_t) throws -> ESEvent.Rename {
        let destination: ESEvent.Rename.Destination
        switch es.destination_type {
        case ES_DESTINATION_TYPE_NEW_PATH:
            destination = .newPath(
                dir: esFile(es.destination.new_path.dir),
                filename: esString(es.destination.new_path.filename)
            )
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            destination = .existingFile(esFile(es.destination.existing_file))
        default:
            throw CommonError.invalidArgument(arg: "es_destination_type_t", invalidValue: es.destination_type)
        }
        return .init(source: esFile(es.source), destination: destination)
    }
    
    func esEvent(searchfs es: es_event_searchfs_t) -> ESEvent.SearchFS {
        .init(attrlist: es.attrlist, target: esFile(es.target))
    }
    
    func esEvent(setacl es: es_event_setacl_t) -> ESEvent.SetACL {
        var acl: acl_t?
        if es.set_or_clear == ES_SET {
            acl = es.acl.set
        }
        return .init(target: esFile(es.target), setOrClear: es.set_or_clear, acl: acl)
    }
    
    func esEvent(setattrlist es: es_event_setattrlist_t) -> ESEvent.SetAttrList {
        .init(attrlist: es.attrlist, target: esFile(es.target))
    }
    
    func esEvent(setextattr es: es_event_setextattr_t) -> ESEvent.SetExtAttr {
        .init(target: esFile(es.target), extattr: esString(es.extattr))
    }
    
    func esEvent(setflags es: es_event_setflags_t) -> ESEvent.SetFlags {
        .init(flags: es.flags, target: esFile(es.target))
    }
    
    func esEvent(setmode es: es_event_setmode_t) -> ESEvent.SetMode {
        .init(mode: es.mode, target: esFile(es.target))
    }
    
    func esEvent(setowner es: es_event_setowner_t) -> ESEvent.SetOwner {
        .init(uid: es.uid, gid: es.gid, target: esFile(es.target))
    }
    
    func esEvent(setuid es: es_event_setuid_t) -> ESEvent.SetUID {
        .init(uid: es.uid)
    }
    
    func esEvent(setgid es: es_event_setgid_t) -> ESEvent.SetUID {
        .init(uid: es.gid)
    }
    
    func esEvent(seteuid es: es_event_seteuid_t) -> ESEvent.SetUID {
        .init(uid: es.euid)
    }
    
    func esEvent(setegid es: es_event_setegid_t) -> ESEvent.SetUID {
        .init(uid: es.egid)
    }
    
    func esEvent(setreuid es: es_event_setreuid_t) -> ESEvent.SetREUID {
        .init(ruid: es.ruid, euid: es.euid)
    }
    
    func esEvent(setregid es: es_event_setregid_t) -> ESEvent.SetREUID {
        .init(ruid: es.rgid, euid: es.egid)
    }
    
    func esEvent(signal es: es_event_signal_t) -> ESEvent.Signal {
        .init(sig: es.sig, target: esProcess(es.target))
    }
    
    func esEvent(stat es: es_event_stat_t) -> ESEvent.Stat {
        .init(target: esFile(es.target))
    }
    
    func esEvent(trace es: es_event_trace_t) -> ESEvent.Trace {
        .init(target: esProcess(es.target))
    }
    
    func esEvent(truncate es: es_event_truncate_t) -> ESEvent.Truncate {
        .init(target: esFile(es.target))
    }
    
    func esEvent(uipc_bind es: es_event_uipc_bind_t) -> ESEvent.UipcBind {
        .init(dir: esFile(es.dir), filename: esString(es.filename), mode: es.mode)
    }
    
    func esEvent(uipc_connect es: es_event_uipc_connect_t) -> ESEvent.UipcConnect {
        .init(file: esFile(es.file), domain: es.domain, type: es.type, protocol: es.protocol)
    }
    
    func esEvent(unlink es: es_event_unlink_t) -> ESEvent.Unlink {
        .init(target: esFile(es.target), parentDir: esFile(es.parent_dir))
    }
    
    func esEvent(unmount es: es_event_unmount_t) -> ESEvent.Unmount {
        .init(statfs: es.statfs.pointee)
    }
    
    func esEvent(utimes es: es_event_utimes_t) -> ESEvent.Utimes {
        .init(target: esFile(es.target), aTime: es.atime, mTime: es.mtime)
    }
    
    func esEvent(write es: es_event_write_t) -> ESEvent.Write {
        .init(target: esFile(es.target))
    }
    
    func esEvent(authentication es: UnsafePointer<es_event_authentication_t>) throws -> ESEvent.Authentication {
        let type: ESEvent.AuthenticationType
        switch es.pointee.type {
        case ES_AUTHENTICATION_TYPE_OD:
            type = .od(.init(
                instigator: esProcess(es.pointee.data.od.pointee.instigator),
                recordType: esString(es.pointee.data.od.pointee.record_type),
                recordName: esString(es.pointee.data.od.pointee.record_name),
                nodeName: esString(es.pointee.data.od.pointee.node_name),
                dbPath: esString(es.pointee.data.od.pointee.db_path)
            ))
        case ES_AUTHENTICATION_TYPE_TOUCHID:
            type = .touchID(.init(
                instigator: esProcess(es.pointee.data.touchid.pointee.instigator),
                touchIDMode: es.pointee.data.touchid.pointee.touchid_mode,
                uid: es.pointee.data.touchid.pointee.has_uid ? es.pointee.data.touchid.pointee.uid.uid : nil
            ))
        case ES_AUTHENTICATION_TYPE_TOKEN:
            type = .token(.init(
                instigator: esProcess(es.pointee.data.token.pointee.instigator),
                pubkeyHash: esString(es.pointee.data.token.pointee.pubkey_hash),
                tokenID: esString(es.pointee.data.token.pointee.token_id),
                kerberosPrincipal: esString(es.pointee.data.token.pointee.kerberos_principal)
            ))
        case ES_AUTHENTICATION_TYPE_AUTO_UNLOCK:
            type = .autoUnlock(.init(
                username: esString(es.pointee.data.auto_unlock.pointee.username),
                type: es.pointee.data.auto_unlock.pointee.type
            ))
        default:
            throw CommonError.invalidArgument(arg: "es_event_authentication_typet", invalidValue: es.pointee.type)
        }
        return .init(success: es.pointee.success, type: type)
    }
    
    func esEvent(xpMalwareDetected es: UnsafePointer<es_event_xp_malware_detected_t>) -> ESEvent.XPMalwareDetected {
        .init(
            signatureVersion: esString(es.pointee.signature_version),
            malwareIdentifier: esString(es.pointee.malware_identifier),
            incidentIdentifier: esString(es.pointee.incident_identifier),
            detectedPath: esString(es.pointee.detected_path)
        )
    }
    
    func esEvent(xpMalwareRemediated es: UnsafePointer<es_event_xp_malware_remediated_t>) -> ESEvent.XPMalwareRemediated {
        .init(
            signatureVersion: esString(es.pointee.signature_version),
            malwareIdentifier: esString(es.pointee.malware_identifier),
            incidentIdentifier: esString(es.pointee.incident_identifier),
            actionType: esString(es.pointee.action_type),
            success: es.pointee.success,
            resultDescription: esString(es.pointee.result_description),
            remediatedPath: esString(es.pointee.remediated_path),
            remediatedProcessAuditToken: es.pointee.remediated_process_audit_token?.pointee
        )
    }
    
    func esEvent(lwSessionLogin es: UnsafePointer<es_event_lw_session_login_t>) -> ESEvent.LWSessionLogin {
        .init(
            username: esString(es.pointee.username),
            graphicalSessionID: es.pointee.graphical_session_id
        )
    }
    
    func esEvent(lwSessionLogout es: UnsafePointer<es_event_lw_session_logout_t>) -> ESEvent.LWSessionLogout {
        .init(
            username: esString(es.pointee.username),
            graphicalSessionID: es.pointee.graphical_session_id
        )
    }
    
    func esEvent(lwSessionLock es: UnsafePointer<es_event_lw_session_lock_t>) -> ESEvent.LWSessionLock {
        .init(
            username: esString(es.pointee.username),
            graphicalSessionID: es.pointee.graphical_session_id
        )
    }
    
    func esEvent(lwSessionUnlock es: UnsafePointer<es_event_lw_session_unlock_t>) -> ESEvent.LWSessionUnlock {
        .init(
            username: esString(es.pointee.username),
            graphicalSessionID: es.pointee.graphical_session_id
        )
    }
    
    func esEvent(screensharingAttach es: UnsafePointer<es_event_screensharing_attach_t>) -> ESEvent.ScreensharingAttach {
        .init(
            success: es.pointee.success,
            sourceAddressType: es.pointee.source_address_type,
            sourceAddress: esString(es.pointee.source_address),
            viewerAppleID: esString(es.pointee.viewer_appleid),
            authenticationType: esString(es.pointee.authentication_type),
            authenticationUsername: esString(es.pointee.authentication_username),
            sessionUsername: esString(es.pointee.session_username),
            existingSession: es.pointee.existing_session,
            graphicalSessionID: es.pointee.graphical_session_id
        )
    }
    
    func esEvent(screensharingDetach es: UnsafePointer<es_event_screensharing_detach_t>) -> ESEvent.ScreensharingDetach {
        .init(
            sourceAddressType: es.pointee.source_address_type,
            sourceAddress: esString(es.pointee.source_address),
            viewerAppleID: esString(es.pointee.viewer_appleid),
            graphicalSessionID: es.pointee.graphical_session_id
        )
    }
    
    func esEvent(opensshLogin es: UnsafePointer<es_event_openssh_login_t>) -> ESEvent.OpensshLogin {
        .init(
            success: es.pointee.success,
            resultType: es.pointee.result_type,
            sourceAddressType: es.pointee.source_address_type,
            sourceAddress: esString(es.pointee.source_address),
            username: esString(es.pointee.username),
            uid: es.pointee.has_uid ? es.pointee.uid.uid : nil
        )
    }
    
    func esEvent(opensshLogout es: UnsafePointer<es_event_openssh_logout_t>) -> ESEvent.OpensshLogout {
        .init(
            sourceAddressType: es.pointee.source_address_type,
            sourceAddress: esString(es.pointee.source_address),
            username: esString(es.pointee.username),
            uid: es.pointee.uid
        )
    }
    
    func esEvent(loginLogin es: UnsafePointer<es_event_login_login_t>) -> ESEvent.LoginLogin {
        .init(
            success: es.pointee.success,
            failureMessage: esString(es.pointee.failure_message),
            username: esString(es.pointee.username),
            uid: es.pointee.has_uid ? es.pointee.uid.uid : nil
        )
    }
    
    func esEvent(loginLogout es: UnsafePointer<es_event_login_logout_t>) -> ESEvent.LoginLogout {
        .init(username: esString(es.pointee.username), uid: es.pointee.uid)
    }
    
    func esEvent(btmLaunchItemAdd es: UnsafePointer<es_event_btm_launch_item_add_t>) -> ESEvent.BTMLaunchItemAdd {
        .init(
            instigator: es.pointee.instigator.flatMap(esProcess),
            app: es.pointee.app.flatMap(esProcess),
            item: esBTMLaunchItem(es.pointee.item),
            executablePath: esString(es.pointee.executable_path)
        )
    }
    
    func esEvent(btmLaunchItemRemove es: UnsafePointer<es_event_btm_launch_item_remove_t>) -> ESEvent.BTMLaunchItemRemove {
        .init(
            instigator: es.pointee.instigator.flatMap(esProcess),
            app: es.pointee.instigator.flatMap(esProcess),
            item: esBTMLaunchItem(es.pointee.item)
        )
    }
    
    func esEvent(profileAdd es: es_event_profile_add_t) -> ESEvent.ProfileAdd {
        .init(
            instigator: esProcess(es.instigator),
            isUpdate: es.is_update,
            profile: esProfile(es.profile.pointee)
        )
    }
    
    func esEvent(profileRemove es: es_event_profile_remove_t) -> ESEvent.ProfileRemove {
        .init(
            instigator: esProcess(es.instigator),
            profile: esProfile(es.profile.pointee)
        )
    }
    
    func esEvent(su es: es_event_su_t) -> ESEvent.SU {
        .init(
            success: es.success,
            failureMessage: esString(es.failure_message),
            fromUID: es.from_uid,
            fromUsername: esString(es.from_username),
            toUID: es.has_to_uid ? es.to_uid.uid : nil,
            toUsername: esString(es.to_username),
            shell: esString(es.shell),
            args: UnsafeBufferPointer(start: es.argv, count: es.argc).map(esString),
            env: UnsafeBufferPointer(start: es.env, count: es.env_count).map(esString)
        )
    }
    
    func esEvent(authorizationPetition es: es_event_authorization_petition_t) -> ESEvent.AuthorizationPetition {
        .init(
            instigator: esProcess(es.instigator),
            petitioner: es.petitioner.flatMap(esProcess),
            flags: es.flags,
            rights: UnsafeBufferPointer(start: es.rights, count: es.right_count).map(esString)
        )
    }
    
    func esEvent(authorizationJudgement es: es_event_authorization_judgement_t) -> ESEvent.AuthorizationJudgement {
        .init(
            instigator: esProcess(es.instigator),
            petitioner: es.petitioner.flatMap(esProcess),
            returnCode: es.return_code,
            results: UnsafeBufferPointer(start: es.results, count: es.result_count).map {
                .init(
                    rightName: esString($0.right_name),
                    ruleClass: $0.rule_class,
                    granted: $0.granted
                )
            }
        )
    }
    
    func esEvent(sudo es: es_event_sudo_t) -> ESEvent.SUDO {
        .init(
            success: es.success,
            rejectInfo: es.reject_info.flatMap {
                .init(
                    pluginName: esString($0.pointee.plugin_name),
                    pluginType: $0.pointee.plugin_type,
                    failureMessage: esString($0.pointee.failure_message)
                )
            },
            fromUID: es.has_from_uid ? es.from_uid.uid : nil,
            fromUsername: esString(es.from_username),
            toUID: es.has_to_uid ? es.to_uid.uid : nil,
            toUsername: esString(es.to_username),
            command: esString(es.command)
        )
    }
    
    func esEvent(odGroupAdd es: es_event_od_group_add_t) throws -> ESEvent.ODGroupAdd {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            groupName: esString(es.group_name),
            member: try esODMemberID(es.member),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odGroupRemove es: es_event_od_group_remove_t) throws -> ESEvent.ODGroupRemove {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            groupName: esString(es.group_name),
            member: try esODMemberID(es.member),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odGroupSet es: es_event_od_group_set_t) throws -> ESEvent.ODGroupSet {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            groupName: esString(es.group_name),
            members: try esODMemberIDs(es.members),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odModifyPassword es: es_event_od_modify_password_t) -> ESEvent.ODModifyPassword {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            accountType: es.account_type,
            accountName: esString(es.account_name),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odDisableUser es: es_event_od_disable_user_t) -> ESEvent.ODDisableUser {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            userName: esString(es.user_name),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odEnableUser es: es_event_od_enable_user_t) -> ESEvent.ODEnableUser {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            userName: esString(es.user_name),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odAttributeValueAdd es: es_event_od_attribute_value_add_t) -> ESEvent.ODAttributeValueAdd {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            recordType: es.record_type,
            recordName: esString(es.record_name),
            attributeName: esString(es.attribute_name),
            attributeValue: esString(es.attribute_value),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odAttributeValueRemove es: es_event_od_attribute_value_remove_t) -> ESEvent.ODAttributeValueRemove {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            recordType: es.record_type,
            recordName: esString(es.record_name),
            attributeName: esString(es.attribute_name),
            attributeValue: esString(es.attribute_value),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odAttributeSet es: es_event_od_attribute_set_t) -> ESEvent.ODAttributeSet {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            recordType: es.record_type,
            recordName: esString(es.record_name),
            attributeName: esString(es.attribute_name),
            attributeValues: UnsafeBufferPointer(
                start: es.attribute_values,
                count: es.attribute_value_count
            ).map(esString),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odCreateUser es: es_event_od_create_user_t) -> ESEvent.ODCreateUser {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            userName: esString(es.user_name),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odCreateGroup es: es_event_od_create_group_t) -> ESEvent.ODCreateGroup {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            groupName: esString(es.group_name),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odDeleteUser es: es_event_od_delete_user_t) -> ESEvent.ODDeleteUser {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            userName: esString(es.user_name),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(odDeleteGroup es: es_event_od_delete_group_t) -> ESEvent.ODDeleteGroup {
        .init(
            instigator: esProcess(es.instigator),
            errorCode: es.error_code,
            groupName: esString(es.group_name),
            nodeName: esString(es.node_name),
            dbPath: esString(es.db_path)
        )
    }
    
    func esEvent(xpcConnect es: es_event_xpc_connect_t) -> ESEvent.XPCConnect {
        .init(serviceName: esString(es.service_name), serviceDomainType: es.service_domain_type)
    }
}
