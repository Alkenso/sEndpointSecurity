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

private protocol ESNativeType: Hashable, Codable, CustomStringConvertible, RawRepresentable {
    var name: String? { get }
}

extension ESNativeType {
    public var description: String {
        "\(name ?? "unknown \(Self.self)") (\(rawValue))"
    }
}

extension es_event_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_EVENT_TYPE_AUTH_EXEC:
            return "ES_EVENT_TYPE_AUTH_EXEC"
        case ES_EVENT_TYPE_AUTH_OPEN:
            return "ES_EVENT_TYPE_AUTH_OPEN"
        case ES_EVENT_TYPE_AUTH_KEXTLOAD:
            return "ES_EVENT_TYPE_AUTH_KEXTLOAD"
        case ES_EVENT_TYPE_AUTH_MMAP:
            return "ES_EVENT_TYPE_AUTH_MMAP"
        case ES_EVENT_TYPE_AUTH_MPROTECT:
            return "ES_EVENT_TYPE_AUTH_MPROTECT"
        case ES_EVENT_TYPE_AUTH_MOUNT:
            return "ES_EVENT_TYPE_AUTH_MOUNT"
        case ES_EVENT_TYPE_AUTH_RENAME:
            return "ES_EVENT_TYPE_AUTH_RENAME"
        case ES_EVENT_TYPE_AUTH_SIGNAL:
            return "ES_EVENT_TYPE_AUTH_SIGNAL"
        case ES_EVENT_TYPE_AUTH_UNLINK:
            return "ES_EVENT_TYPE_AUTH_UNLINK"
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            return "ES_EVENT_TYPE_NOTIFY_EXEC"
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            return "ES_EVENT_TYPE_NOTIFY_OPEN"
        case ES_EVENT_TYPE_NOTIFY_FORK:
            return "ES_EVENT_TYPE_NOTIFY_FORK"
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            return "ES_EVENT_TYPE_NOTIFY_CLOSE"
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            return "ES_EVENT_TYPE_NOTIFY_CREATE"
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            return "ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA"
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return "ES_EVENT_TYPE_NOTIFY_EXIT"
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            return "ES_EVENT_TYPE_NOTIFY_GET_TASK"
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            return "ES_EVENT_TYPE_NOTIFY_KEXTLOAD"
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            return "ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD"
        case ES_EVENT_TYPE_NOTIFY_LINK:
            return "ES_EVENT_TYPE_NOTIFY_LINK"
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            return "ES_EVENT_TYPE_NOTIFY_MMAP"
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            return "ES_EVENT_TYPE_NOTIFY_MPROTECT"
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            return "ES_EVENT_TYPE_NOTIFY_MOUNT"
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            return "ES_EVENT_TYPE_NOTIFY_UNMOUNT"
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            return "ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN"
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            return "ES_EVENT_TYPE_NOTIFY_RENAME"
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            return "ES_EVENT_TYPE_NOTIFY_SETATTRLIST"
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            return "ES_EVENT_TYPE_NOTIFY_SETEXTATTR"
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            return "ES_EVENT_TYPE_NOTIFY_SETFLAGS"
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            return "ES_EVENT_TYPE_NOTIFY_SETMODE"
        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            return "ES_EVENT_TYPE_NOTIFY_SETOWNER"
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            return "ES_EVENT_TYPE_NOTIFY_SIGNAL"
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            return "ES_EVENT_TYPE_NOTIFY_UNLINK"
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            return "ES_EVENT_TYPE_NOTIFY_WRITE"
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE:
            return "ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE"
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
            return "ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE"
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE:
            return "ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE"
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
            return "ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE"
        case ES_EVENT_TYPE_AUTH_READLINK:
            return "ES_EVENT_TYPE_AUTH_READLINK"
        case ES_EVENT_TYPE_NOTIFY_READLINK:
            return "ES_EVENT_TYPE_NOTIFY_READLINK"
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            return "ES_EVENT_TYPE_AUTH_TRUNCATE"
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            return "ES_EVENT_TYPE_NOTIFY_TRUNCATE"
        case ES_EVENT_TYPE_AUTH_LINK:
            return "ES_EVENT_TYPE_AUTH_LINK"
        case ES_EVENT_TYPE_NOTIFY_LOOKUP:
            return "ES_EVENT_TYPE_NOTIFY_LOOKUP"
        case ES_EVENT_TYPE_AUTH_CREATE:
            return "ES_EVENT_TYPE_AUTH_CREATE"
        case ES_EVENT_TYPE_AUTH_SETATTRLIST:
            return "ES_EVENT_TYPE_AUTH_SETATTRLIST"
        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
            return "ES_EVENT_TYPE_AUTH_SETEXTATTR"
        case ES_EVENT_TYPE_AUTH_SETFLAGS:
            return "ES_EVENT_TYPE_AUTH_SETFLAGS"
        case ES_EVENT_TYPE_AUTH_SETMODE:
            return "ES_EVENT_TYPE_AUTH_SETMODE"
        case ES_EVENT_TYPE_AUTH_SETOWNER:
            return "ES_EVENT_TYPE_AUTH_SETOWNER"
        case ES_EVENT_TYPE_AUTH_CHDIR:
            return "ES_EVENT_TYPE_AUTH_CHDIR"
        case ES_EVENT_TYPE_NOTIFY_CHDIR:
            return "ES_EVENT_TYPE_NOTIFY_CHDIR"
        case ES_EVENT_TYPE_AUTH_GETATTRLIST:
            return "ES_EVENT_TYPE_AUTH_GETATTRLIST"
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
            return "ES_EVENT_TYPE_NOTIFY_GETATTRLIST"
        case ES_EVENT_TYPE_NOTIFY_STAT:
            return "ES_EVENT_TYPE_NOTIFY_STAT"
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            return "ES_EVENT_TYPE_NOTIFY_ACCESS"
        case ES_EVENT_TYPE_AUTH_CHROOT:
            return "ES_EVENT_TYPE_AUTH_CHROOT"
        case ES_EVENT_TYPE_NOTIFY_CHROOT:
            return "ES_EVENT_TYPE_NOTIFY_CHROOT"
        case ES_EVENT_TYPE_AUTH_UTIMES:
            return "ES_EVENT_TYPE_AUTH_UTIMES"
        case ES_EVENT_TYPE_NOTIFY_UTIMES:
            return "ES_EVENT_TYPE_NOTIFY_UTIMES"
        case ES_EVENT_TYPE_AUTH_CLONE:
            return "ES_EVENT_TYPE_AUTH_CLONE"
        case ES_EVENT_TYPE_NOTIFY_CLONE:
            return "ES_EVENT_TYPE_NOTIFY_CLONE"
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            return "ES_EVENT_TYPE_NOTIFY_FCNTL"
        case ES_EVENT_TYPE_AUTH_GETEXTATTR:
            return "ES_EVENT_TYPE_AUTH_GETEXTATTR"
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
            return "ES_EVENT_TYPE_NOTIFY_GETEXTATTR"
        case ES_EVENT_TYPE_AUTH_LISTEXTATTR:
            return "ES_EVENT_TYPE_AUTH_LISTEXTATTR"
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
            return "ES_EVENT_TYPE_NOTIFY_LISTEXTATTR"
        case ES_EVENT_TYPE_AUTH_READDIR:
            return "ES_EVENT_TYPE_AUTH_READDIR"
        case ES_EVENT_TYPE_NOTIFY_READDIR:
            return "ES_EVENT_TYPE_NOTIFY_READDIR"
        case ES_EVENT_TYPE_AUTH_DELETEEXTATTR:
            return "ES_EVENT_TYPE_AUTH_DELETEEXTATTR"
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            return "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR"
        case ES_EVENT_TYPE_AUTH_FSGETPATH:
            return "ES_EVENT_TYPE_AUTH_FSGETPATH"
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
            return "ES_EVENT_TYPE_NOTIFY_FSGETPATH"
        case ES_EVENT_TYPE_NOTIFY_DUP:
            return "ES_EVENT_TYPE_NOTIFY_DUP"
        case ES_EVENT_TYPE_AUTH_SETTIME:
            return "ES_EVENT_TYPE_AUTH_SETTIME"
        case ES_EVENT_TYPE_NOTIFY_SETTIME:
            return "ES_EVENT_TYPE_NOTIFY_SETTIME"
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
            return "ES_EVENT_TYPE_NOTIFY_UIPC_BIND"
        case ES_EVENT_TYPE_AUTH_UIPC_BIND:
            return "ES_EVENT_TYPE_AUTH_UIPC_BIND"
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            return "ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT"
        case ES_EVENT_TYPE_AUTH_UIPC_CONNECT:
            return "ES_EVENT_TYPE_AUTH_UIPC_CONNECT"
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            return "ES_EVENT_TYPE_AUTH_EXCHANGEDATA"
        case ES_EVENT_TYPE_AUTH_SETACL:
            return "ES_EVENT_TYPE_AUTH_SETACL"
        case ES_EVENT_TYPE_NOTIFY_SETACL:
            return "ES_EVENT_TYPE_NOTIFY_SETACL"
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
            return "ES_EVENT_TYPE_NOTIFY_PTY_GRANT"
        case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
            return "ES_EVENT_TYPE_NOTIFY_PTY_CLOSE"
        case ES_EVENT_TYPE_AUTH_PROC_CHECK:
            return "ES_EVENT_TYPE_AUTH_PROC_CHECK"
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            return "ES_EVENT_TYPE_NOTIFY_PROC_CHECK"
        case ES_EVENT_TYPE_AUTH_GET_TASK:
            return "ES_EVENT_TYPE_AUTH_GET_TASK"
        case ES_EVENT_TYPE_AUTH_SEARCHFS:
            return "ES_EVENT_TYPE_AUTH_SEARCHFS"
        case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
            return "ES_EVENT_TYPE_NOTIFY_SEARCHFS"
        case ES_EVENT_TYPE_AUTH_FCNTL:
            return "ES_EVENT_TYPE_AUTH_FCNTL"
        case ES_EVENT_TYPE_AUTH_IOKIT_OPEN:
            return "ES_EVENT_TYPE_AUTH_IOKIT_OPEN"
        case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
            return "ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME"
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
            return "ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME"
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            return "ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED"
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
            return "ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME"
        case ES_EVENT_TYPE_NOTIFY_TRACE:
            return "ES_EVENT_TYPE_NOTIFY_TRACE"
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            return "ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE"
        case ES_EVENT_TYPE_AUTH_REMOUNT:
            return "ES_EVENT_TYPE_AUTH_REMOUNT"
        case ES_EVENT_TYPE_NOTIFY_REMOUNT:
            return "ES_EVENT_TYPE_NOTIFY_REMOUNT"
        case ES_EVENT_TYPE_AUTH_GET_TASK_READ:
            return "ES_EVENT_TYPE_AUTH_GET_TASK_READ"
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            return "ES_EVENT_TYPE_NOTIFY_GET_TASK_READ"
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
            return "ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT"
        case ES_EVENT_TYPE_NOTIFY_SETUID:
            return "ES_EVENT_TYPE_NOTIFY_SETUID"
        case ES_EVENT_TYPE_NOTIFY_SETGID:
            return "ES_EVENT_TYPE_NOTIFY_SETGID"
        case ES_EVENT_TYPE_NOTIFY_SETEUID:
            return "ES_EVENT_TYPE_NOTIFY_SETEUID"
        case ES_EVENT_TYPE_NOTIFY_SETEGID:
            return "ES_EVENT_TYPE_NOTIFY_SETEGID"
        case ES_EVENT_TYPE_NOTIFY_SETREUID:
            return "ES_EVENT_TYPE_NOTIFY_SETREUID"
        case ES_EVENT_TYPE_NOTIFY_SETREGID:
            return "ES_EVENT_TYPE_NOTIFY_SETREGID"
        case ES_EVENT_TYPE_AUTH_COPYFILE:
            return "ES_EVENT_TYPE_AUTH_COPYFILE"
        case ES_EVENT_TYPE_NOTIFY_COPYFILE:
            return "ES_EVENT_TYPE_NOTIFY_COPYFILE"
        case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION:
            return "ES_EVENT_TYPE_NOTIFY_AUTHENTICATION"
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
            return "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED"
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
            return "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED"
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN:
            return "ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN"
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT:
            return "ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT"
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK:
            return "ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK"
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK:
            return "ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK"
        case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH:
            return "ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH"
        case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH:
            return "ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH"
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
            return "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN"
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
            return "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT"
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
            return "ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN"
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT:
            return "ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT"
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            return "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD"
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
            return "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE"
#if swift(>=5.9) // Xcode 14 support.
        case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD:
            return "ES_EVENT_TYPE_NOTIFY_PROFILE_ADD"
        case ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE:
            return "ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE"
        case ES_EVENT_TYPE_NOTIFY_SU:
            return "ES_EVENT_TYPE_NOTIFY_SU"
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
            return "ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION"
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
            return "ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT"
        case ES_EVENT_TYPE_NOTIFY_SUDO:
            return "ES_EVENT_TYPE_NOTIFY_SUDO"
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD:
            return "ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD"
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE:
            return "ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE"
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET:
            return "ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET"
        case ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD:
            return "ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD"
        case ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER:
            return "ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER"
        case ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER:
            return "ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER"
        case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD:
            return "ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD"
        case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE:
            return "ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE"
        case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET:
            return "ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET"
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER:
            return "ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER"
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP:
            return "ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP"
        case ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER:
            return "ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER"
        case ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP:
            return "ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP"
        case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
            return "ES_EVENT_TYPE_NOTIFY_XPC_CONNECT"
#endif
        default:
            return nil
        }
    }
}

extension es_auth_result_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_AUTH_RESULT_ALLOW:
            return "ES_AUTH_RESULT_ALLOW"
        case ES_AUTH_RESULT_DENY:
            return "ES_AUTH_RESULT_DENY"
        default:
            return nil
        }
    }
}

extension es_action_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_ACTION_TYPE_AUTH:
            return "ES_ACTION_TYPE_AUTH"
        case ES_ACTION_TYPE_NOTIFY:
            return "ES_ACTION_TYPE_NOTIFY"
        default:
            return nil
        }
    }
}

extension es_result_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_RESULT_TYPE_AUTH:
            return "ES_RESULT_TYPE_AUTH"
        case ES_RESULT_TYPE_FLAGS:
            return "ES_RESULT_TYPE_FLAGS"
        default:
            return nil
        }
    }
}

extension es_return_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_RETURN_SUCCESS:
            return "ES_RETURN_SUCCESS"
        case ES_RETURN_ERROR:
            return "ES_RETURN_ERROR"
        default:
            return nil
        }
    }
}

extension es_respond_result_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_RESPOND_RESULT_SUCCESS:
            return "ES_RESPOND_RESULT_SUCCESS"
        case ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT:
            return "ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT"
        case ES_RESPOND_RESULT_ERR_INTERNAL:
            return "ES_RESPOND_RESULT_ERR_INTERNAL"
        case ES_RESPOND_RESULT_NOT_FOUND:
            return "ES_RESPOND_RESULT_NOT_FOUND"
        case ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE:
            return "ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE"
        case ES_RESPOND_RESULT_ERR_EVENT_TYPE:
            return "ES_RESPOND_RESULT_ERR_EVENT_TYPE"
        default:
            return nil
        }
    }
}

extension es_new_client_result_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            return "ES_NEW_CLIENT_RESULT_SUCCESS"
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            return "ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT"
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            return "ES_NEW_CLIENT_RESULT_ERR_INTERNAL"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return "ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED"
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS"
        default:
            return nil
        }
    }
}

extension es_clear_cache_result_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_CLEAR_CACHE_RESULT_SUCCESS:
            return "ES_CLEAR_CACHE_RESULT_SUCCESS"
        case ES_CLEAR_CACHE_RESULT_ERR_INTERNAL:
            return "ES_CLEAR_CACHE_RESULT_ERR_INTERNAL"
        case ES_CLEAR_CACHE_RESULT_ERR_THROTTLE:
            return "ES_CLEAR_CACHE_RESULT_ERR_THROTTLE"
        default:
            return nil
        }
    }
}

extension es_proc_check_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_PROC_CHECK_TYPE_LISTPIDS:
            return "ES_PROC_CHECK_TYPE_LISTPIDS"
        case ES_PROC_CHECK_TYPE_PIDINFO:
            return "ES_PROC_CHECK_TYPE_PIDINFO"
        case ES_PROC_CHECK_TYPE_PIDFDINFO:
            return "ES_PROC_CHECK_TYPE_PIDFDINFO"
        case ES_PROC_CHECK_TYPE_KERNMSGBUF:
            return "ES_PROC_CHECK_TYPE_KERNMSGBUF"
        case ES_PROC_CHECK_TYPE_SETCONTROL:
            return "ES_PROC_CHECK_TYPE_SETCONTROL"
        case ES_PROC_CHECK_TYPE_PIDFILEPORTINFO:
            return "ES_PROC_CHECK_TYPE_PIDFILEPORTINFO"
        case ES_PROC_CHECK_TYPE_TERMINATE:
            return "ES_PROC_CHECK_TYPE_TERMINATE"
        case ES_PROC_CHECK_TYPE_DIRTYCONTROL:
            return "ES_PROC_CHECK_TYPE_DIRTYCONTROL"
        case ES_PROC_CHECK_TYPE_PIDRUSAGE:
            return "ES_PROC_CHECK_TYPE_PIDRUSAGE"
        case ES_PROC_CHECK_TYPE_UDATA_INFO:
            return "ES_PROC_CHECK_TYPE_UDATA_INFO"
        default:
            return nil
        }
    }
}

extension es_proc_suspend_resume_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND:
            return "ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND"
        case ES_PROC_SUSPEND_RESUME_TYPE_RESUME:
            return "ES_PROC_SUSPEND_RESUME_TYPE_RESUME"
        case ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS:
            return "ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS"
        default:
            return nil
        }
    }
}

extension es_set_or_clear_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_SET:
            return "ES_SET"
        case ES_CLEAR:
            return "ES_CLEAR"
        default:
            return nil
        }
    }
}

extension es_mute_path_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_MUTE_PATH_TYPE_PREFIX:
            return "ES_MUTE_PATH_TYPE_PREFIX"
        case ES_MUTE_PATH_TYPE_LITERAL:
            return "ES_MUTE_PATH_TYPE_LITERAL"
        case ES_MUTE_PATH_TYPE_TARGET_PREFIX:
            return "ES_MUTE_PATH_TYPE_TARGET_PREFIX"
        case ES_MUTE_PATH_TYPE_TARGET_LITERAL:
            return "ES_MUTE_PATH_TYPE_TARGET_LITERAL"
        default:
            return nil
        }
    }
}

extension es_mute_inversion_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_MUTE_INVERSION_TYPE_PROCESS:
            return "ES_MUTE_INVERSION_TYPE_PROCESS"
        case ES_MUTE_INVERSION_TYPE_PATH:
            return "ES_MUTE_INVERSION_TYPE_PATH"
        case ES_MUTE_INVERSION_TYPE_TARGET_PATH:
            return "ES_MUTE_INVERSION_TYPE_TARGET_PATH"
        case ES_MUTE_INVERSION_TYPE_LAST:
            return "ES_MUTE_INVERSION_TYPE_LAST"
        default:
            return nil
        }
    }
}

extension es_mute_inverted_return_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_MUTE_INVERTED:
            return "ES_MUTE_INVERTED"
        case ES_MUTE_NOT_INVERTED:
            return "ES_MUTE_NOT_INVERTED"
        case ES_MUTE_INVERTED_ERROR:
            return "ES_MUTE_INVERTED_ERROR"
        default:
            return nil
        }
    }
}

extension es_btm_item_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_BTM_ITEM_TYPE_USER_ITEM:
            return "ES_BTM_ITEM_TYPE_USER_ITEM"
        case ES_BTM_ITEM_TYPE_APP:
            return "ES_BTM_ITEM_TYPE_APP"
        case ES_BTM_ITEM_TYPE_LOGIN_ITEM:
            return "ES_BTM_ITEM_TYPE_LOGIN_ITEM"
        case ES_BTM_ITEM_TYPE_AGENT:
            return "ES_BTM_ITEM_TYPE_AGENT"
        case ES_BTM_ITEM_TYPE_DAEMON:
            return "ES_BTM_ITEM_TYPE_DAEMON"
        default:
            return nil
        }
    }
}

extension es_touchid_mode_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_TOUCHID_MODE_VERIFICATION:
            return "ES_TOUCHID_MODE_VERIFICATION"
        case ES_TOUCHID_MODE_IDENTIFICATION:
            return "ES_TOUCHID_MODE_IDENTIFICATION"
        default:
            return nil
        }
    }
}

extension es_auto_unlock_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_AUTO_UNLOCK_MACHINE_UNLOCK:
            return "ES_AUTO_UNLOCK_MACHINE_UNLOCK"
        case ES_AUTO_UNLOCK_AUTH_PROMPT:
            return "ES_AUTO_UNLOCK_AUTH_PROMPT"
        default:
            return nil
        }
    }
}

extension es_openssh_login_result_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_OPENSSH_LOGIN_EXCEED_MAXTRIES:
            return "ES_OPENSSH_LOGIN_EXCEED_MAXTRIES"
        case ES_OPENSSH_LOGIN_ROOT_DENIED:
            return "ES_OPENSSH_LOGIN_ROOT_DENIED"
        case ES_OPENSSH_AUTH_SUCCESS:
            return "ES_OPENSSH_AUTH_SUCCESS"
        case ES_OPENSSH_AUTH_FAIL_NONE:
            return "ES_OPENSSH_AUTH_FAIL_NONE"
        case ES_OPENSSH_AUTH_FAIL_PASSWD:
            return "ES_OPENSSH_AUTH_FAIL_PASSWD"
        case ES_OPENSSH_AUTH_FAIL_KBDINT:
            return "ES_OPENSSH_AUTH_FAIL_KBDINT"
        case ES_OPENSSH_AUTH_FAIL_PUBKEY:
            return "ES_OPENSSH_AUTH_FAIL_PUBKEY"
        case ES_OPENSSH_AUTH_FAIL_HOSTBASED:
            return "ES_OPENSSH_AUTH_FAIL_HOSTBASED"
        case ES_OPENSSH_AUTH_FAIL_GSSAPI:
            return "ES_OPENSSH_AUTH_FAIL_GSSAPI"
        case ES_OPENSSH_INVALID_USER:
            return "ES_OPENSSH_INVALID_USER"
        default:
            return nil
        }
    }
}

extension es_address_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_ADDRESS_TYPE_NONE:
            return "ES_ADDRESS_TYPE_NONE"
        case ES_ADDRESS_TYPE_IPV4:
            return "ES_ADDRESS_TYPE_IPV4"
        case ES_ADDRESS_TYPE_IPV6:
            return "ES_ADDRESS_TYPE_IPV6"
        case ES_ADDRESS_TYPE_NAMED_SOCKET:
            return "ES_ADDRESS_TYPE_NAMED_SOCKET"
        default:
            return nil
        }
    }
}

#if swift(>=5.9) // Xcode 14 support.

extension es_profile_source_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_PROFILE_SOURCE_MANAGED:
            return "ES_PROFILE_SOURCE_MANAGED"
        case ES_PROFILE_SOURCE_INSTALL:
            return "ES_PROFILE_SOURCE_INSTALL"
        default:
            return nil
        }
    }
}

extension es_sudo_plugin_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_SUDO_PLUGIN_TYPE_UNKNOWN:
            return "ES_SUDO_PLUGIN_TYPE_UNKNOWN"
        case ES_SUDO_PLUGIN_TYPE_FRONT_END:
            return "ES_SUDO_PLUGIN_TYPE_FRONT_END"
        case ES_SUDO_PLUGIN_TYPE_POLICY:
            return "ES_SUDO_PLUGIN_TYPE_POLICY"
        case ES_SUDO_PLUGIN_TYPE_IO:
            return "ES_SUDO_PLUGIN_TYPE_IO"
        case ES_SUDO_PLUGIN_TYPE_AUDIT:
            return "ES_SUDO_PLUGIN_TYPE_AUDIT"
        case ES_SUDO_PLUGIN_TYPE_APPROVAL:
            return "ES_SUDO_PLUGIN_TYPE_APPROVAL"
        default:
            return nil
        }
    }
}

extension es_authorization_rule_class_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_AUTHORIZATION_RULE_CLASS_USER:
            return "ES_AUTHORIZATION_RULE_CLASS_USER"
        case ES_AUTHORIZATION_RULE_CLASS_RULE:
            return "ES_AUTHORIZATION_RULE_CLASS_RULE"
        case ES_AUTHORIZATION_RULE_CLASS_MECHANISM:
            return "ES_AUTHORIZATION_RULE_CLASS_MECHANISM"
        case ES_AUTHORIZATION_RULE_CLASS_ALLOW:
            return "ES_AUTHORIZATION_RULE_CLASS_ALLOW"
        case ES_AUTHORIZATION_RULE_CLASS_DENY:
            return "ES_AUTHORIZATION_RULE_CLASS_DENY"
        case ES_AUTHORIZATION_RULE_CLASS_UNKNOWN:
            return "ES_AUTHORIZATION_RULE_CLASS_UNKNOWN"
        case ES_AUTHORIZATION_RULE_CLASS_INVALID:
            return "ES_AUTHORIZATION_RULE_CLASS_INVALID"
        default:
            return nil
        }
    }
}

extension es_od_account_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_OD_ACCOUNT_TYPE_USER:
            return "ES_OD_ACCOUNT_TYPE_USER"
        case ES_OD_ACCOUNT_TYPE_COMPUTER:
            return "ES_OD_ACCOUNT_TYPE_COMPUTER"
        default:
            return nil
        }
    }
}

extension es_od_record_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_OD_RECORD_TYPE_USER:
            return "ES_OD_RECORD_TYPE_USER"
        case ES_OD_RECORD_TYPE_GROUP:
            return "ES_OD_RECORD_TYPE_GROUP"
        default:
            return nil
        }
    }
}

extension es_xpc_domain_type_t: ESNativeType {
    fileprivate var name: String? {
        switch self {
        case ES_XPC_DOMAIN_TYPE_SYSTEM:
            return "ES_XPC_DOMAIN_TYPE_SYSTEM"
        case ES_XPC_DOMAIN_TYPE_USER:
            return "ES_XPC_DOMAIN_TYPE_USER"
        case ES_XPC_DOMAIN_TYPE_USER_LOGIN:
            return "ES_XPC_DOMAIN_TYPE_USER_LOGIN"
        case ES_XPC_DOMAIN_TYPE_SESSION:
            return "ES_XPC_DOMAIN_TYPE_SESSION"
        case ES_XPC_DOMAIN_TYPE_PID:
            return "ES_XPC_DOMAIN_TYPE_PID"
        case ES_XPC_DOMAIN_TYPE_MANAGER:
            return "ES_XPC_DOMAIN_TYPE_MANAGER"
        case ES_XPC_DOMAIN_TYPE_PORT:
            return "ES_XPC_DOMAIN_TYPE_PORT"
        case ES_XPC_DOMAIN_TYPE_GUI:
            return "ES_XPC_DOMAIN_TYPE_GUI"
        default:
            return nil
        }
    }
}

#endif
