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

extension es_event_type_t: Hashable, Codable {}

extension es_event_type_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
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
        default:
            return "unknown es_event_type_t"
        }
    }
}

extension es_auth_result_t: Hashable, Codable {}

extension es_auth_result_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
        switch self {
        case ES_AUTH_RESULT_ALLOW:
            return "ES_AUTH_RESULT_ALLOW"
        case ES_AUTH_RESULT_DENY:
            return "ES_AUTH_RESULT_DENY"
        default:
            return "unknown es_auth_result_t"
        }
    }
}

extension es_result_type_t: Hashable, Codable {}

extension es_result_type_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
        switch self {
        case ES_RESULT_TYPE_AUTH:
            return "ES_RESULT_TYPE_AUTH"
        case ES_RESULT_TYPE_FLAGS:
            return "ES_RESULT_TYPE_FLAGS"
        default:
            return "unknown es_result_type_t"
        }
    }
}

extension es_return_t: Hashable, Codable {}

extension es_return_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
        switch self {
        case ES_RETURN_SUCCESS:
            return "ES_RETURN_SUCCESS"
        case ES_RETURN_ERROR:
            return "ES_RETURN_ERROR"
        default:
            return "unknown es_return_t"
        }
    }
}

extension es_respond_result_t: Hashable, Codable {}

extension es_respond_result_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
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
            return "unknown es_respond_result_t"
        }
    }
}

extension es_new_client_result_t: Hashable, Codable {}

extension es_new_client_result_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
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
            return "unknown es_new_client_result_t"
        }
    }
}

extension es_clear_cache_result_t: Hashable, Codable {}

extension es_clear_cache_result_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
        switch self {
        case ES_CLEAR_CACHE_RESULT_SUCCESS:
            return "ES_CLEAR_CACHE_RESULT_SUCCESS"
        case ES_CLEAR_CACHE_RESULT_ERR_INTERNAL:
            return "ES_CLEAR_CACHE_RESULT_ERR_INTERNAL"
        case ES_CLEAR_CACHE_RESULT_ERR_THROTTLE:
            return "ES_CLEAR_CACHE_RESULT_ERR_THROTTLE"
        default:
            return "unknown es_clear_cache_result_t"
        }
    }
}

extension es_proc_check_type_t: Hashable, Codable {}

extension es_proc_check_type_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
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
            return "unknown es_proc_check_type_t"
        }
    }
}

extension es_proc_suspend_resume_type_t: Hashable, Codable {}

extension es_proc_suspend_resume_type_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
        switch self {
        case ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND:
            return "ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND"
        case ES_PROC_SUSPEND_RESUME_TYPE_RESUME:
            return "ES_PROC_SUSPEND_RESUME_TYPE_RESUME"
        case ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS:
            return "ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS"
        default:
            return "unknown es_proc_check_type_t"
        }
    }
}

extension es_set_or_clear_t: Hashable, Codable {}

extension es_set_or_clear_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
        switch self {
        case ES_SET:
            return "ES_SET"
        case ES_CLEAR:
            return "ES_CLEAR"
        default:
            return "unknown es_set_or_clear_t"
        }
    }
}

extension es_mute_path_type_t: Hashable, Codable {}

extension es_mute_path_type_t: CustomDebugStringConvertible {
    public var debugDescription: String {
        "\(name) (\(rawValue))"
    }
    
    private var name: String {
        switch self {
        case ES_MUTE_PATH_TYPE_PREFIX:
            return "ES_MUTE_PATH_TYPE_PREFIX"
        case ES_MUTE_PATH_TYPE_LITERAL:
            return "ES_MUTE_PATH_TYPE_LITERAL"
        default:
            return "unknown es_mute_path_type_t"
        }
    }
}
