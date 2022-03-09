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


extension es_message_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        writer.userInfo.setMessageVersion(version)
        
        try writer.append(version)
        try writer.append(time)
        try writer.append(mach_time)
        try writer.append(deadline)
        try process.pointee.encode(with: &writer)
        try writer.append(seq_num)
        try writer.append(action_type)
        try writer.append(action)
        try writer.append(event_type)
        try event.encode(type: event_type, with: &writer)
        
        guard version >= 4 else { return }
        try thread.encode(with: &writer)
        try writer.append(global_seq_num)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            version = try reader.read()
            reader.userInfo.setMessageVersion(version)
            
            time = try reader.read()
            mach_time = try reader.read()
            deadline = try reader.read()
            process = try .allocate(from: &reader)
            seq_num = try reader.read()
            action_type = try reader.read()
            action = try reader.read()
            event_type = try reader.read()
            try event.decode(type: event_type, from: &reader)
            
            guard version >= 4 else { return }
            thread = try .allocate(from: &reader)
            global_seq_num = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        process.freeAndDeallocate()
        event.freeInternals(type: event_type)
        thread?.freeAndDeallocate()
    }
}

extension es_process_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        let version = try writer.userInfo.messageVersion()
        
        try writer.append(audit_token)
        try writer.append(ppid)
        try writer.append(original_ppid)
        try writer.append(group_id)
        try writer.append(session_id)
        try writer.append(codesigning_flags)
        try writer.append(is_platform_binary)
        try writer.append(is_es_client)
        try writer.append(cdhash)
        try signing_id.encode(with: &writer)
        try team_id.encode(with: &writer)
        try executable.pointee.encode(with: &writer)
        
        guard version >= 2 else { return }
        try tty.encode(with: &writer)
        
        guard version >= 3 else { return }
        try writer.append(start_time)
        
        guard version >= 4 else { return }
        try writer.append(responsible_audit_token)
        try writer.append(parent_audit_token)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        let version = try reader.userInfo.messageVersion()
        
        do {
            audit_token = try reader.read()
            ppid = try reader.read()
            original_ppid = try reader.read()
            group_id = try reader.read()
            session_id = try reader.read()
            codesigning_flags = try reader.read()
            is_platform_binary = try reader.read()
            is_es_client = try reader.read()
            cdhash = try reader.read()
            try signing_id.decode(from: &reader)
            try team_id.decode(from: &reader)
            executable = try .allocate(from: &reader)
            
            guard version >= 2 else { return }
            tty = try .allocate(from: &reader)
            
            guard version >= 3 else { return }
            start_time = try reader.read()
            
            guard version >= 4 else { return }
            responsible_audit_token = try reader.read()
            parent_audit_token = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        signing_id.freeInternals()
        team_id.freeInternals()
        executable.nullable?.freeAndDeallocate()
        tty?.freeAndDeallocate()
    }
}

extension es_string_token_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(length)
        try writer.append(.init(start: data, count: length))
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        length = try reader.read()
        let strData = try reader.read(count: length)
        data = strData.withUnsafeBytes {
            let ptr = UnsafeMutablePointer<CChar>.allocate(capacity: $0.count + 1)
            ptr.advanced(by: $0.count).initialize(to: 0) // NULL-terminator
            memcpy(ptr, $0.baseAddress, $0.count)
            return UnsafePointer<CChar>(ptr)
        }
    }
    
    func freeInternals() {
        if !data.isNull {
            data.deallocate()
        }
    }
}

extension es_token_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(size)
        try writer.append(.init(start: data, count: size))
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        size = try reader.read()
        data = try reader.read(count: size).withUnsafeBytes {
            let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: $0.count)
            memcpy(ptr, $0.baseAddress, $0.count)
            return UnsafePointer<UInt8>(ptr)
        }
    }
    
    func freeInternals() {
        if !data.isNull {
            data.deallocate()
        }
    }
}

extension es_file_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try path.encode(with: &writer)
        try writer.append(path_truncated)
        try writer.append(stat)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            try path.decode(from: &reader)
            try path_truncated = reader.read()
            try stat = reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        path.freeInternals()
    }
}

extension es_thread_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(thread_id)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        thread_id = try reader.read()
    }
    
    func freeInternals() {}
}

extension es_thread_state_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(flavor)
        try state.encode(with: &writer)
        
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            flavor = try reader.read()
            try state.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        state.freeInternals()
    }
}

extension es_events_t {
    func encode(type: es_event_type_t, with writer: inout BinaryWriter) throws {
        switch type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            try exec.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_OPEN:
            try open.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_KEXTLOAD:
            try kextload.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_MMAP:
            try mmap.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_MPROTECT:
            try mprotect.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_MOUNT:
            try mount.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_RENAME:
            try rename.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_SIGNAL:
            try signal.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_UNLINK:
            try unlink.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            try exec.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            try open.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_FORK:
            try fork.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            try close.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            try create.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            try exchangedata.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            try exit.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            try get_task.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            try kextload.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            try kextunload.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_LINK:
            try link.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            try mmap.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            try mprotect.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            try mount.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            try unmount.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            try iokit_open.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            try rename.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            try setattrlist.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            try setextattr.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            try setflags.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            try setmode.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            try setowner.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            try signal.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            try unlink.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            try write.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE:
            try file_provider_materialize.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
            try file_provider_materialize.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE:
            try file_provider_update.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
            try file_provider_update.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_READLINK:
            try readlink.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_READLINK:
            try readlink.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            try truncate.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            try truncate.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_LINK:
            try link.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_LOOKUP:
            try lookup.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_CREATE:
            try create.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_SETATTRLIST:
            try setattrlist.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
            try setextattr.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_SETFLAGS:
            try setflags.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_SETMODE:
            try setmode.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_SETOWNER:
            try setowner.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_CHDIR:
            try chdir.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_CHDIR:
            try chdir.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_GETATTRLIST:
            try getattrlist.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
            try getattrlist.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_STAT:
            try stat.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            try access.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_CHROOT:
            try chroot.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_CHROOT:
            try chroot.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_UTIMES:
            try utimes.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_UTIMES:
            try utimes.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_CLONE:
            try clone.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_CLONE:
            try clone.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            try fcntl.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_GETEXTATTR:
            try getextattr.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
            try getextattr.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_LISTEXTATTR:
            try listextattr.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
            try listextattr.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_READDIR:
            try readdir.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_READDIR:
            try readdir.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_DELETEEXTATTR:
            try deleteextattr.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            try deleteextattr.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_FSGETPATH:
            try fsgetpath.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
            try fsgetpath.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_DUP:
            try dup.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_SETTIME:
            try settime.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETTIME:
            try settime.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
            try uipc_bind.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_UIPC_BIND:
            try uipc_bind.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            try uipc_connect.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_UIPC_CONNECT:
            try uipc_connect.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            try exchangedata.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_SETACL:
            try setacl.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETACL:
            try setacl.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
            try pty_grant.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
            try pty_close.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_PROC_CHECK:
            try proc_check.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            try proc_check.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_GET_TASK:
            try get_task.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_SEARCHFS:
            try searchfs.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
            try searchfs.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_FCNTL:
            try fcntl.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_IOKIT_OPEN:
            try iokit_open.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
            try proc_suspend_resume.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
            try proc_suspend_resume.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            try cs_invalidated.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
            try get_task_name.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_TRACE:
            try trace.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            try remote_thread_create.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_REMOUNT:
            try remount.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_REMOUNT:
            try remount.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_GET_TASK_READ:
            try get_task_read.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            try get_task_read.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
            try get_task_inspect.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETUID:
            try setuid.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETGID:
            try setuid.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETEUID:
            try setuid.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETEGID:
            try setuid.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETREUID:
            try setreuid.encode(with: &writer)
        case ES_EVENT_TYPE_NOTIFY_SETREGID:
            try setreuid.encode(with: &writer)
        case ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_NOTIFY_COPYFILE:
            try copyfile.encode(with: &writer)
        default:
            fatalError()
        }
    }
    
    mutating func decode(type: es_event_type_t, from reader: inout BinaryReader) throws {
        switch type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            try exec.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_OPEN:
            try open.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_KEXTLOAD:
            try kextload.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_MMAP:
            try mmap.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_MPROTECT:
            try mprotect.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_MOUNT:
            try mount.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_RENAME:
            try rename.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_SIGNAL:
            try signal.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_UNLINK:
            try unlink.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            try exec.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            try open.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_FORK:
            try fork.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            try close.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            try create.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            try exchangedata.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            try exit.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            try get_task.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            try kextload.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            try kextunload.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_LINK:
            try link.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            try mmap.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            try mprotect.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            try mount.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            try unmount.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            try iokit_open.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            try rename.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            try setattrlist.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            try setextattr.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            try setflags.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            try setmode.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            try setowner.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            try signal.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            try unlink.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            try write.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE:
            try file_provider_materialize.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
            try file_provider_materialize.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE:
            try file_provider_update.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
            try file_provider_update.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_READLINK:
            try readlink.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_READLINK:
            try readlink.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            try truncate.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            try truncate.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_LINK:
            try link.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_LOOKUP:
            try lookup.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_CREATE:
            try create.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_SETATTRLIST:
            try setattrlist.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
            try setextattr.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_SETFLAGS:
            try setflags.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_SETMODE:
            try setmode.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_SETOWNER:
            try setowner.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_CHDIR:
            try chdir.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_CHDIR:
            try chdir.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_GETATTRLIST:
            try getattrlist.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
            try getattrlist.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_STAT:
            try stat.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            try access.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_CHROOT:
            try chroot.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_CHROOT:
            try chroot.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_UTIMES:
            try utimes.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_UTIMES:
            try utimes.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_CLONE:
            try clone.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_CLONE:
            try clone.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            try fcntl.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_GETEXTATTR:
            try getextattr.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
            try getextattr.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_LISTEXTATTR:
            try listextattr.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
            try listextattr.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_READDIR:
            try readdir.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_READDIR:
            try readdir.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_DELETEEXTATTR:
            try deleteextattr.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            try deleteextattr.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_FSGETPATH:
            try fsgetpath.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
            try fsgetpath.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_DUP:
            try dup.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_SETTIME:
            try settime.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETTIME:
            try settime.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
            try uipc_bind.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_UIPC_BIND:
            try uipc_bind.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            try uipc_connect.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_UIPC_CONNECT:
            try uipc_connect.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            try exchangedata.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_SETACL:
            try setacl.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETACL:
            try setacl.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
            try pty_grant.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
            try pty_close.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_PROC_CHECK:
            try proc_check.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            try proc_check.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_GET_TASK:
            try get_task.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_SEARCHFS:
            try searchfs.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
            try searchfs.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_FCNTL:
            try fcntl.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_IOKIT_OPEN:
            try iokit_open.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
            try proc_suspend_resume.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
            try proc_suspend_resume.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            try cs_invalidated.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
            try get_task_name.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_TRACE:
            try trace.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            try remote_thread_create.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_REMOUNT:
            try remount.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_REMOUNT:
            try remount.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_GET_TASK_READ:
            try get_task_read.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            try get_task_read.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
            try get_task_inspect.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETUID:
            try setuid.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETGID:
            try setuid.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETEUID:
            try setuid.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETEGID:
            try setuid.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETREUID:
            try setreuid.decode(from: &reader)
        case ES_EVENT_TYPE_NOTIFY_SETREGID:
            try setreuid.decode(from: &reader)
        case ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_NOTIFY_COPYFILE:
            try copyfile.decode(from: &reader)
        default:
            fatalError()
        }
    }
    
    func freeInternals(type: es_event_type_t) {
        switch type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            exec.freeInternals()
        case ES_EVENT_TYPE_AUTH_OPEN:
            open.freeInternals()
        case ES_EVENT_TYPE_AUTH_KEXTLOAD:
            kextload.freeInternals()
        case ES_EVENT_TYPE_AUTH_MMAP:
            mmap.freeInternals()
        case ES_EVENT_TYPE_AUTH_MPROTECT:
            mprotect.freeInternals()
        case ES_EVENT_TYPE_AUTH_MOUNT:
            mount.freeInternals()
        case ES_EVENT_TYPE_AUTH_RENAME:
            rename.freeInternals()
        case ES_EVENT_TYPE_AUTH_SIGNAL:
            signal.freeInternals()
        case ES_EVENT_TYPE_AUTH_UNLINK:
            unlink.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            exec.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            open.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_FORK:
            fork.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            close.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            create.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            exchangedata.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            exit.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            get_task.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            kextload.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            kextunload.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_LINK:
            link.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            mmap.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            mprotect.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            mount.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            unmount.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            iokit_open.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            rename.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            setattrlist.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            setextattr.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            setflags.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            setmode.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            setowner.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            signal.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            unlink.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            write.freeInternals()
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE:
            file_provider_materialize.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
            file_provider_materialize.freeInternals()
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE:
            file_provider_update.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
            file_provider_update.freeInternals()
        case ES_EVENT_TYPE_AUTH_READLINK:
            readlink.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_READLINK:
            readlink.freeInternals()
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            truncate.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            truncate.freeInternals()
        case ES_EVENT_TYPE_AUTH_LINK:
            link.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_LOOKUP:
            lookup.freeInternals()
        case ES_EVENT_TYPE_AUTH_CREATE:
            create.freeInternals()
        case ES_EVENT_TYPE_AUTH_SETATTRLIST:
            setattrlist.freeInternals()
        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
            setextattr.freeInternals()
        case ES_EVENT_TYPE_AUTH_SETFLAGS:
            setflags.freeInternals()
        case ES_EVENT_TYPE_AUTH_SETMODE:
            setmode.freeInternals()
        case ES_EVENT_TYPE_AUTH_SETOWNER:
            setowner.freeInternals()
        case ES_EVENT_TYPE_AUTH_CHDIR:
            chdir.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_CHDIR:
            chdir.freeInternals()
        case ES_EVENT_TYPE_AUTH_GETATTRLIST:
            getattrlist.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
            getattrlist.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_STAT:
            stat.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            access.freeInternals()
        case ES_EVENT_TYPE_AUTH_CHROOT:
            chroot.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_CHROOT:
            chroot.freeInternals()
        case ES_EVENT_TYPE_AUTH_UTIMES:
            utimes.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_UTIMES:
            utimes.freeInternals()
        case ES_EVENT_TYPE_AUTH_CLONE:
            clone.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_CLONE:
            clone.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            fcntl.freeInternals()
        case ES_EVENT_TYPE_AUTH_GETEXTATTR:
            getextattr.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
            getextattr.freeInternals()
        case ES_EVENT_TYPE_AUTH_LISTEXTATTR:
            listextattr.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
            listextattr.freeInternals()
        case ES_EVENT_TYPE_AUTH_READDIR:
            readdir.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_READDIR:
            readdir.freeInternals()
        case ES_EVENT_TYPE_AUTH_DELETEEXTATTR:
            deleteextattr.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            deleteextattr.freeInternals()
        case ES_EVENT_TYPE_AUTH_FSGETPATH:
            fsgetpath.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
            fsgetpath.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_DUP:
            dup.freeInternals()
        case ES_EVENT_TYPE_AUTH_SETTIME:
            settime.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETTIME:
            settime.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
            uipc_bind.freeInternals()
        case ES_EVENT_TYPE_AUTH_UIPC_BIND:
            uipc_bind.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            uipc_connect.freeInternals()
        case ES_EVENT_TYPE_AUTH_UIPC_CONNECT:
            uipc_connect.freeInternals()
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            exchangedata.freeInternals()
        case ES_EVENT_TYPE_AUTH_SETACL:
            setacl.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETACL:
            setacl.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
            pty_grant.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
            pty_close.freeInternals()
        case ES_EVENT_TYPE_AUTH_PROC_CHECK:
            proc_check.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            proc_check.freeInternals()
        case ES_EVENT_TYPE_AUTH_GET_TASK:
            get_task.freeInternals()
        case ES_EVENT_TYPE_AUTH_SEARCHFS:
            searchfs.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
            searchfs.freeInternals()
        case ES_EVENT_TYPE_AUTH_FCNTL:
            fcntl.freeInternals()
        case ES_EVENT_TYPE_AUTH_IOKIT_OPEN:
            iokit_open.freeInternals()
        case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
            proc_suspend_resume.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
            proc_suspend_resume.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            cs_invalidated.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
            get_task_name.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_TRACE:
            trace.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            remote_thread_create.freeInternals()
        case ES_EVENT_TYPE_AUTH_REMOUNT:
            remount.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_REMOUNT:
            remount.freeInternals()
        case ES_EVENT_TYPE_AUTH_GET_TASK_READ:
            get_task_read.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            get_task_read.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
            get_task_inspect.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETUID:
            setuid.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETGID:
            setuid.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETEUID:
            setuid.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETEGID:
            setuid.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETREUID:
            setreuid.freeInternals()
        case ES_EVENT_TYPE_NOTIFY_SETREGID:
            setreuid.freeInternals()
        case ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_NOTIFY_COPYFILE:
            copyfile.freeInternals()
        default:
            break
        }
    }
    
    enum Stru {
        case free
        case encode(((inout BinaryWriter) throws -> Void) throws -> Void)
        case decode(((inout BinaryReader) throws -> Void) throws -> Void)
        
        func callAsFunction<T: LocalConstructible>(_ value: inout T) throws {
            switch self {
            case .encode(let body):
                try body { try value.encode(with: &$0) }
            case .decode(let body):
                try body { try value.decode(from: &$0) }
            case .free:
                value.freeInternals()
            }
        }
    }
    
    mutating func withEvent(_ body: Stru) throws {
        try body(&exec)
    }
}


// MARK: - Events

extension es_event_exec_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        let version = try writer.userInfo.messageVersion()
        
        try target.pointee.encode(with: &writer)
        
        guard version >= 2 else { return }
        try script.encode(with: &writer)
        
        guard version >= 3 else { return }
        try cwd.pointee.encode(with: &writer)
        
        guard version >= 4 else { return }
        try writer.append(last_fd)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        let version = try reader.userInfo.messageVersion()
        
        do {
            target = try .allocate(from: &reader)
            
            guard version >= 2 else { return }
            script = try .allocate(from: &reader)
            
            guard version >= 3 else { return }
            cwd = try .allocate(from: &reader)
            
            guard version >= 4 else { return }
            last_fd = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
        script?.nullable?.freeAndDeallocate()
        cwd.nullable?.freeAndDeallocate()
    }
}

extension es_event_exit_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(stat)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            stat = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {}
}

extension es_event_open_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(fflag)
        try file.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            fflag = try reader.read()
            file = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        file.nullable?.freeAndDeallocate()
    }
}

extension es_event_access_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(mode)
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            mode = try reader.read()
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_create_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        let version = try writer.userInfo.messageVersion()
        
        try writer.append(destination_type)
        switch destination_type {
        case ES_DESTINATION_TYPE_NEW_PATH:
            try destination.new_path.dir.pointee.encode(with: &writer)
            try destination.new_path.filename.encode(with: &writer)
            try writer.append(destination.new_path.mode)
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            try destination.existing_file.pointee.encode(with: &writer)
        default:
            throw CommonError.unexpected("Unsupported destination_type = \(destination_type)")
        }
        
        guard version >= 2 else { return }
        //  acl field is skipped b/c it is opaque pointer and cannot be copied
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        var destinationTypeRead = false
        do {
            let version = try reader.userInfo.messageVersion()
            
            destination_type = try reader.read()
            destinationTypeRead = true
            
            switch destination_type {
            case ES_DESTINATION_TYPE_NEW_PATH:
                destination.new_path.dir = try .allocate(from: &reader)
                try destination.new_path.filename.decode(from: &reader)
                destination.new_path.mode = try reader.read()
            case ES_DESTINATION_TYPE_EXISTING_FILE:
                destination.existing_file = try .allocate(from: &reader)
            default:
                throw CommonError.unexpected("Unsupported destination_type = \(destination_type)")
            }
            
            guard version >= 2 else { return }
            //  acl field is skipped b/c it is opaque pointer and cannot be copied
        } catch {
            if destinationTypeRead {
                freeInternals()
            }
            throw error
        }
    }
    
    func freeInternals() {
        switch destination_type {
        case ES_DESTINATION_TYPE_NEW_PATH:
            destination.new_path.dir.nullable?.freeAndDeallocate()
            destination.new_path.filename.freeInternals()
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            destination.existing_file.nullable?.freeAndDeallocate()
        default:
            break
        }
    }
}

extension es_event_write_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_truncate_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            try target = .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_exchangedata_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try file1.pointee.encode(with: &writer)
        try file2.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            file1 = try .allocate(from: &reader)
            file2 = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        file1.nullable?.freeAndDeallocate()
        file2.nullable?.freeAndDeallocate()
    }
}

extension es_event_rename_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try source.pointee.encode(with: &writer)
        try writer.append(destination_type)
        switch destination_type {
        case ES_DESTINATION_TYPE_NEW_PATH:
            try destination.new_path.dir.pointee.encode(with: &writer)
            try destination.new_path.filename.encode(with: &writer)
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            try destination.existing_file.pointee.encode(with: &writer)
        default:
            throw CommonError.unexpected("Unsupported destination_type = \(destination_type)")
        }
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        var destinationTypeRead = false
        do {
            source = try .allocate(from: &reader)
            
            destination_type = try reader.read()
            destinationTypeRead = true
            
            switch destination_type {
            case ES_DESTINATION_TYPE_NEW_PATH:
                destination.new_path.dir = try .allocate(from: &reader)
                try destination.new_path.filename.decode(from: &reader)
            case ES_DESTINATION_TYPE_EXISTING_FILE:
                destination.existing_file = try .allocate(from: &reader)
            default:
                throw CommonError.unexpected("Unsupported destination_type = \(destination_type)")
            }
        } catch {
            if destinationTypeRead {
                freeInternals()
            }
            throw error
        }
    }
    
    func freeInternals() {
        source.nullable?.freeAndDeallocate()
        
        switch destination_type {
        case ES_DESTINATION_TYPE_NEW_PATH:
            destination.new_path.dir.nullable?.freeAndDeallocate()
            destination.new_path.filename.freeInternals()
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            destination.existing_file.nullable?.freeAndDeallocate()
        default:
            break
        }
    }
}

extension es_event_clone_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try source.pointee.encode(with: &writer)
        try target_dir.pointee.encode(with: &writer)
        try target_name.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            source = try .allocate(from: &reader)
            target_dir = try .allocate(from: &reader)
            try target_name.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        source.nullable?.freeAndDeallocate()
        target_dir.nullable?.freeAndDeallocate()
        target_name.freeInternals()
    }
}

extension es_event_copyfile_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try source.pointee.encode(with: &writer)
        try target_file.encode(with: &writer)
        try target_dir.pointee.encode(with: &writer)
        try target_name.encode(with: &writer)
        try writer.append(mode)
        try writer.append(flags)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            source = try .allocate(from: &reader)
            target_file = try .allocate(from: &reader)
            target_dir = try .allocate(from: &reader)
            try target_name.decode(from: &reader)
            mode = try reader.read()
            flags = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        source.nullable?.freeAndDeallocate()
        target_file?.nullable?.freeAndDeallocate()
        target_dir.nullable?.freeAndDeallocate()
        target_name.freeInternals()
    }
}

extension es_event_close_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(modified)
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            modified = try reader.read()
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_link_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try source.pointee.encode(with: &writer)
        try target_dir.pointee.encode(with: &writer)
        try target_filename.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            source = try .allocate(from: &reader)
            target_dir = try .allocate(from: &reader)
            try target_filename.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        source.nullable?.freeAndDeallocate()
        target_dir.nullable?.freeAndDeallocate()
        target_filename.freeInternals()
    }
}

extension es_event_unlink_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
        try parent_dir.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
            parent_dir = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
        parent_dir.nullable?.freeAndDeallocate()
    }
}

extension es_event_lookup_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try source_dir.pointee.encode(with: &writer)
        try relative_target.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            source_dir = try .allocate(from: &reader)
            try relative_target.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        source_dir.nullable?.freeAndDeallocate()
        relative_target.freeInternals()
    }
}

extension es_event_readdir_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_readlink_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try source.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            source = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        source.nullable?.freeAndDeallocate()
    }
}

extension es_event_chdir_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_chroot_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_dup_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            try target = .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_file_provider_materialize_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try instigator.pointee.encode(with: &writer)
        try source.pointee.encode(with: &writer)
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            instigator = try .allocate(from: &reader)
            source = try .allocate(from: &reader)
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        instigator.nullable?.freeAndDeallocate()
        source.nullable?.freeAndDeallocate()
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_file_provider_update_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try source.pointee.encode(with: &writer)
        try target_path.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            source = try .allocate(from: &reader)
            try target_path.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        source.nullable?.freeAndDeallocate()
        target_path.freeInternals()
    }
}

extension es_event_fork_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try child.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            child = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        child.nullable?.freeAndDeallocate()
    }
}

extension es_event_signal_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(sig)
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            sig = try reader.read()
            try target = .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_fsgetpath_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_get_task_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_get_task_read_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_get_task_inspect_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_get_task_name_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_fcntl_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
        try writer.append(cmd)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
            cmd = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_iokit_open_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(user_client_type)
        try user_client_class.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            try user_client_type = reader.read()
            try user_client_class.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        user_client_class.freeInternals()
    }
}

extension es_event_kextload_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try identifier.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            try identifier.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        identifier.freeInternals()
    }
}

extension es_event_kextunload_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try identifier.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            try identifier.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        identifier.freeInternals()
    }
}

extension es_event_mount_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(statfs.pointee)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            statfs = .allocate(capacity: 1)
            statfs.initialize(to: try reader.read())
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        statfs.nullable?.deallocate()
    }
}

extension es_event_unmount_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(statfs.pointee)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            statfs = .allocate(capacity: 1)
            statfs.initialize(to: try reader.read())
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        statfs.nullable?.deallocate()
    }
}

extension es_event_remount_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(statfs.pointee)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            statfs = .allocate(capacity: 1)
            statfs.initialize(to: try reader.read())
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        statfs.nullable?.deallocate()
    }
}

extension es_event_mmap_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(protection)
        try writer.append(max_protection)
        try writer.append(flags)
        try writer.append(file_pos)
        try source.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            protection = try reader.read()
            max_protection = try reader.read()
            flags = try reader.read()
            file_pos = try reader.read()
            source = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        source.nullable?.freeAndDeallocate()
    }
}

extension es_event_mprotect_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(protection)
        try writer.append(address)
        try writer.append(size)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            protection = try reader.read()
            address = try reader.read()
            size = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {}
}

extension es_event_proc_check_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.encode(with: &writer)
        try writer.append(type.rawValue)
        try writer.append(flavor)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
            type = try .init(reader.read())
            flavor = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target?.nullable?.freeAndDeallocate()
    }
}

extension es_event_proc_suspend_resume_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.encode(with: &writer)
        try writer.append(type.rawValue)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
            type = try .init(reader.read())
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target?.nullable?.freeAndDeallocate()
    }
}

extension es_event_pty_close_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(dev)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            dev = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {}
}

extension es_event_pty_grant_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(dev)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            dev = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {}
}

extension es_event_remote_thread_create_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
        try thread_state.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
            thread_state = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
        thread_state?.nullable?.freeAndDeallocate()
    }
}

extension es_event_searchfs_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(attrlist)
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            attrlist = try reader.read()
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_setacl_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        //  TODO: acl_t currently is not supported
        
        try target.pointee.encode(with: &writer)
        try writer.append(set_or_clear)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
            set_or_clear = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_getattrlist_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(attrlist)
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            attrlist = try reader.read()
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_setattrlist_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(attrlist)
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            attrlist = try reader.read()
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_listextattr_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_getextattr_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
        try extattr.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
            try extattr.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
        extattr.freeInternals()
    }
}

extension es_event_setextattr_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
        try extattr.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
            try extattr.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
        extattr.freeInternals()
    }
}

extension es_event_deleteextattr_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
        try extattr.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            try target = .allocate(from: &reader)
            try extattr.decode(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
        extattr.freeInternals()
    }
}

extension es_event_setflags_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(flags)
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            flags = try reader.read()
            try target = .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_setmode_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(mode)
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            mode = try reader.read()
            try target = .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_setuid_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(uid)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        uid = try reader.read()
    }
    
    func freeInternals() {}
}

extension es_event_setgid_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(gid)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        gid = try reader.read()
    }
    
    func freeInternals() {}
}

extension es_event_seteuid_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(euid)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        euid = try reader.read()
    }
    
    func freeInternals() {}
}

extension es_event_setegid_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(egid)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        egid = try reader.read()
    }
    
    func freeInternals() {}
}

extension es_event_setreuid_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(ruid)
        try writer.append(euid)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        ruid = try reader.read()
        euid = try reader.read()
    }
    
    func freeInternals() {}
}

extension es_event_setregid_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(rgid)
        try writer.append(egid)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        rgid = try reader.read()
        egid = try reader.read()
    }
    
    func freeInternals() {}
}

extension es_event_setowner_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try writer.append(uid)
        try writer.append(gid)
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            uid = try reader.read()
            gid = try reader.read()
            try target = .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_settime_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {}
    
    mutating func decode(from reader: inout BinaryReader) throws {}
    
    func freeInternals() {}
}

extension es_event_stat_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            try target = .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_trace_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            try target = .allocate(from: &reader)
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_uipc_bind_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try dir.pointee.encode(with: &writer)
        try filename.encode(with: &writer)
        try writer.append(mode)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            
            dir = try .allocate(from: &reader)
            try filename.decode(from: &reader)
            mode = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        dir.nullable?.freeAndDeallocate()
        filename.freeInternals()
    }
}

extension es_event_uipc_connect_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try file.pointee.encode(with: &writer)
        try writer.append(domain)
        try writer.append(type)
        try writer.append(`protocol`)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            file = try .allocate(from: &reader)
            domain = try reader.read()
            type = try reader.read()
            `protocol` = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        file.nullable?.freeAndDeallocate()
    }
}

extension es_event_utimes_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {
        try target.pointee.encode(with: &writer)
        try writer.append(atime)
        try writer.append(mtime)
    }
    
    mutating func decode(from reader: inout BinaryReader) throws {
        do {
            target = try .allocate(from: &reader)
            atime = try reader.read()
            mtime = try reader.read()
        } catch {
            freeInternals()
            throw error
        }
    }
    
    func freeInternals() {
        target.nullable?.freeAndDeallocate()
    }
}

extension es_event_cs_invalidated_t: LocalConstructible {
    func encode(with writer: inout BinaryWriter) throws {}
    
    mutating func decode(from reader: inout BinaryReader) throws {}
    
    func freeInternals() {}
}
