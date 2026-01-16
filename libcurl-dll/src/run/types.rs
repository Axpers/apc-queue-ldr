use std::ffi::c_void;

use windows_sys::Wdk::System::Memory::SECTION_INHERIT;

pub type HANDLE = isize;

pub type NtAllocateVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;

pub type NtWriteVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;

pub type NtQueueApcThreadEx = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
) -> i32;

pub type NtOpenProcess =
    unsafe extern "system" fn(*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut CLIENT_ID) -> i32;

pub type NtOpenThread =
    unsafe extern "system" fn(*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut CLIENT_ID) -> i32;

pub type NtClose = unsafe extern "system" fn(HANDLE) -> i32;

pub type NtCreateFile = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *mut OBJECT_ATTRIBUTES,
    *mut IO_STATUS_BLOCK,
    *mut i64,
    u32,
    u32,
    u32,
    u32,
    *mut c_void,
    u32,
) -> i32;

pub type NtCreateSection = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *mut OBJECT_ATTRIBUTES,
    *mut i64,
    u32,
    u32,
    HANDLE,
) -> i32;

pub type NtMapViewOfSection = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *mut *mut c_void,
    usize,
    usize,
    *mut i64,
    *mut usize,
    SECTION_INHERIT,
    u32,
    u32,
) -> i32;

pub type NtUnmapViewOfSection = unsafe extern "system" fn(HANDLE, *mut c_void) -> i32;

pub type NtProtectVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;

#[repr(C)]
#[allow(non_snake_case)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut c_void,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct IO_STATUS_BLOCK {
    pub Status: i32,
    pub Information: usize,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}
