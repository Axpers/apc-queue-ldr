use std::ffi::CStr;
use windows_sys::Win32::{
    Foundation::HINSTANCE,
    System::{
        Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS64},
        Kernel::LIST_ENTRY,
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
        Threading::PEB,
        WindowsProgramming::LDR_DATA_TABLE_ENTRY,
    },
};

pub fn get_module_base_addr(module_name: &str) -> HINSTANCE {
    unsafe {
        let peb = get_current_peb();
        let mut p_ldr_data_table_entry =
            (*(*peb).Ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut p_list_entry = &(*(*peb).Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;

        loop {
            let buffer = std::slice::from_raw_parts(
                (*p_ldr_data_table_entry).FullDllName.Buffer,
                (*p_ldr_data_table_entry).FullDllName.Length as usize / 2,
            );
            let dll_name = String::from_utf16_lossy(buffer);

            if dll_name.to_lowercase().contains(module_name) {
                return (*p_ldr_data_table_entry).Reserved2[0] as HINSTANCE;
            }

            if p_list_entry == (*(*peb).Ldr).InMemoryOrderModuleList.Blink {
                return std::ptr::null_mut();
            }

            p_list_entry = (*p_list_entry).Flink;
            p_ldr_data_table_entry = (*p_list_entry).Flink as *const LDR_DATA_TABLE_ENTRY;
        }
    }
}

// Usage
// pub type MessageBoxA = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;
// let user32_base_address = get_module_base_addr(obfstr!("user32.dll"))
// let message_box_a: MessageBoxA = transmute(get_proc_addr(user32_base_address, obfstr!("MessageBoxA")));

pub fn get_proc_addr(module_handle: HINSTANCE, function: &str) -> *mut usize {
    unsafe {
        if module_handle.is_null() {
            return std::ptr::null_mut();
        }

        let dos_header = module_handle as *const IMAGE_DOS_HEADER;
        let nt_header =
            (module_handle as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let data_directory =
            &(*nt_header).OptionalHeader.DataDirectory[0] as *const IMAGE_DATA_DIRECTORY;
        let export_directory = (module_handle as usize + (*data_directory).VirtualAddress as usize)
            as *const IMAGE_EXPORT_DIRECTORY;

        let address_array = (module_handle as usize
            + (*export_directory).AddressOfFunctions as usize)
            as *const u32;
        let mut name_array =
            (module_handle as usize + (*export_directory).AddressOfNames as usize) as *const u32;
        let mut name_ordinals = (module_handle as usize
            + (*export_directory).AddressOfNameOrdinals as usize)
            as *const u16;

        for _ in 0..(*export_directory).NumberOfNames {
            let name_offset = *name_array;
            let current_function =
                CStr::from_ptr((module_handle as usize + name_offset as usize) as *const i8)
                    .to_str()
                    .unwrap_or("");

            if current_function == function {
                let ordinal = *name_ordinals;
                let function_rva = *address_array.add(ordinal as usize);
                let function_addr = (module_handle as usize + function_rva as usize) as *mut usize;
                return function_addr;
            }

            name_array = name_array.add(1);
            name_ordinals = name_ordinals.add(1);
        }

        std::ptr::null_mut()
    }
}

fn get_current_peb() -> *const PEB {
    __readgsqword(0x60) as *const PEB
}

#[inline(always)]
fn __readgsqword(offset: u64) -> u64 {
    unsafe {
        let out: u64;
        core::arch::asm!(
            "mov {}, gs:[{:e}]",
            lateout(reg) out,
            in(reg) offset,
            options(nostack, pure, readonly),
        );
        out
    }
}
