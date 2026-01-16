mod run;

use crate::run::run;

#[unsafe(no_mangle)]
pub extern "system" fn curl_easy_setopt() {}

#[unsafe(no_mangle)]
pub extern "system" fn curl_easy_cleanup() {}

#[unsafe(no_mangle)]
pub extern "system" fn curl_easy_perform() {}

#[unsafe(no_mangle)]
pub extern "system" fn curl_easy_init() {
    run();
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_: usize, _: u32, _: usize) -> i32 {
    1
}
