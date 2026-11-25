# Reverse Engineering and Partial Devirtualization of BattlEye's `BEDaisy.sys` (VMProtect 3.8+)

> [!IMPORTANT]
> **Note (Partial Devirtualization):** Not every function in `BEDaisy.sys` was devirtualized. Out of `224` `RUNTIME_FUNCTION` entries in the PE exception table (`87` virtualized with VMProtect, `123` mutated, `14` native), we recovered and patched **`84` functions (`37.5%`)** into `.devirt`: **`46` of `87`** virtualized functions, **`36` of `123`** mutated functions, and `2` entry/helper routines (`GsDriverEntry` plus `1` native stub). The other **`41` virtualized functions** (including `DriverMain` at `0x10b20` and the main `IRP_MJ_DEVICE_CONTROL` handler) and **`87` mutated or non-code PDATA entries** are still in `.be0`.
>
> **Before & After Binaries:** [https://github.com/est1mate/est1mate.github.io/tree/main/battleye](https://github.com/est1mate/est1mate.github.io/tree/main/battleye)

---

## 1. Target Binary and Protection Overview

`BEDaisy.sys` is BattlEye's 64-bit Windows kernel anti-cheat driver (`IMAGE_FILE_MACHINE_AMD64 = 0x8664`, `IMAGE_SUBSYSTEM_NATIVE = 1`). The analyzed build has `TimeDateStamp = 0x660f34f6` (`2024-04-04 23:17:10 UTC`), a file size of `5,148,848` bytes (`SizeOfImage = 0x4eb000`, `ImageBase = 0x140000000`, PE CheckSum `0x4ed4cc`), and a `20,656`-byte Microsoft WHQL Authenticode signature (`Microsoft Windows Hardware Compatibility Publisher`, valid `2024-01-11` to `2025-01-10`, issued under `Microsoft Windows Third Party Component CA 2014`). Its SHA-256 hash is `0de4ca95303c938bbe97494a22021cc3b393052073fc22b1aeb20185350815e8`.

Opening `BEDaisy.sys` in a disassembler shows four things VMProtect 3.5+/3.8+ does to the binary:

1. **Import hiding:** The PE Import Directory (`RVA 0x1a090`) lists only 6 imports: `FltGetRoutineAddress` from `FLTMGR.SYS`, and `MmGetSystemRoutineAddress`, `__C_specific_handler`, `__chkstk`, `MmMapLockedPagesSpecifyCache`, and `KeBugCheckEx` from `ntoskrnl.exe`. Process/thread/image notify registration, handle-table enumeration, physical memory mapping, APC queuing, object callbacks, minifilter registration, and file/section routines are resolved at boot into `123` `.data` function pointers.
2. **Zero static UTF-16LE strings:** Outside `.be0`, `.rdata` (`4` ASCII strings), `.data` (`8` ASCII strings), and `INIT` (`8` ASCII strings) contain zero UTF-16LE strings. Device paths (`\Device\BattlEye`, `\DosDevices\BattlEye`), section names (`\Device\PhysicalMemory`), minifilter altitudes (`363220`), module/process names (`csrss.exe`, `dxgkrnl.sys`, `ntdll.dll`), and all `124` kernel API strings are decrypted or written onto the stack right before use.
3. **Instruction mutation and jump-chains in `.text` and `.be0`:** Of the `224` entries in the PE Exception Directory (`RVA 0x4e8cd0`), `123` are mutated. Basic blocks are broken into 1-to-5 instruction pieces linked by `2,858` unconditional `jmp rel32` jumps, padded with dead flag/register ops (`sal`, `rcr`, `btr`, `btc`, `cmovo`, `setns`, `xadd`, `bswap`) and Mixed Boolean-Arithmetic (MBA) expressions.
4. **10 separate VM interpreters:** `87` entries (`38.8%` of the PDATA table, including `GsDriverEntry`, `DriverMain`, `BeDriverUnload`, all `IRP_MJ_*` dispatch routines, PE header checks, and kernel object queries) jump into **10 VMProtect 3.8+ bytecode interpreters** in `.be0` (`4.80 MiB`). Each VM uses its own hardware register assignment for the virtual instruction pointer (`VIP`), virtual stack pointer (`VSP`), bytecode direction (forward or backward), rolling decryption key, and handler jump registers.

Using `Unicorn`, `Capstone`, `Triton`, `Z3` and `llvmlite` we dumped the dynamically resolved imports and stack strings, mapped out all 10 VM interpreters, lifted `84` functions through `LLVM` (`-O3`) into a new `.devirt` section (`5,430,272` bytes, SHA-256 `3a7b6b7ddfc0cf1ecd0a7563ad192ff97e9461786c763964cf1cc19d55057d13`), and compared each patched function's behavior against the original binary in `Unicorn`. Before and after files are on GitHub at [https://github.com/est1mate/est1mate.github.io/tree/main/battleye](https://github.com/est1mate/est1mate.github.io/tree/main/battleye).

---

## 2. Binary Layout, Unpacking Analysis, and Boot Flow

### 2.1 Section Layout and No Runtime Packer

Even though `.be0` is `4.80 MiB` with `7.7169` Shannon entropy and the header only lists `6` imports, `BEDaisy.sys` is not packed:

| Section | RVA | Virtual Size | Raw Offset | Raw Size | Flags | Perms | Entropy | Zero Ratio | Contents |
|---|---:|---:|---:|---:|---|---|---:|---:|---|
| `.text` | `0x001000` | `0x0134cf` | `0x000400` | `0x013600` | `0x68000020` | `R-X` | `7.8859` | `2.69%` | `117` PDATA entries: native routines, mutated prologues, `jmp .be0` thunks |
| `.rdata` | `0x015000` | `0x001014` | `0x013a00` | `0x001200` | `0x48000040` | `R--` | `5.2933` | `35.05%` | 6-entry static IAT (`0x15000..0x15038`), `LOAD_CONFIG` (`0x15210`), `UNWIND_INFO` |
| `.data` | `0x017000` | `0x001011` | `0x014c00` | `0x000200` | `0xc8000040` | `RW-` | `4.8341` | `43.75%` | `0x200` initialized bytes (`__security_cookie` at `0x17120`) + `0xe11` BSS (`.data` IAT `0x17290..0x177b0`, mutex `0x171e0`, state globals) |
| `.pdata` | `0x019000` | `0x000588` | `0x014e00` | `0x000600` | `0x48000040` | `R--` | `7.5742` | `8.14%` | Compiler `.pdata` superseded by `.be0` exception directory |
| `INIT` | `0x01a000` | `0x0001b2` | `0x015400` | `0x000200` | `0x60000020` | `R-X` | `4.8551` | `37.11%` | Entry point (`0x1a000`), `__security_init_cookie` (`0x1a02c`), Import Table (`0x1a090`) |
| `.be0` | `0x01b000` | `0x4ce750` | `0x015600` | `0x4ce800` | `0x68000020` | `R-X` | `7.7169` | `3.45%` | `10` VM interpreters, handler pool, VM bytecode, mutated code, active `PDATA` (`0x4e8cd0`, `224` entries) |
| `.reloc` | `0x4ea000` | `0x0000f8` | `0x015400` | `0x000200` | `0x42000040` | `R--` | `2.2164` | `75.00%` | `20` base-relocation blocks (`44` `DIR64` entries; raw offset `0x4e3e00`) |

No section carries both `IMAGE_SCN_MEM_WRITE` (`0x80000000`) and `IMAGE_SCN_MEM_EXECUTE` (`0x20000000`). Windows HVCI (Hypervisor-Protected Code Integrity) blocks kernel drivers with `RWX` sections or self-modifying code pages, so VMProtect protects `BEDaisy.sys` through static virtualization and code mutation inside read-execute pages (`.text` and `.be0`). Writable runtime state lives in `.data` (`0x17000..0x18011`, where `VirtualSize = 0x1011` exceeds `RawSize = 0x200` to allocate BSS space for resolved pointers) and on the kernel stack.

### 2.2 Entry Point Flow (`0x14001a000` -> `GsDriverEntry` -> `DriverMain`)

`AddressOfEntryPoint` is `INIT:0x14001a000`, which executes a 5-byte relative jump (`e9 c8 69 ff ff`) to `0x1400109cd` (`GsDriverEntry` in `.text`). Disassembly of `0x1400109cd` shows the mutated prologue before jumping into VM #5 (`0x140330e68`):

```x86asm
0x14001a000 (+0x01a000):  e9c869ffff              jmp      0x1400109cd
; --- GsDriverEntry mutated entry stub (.text) ---
0x1400109cd (+0x0109cd):  57                      push     rdi
0x1400109ce (+0x0109ce):  48bf96eab3d687d2bc11    movabs   rdi, 0x11bcd287d6b3ea96
0x1400109d8 (+0x0109d8):  9c                      pushfq
0x1400109d9 (+0x0109d9):  f7c79049b8ea            test     edi, 0xeab84990      ; clears OF=0, CF=0
0x1400109df (+0x0109df):  4155                    push     r13
0x1400109e1 (+0x0109e1):  0f80e7ffffff            jo       0x1400109ce          ; dead branch (OF==0 always)
0x1400109e7 (+0x0109e7):  6814b23d6f              push     0x6f3db214
0x1400109ec (+0x0109ec):  488b7c2418              mov      rdi, qword ptr [rsp + 0x18]
0x1400109f1 (+0x0109f1):  48c7442418898ccebc      mov      qword ptr [rsp + 0x18], 0xffffffffbcce8c89
0x1400109fa (+0x0109fa):  803c2428                cmp      byte ptr [rsp], 0x28 ; compares 0x14 vs 0x28 -> CF=1, ZF=0
0x1400109ff (+0x0109ff):  4c8b2c24                mov      r13, qword ptr [rsp]
0x140010a04 (+0x010a04):  0f87e2ffffff            ja       0x1400109ec          ; dead branch (0x14 > 0x28 is false)
0x140010a0a (+0x010a0a):  490fcd                  bswap    r13
0x140010a0d (+0x010a0d):  53                      push     rbx
0x140010a0e (+0x010a0e):  ff742418                push     qword ptr [rsp + 0x18]
0x140010a12 (+0x010a12):  9d                      popfq
0x140010a13 (+0x010a13):  4889742418              mov      qword ptr [rsp + 0x18], rsi
0x140010a18 (+0x010a18):  4c8b6c2410              mov      r13, qword ptr [rsp + 0x10]
0x140010a1d (+0x010a1d):  488b5c2408              mov      rbx, qword ptr [rsp + 8]
0x140010a22 (+0x010a22):  488b9c1c14b23d6f        mov      rbx, qword ptr [rsp + rbx - 0x6f3db214] ; [rsp] since rbx=0x6f3db214
0x140010a2a (+0x010a2a):  48c7442408b5d226df      mov      qword ptr [rsp + 8], 0xffffffffdf26d2b5 ; encrypted bytecode seed
0x140010a33 (+0x010a33):  488d642418              lea      rsp, [rsp + 0x18]
0x140010a38 (+0x010a38):  e92b043200              jmp      0x140330e68          ; enter VM #5
```

Two obfuscation patterns appear in `0x109cd..0x10a38`:
1. `test edi, 0xeab84990` clears `OF = 0`, making `jo 0x1400109ce` a dead backward jump aimed at recursive-descent disassemblers. Likewise, `push 0x6f3db214` writes `0x14` to `[rsp]`, so `cmp byte ptr [rsp], 0x28; ja 0x1400109ec` (`0x14 > 0x28`) never branches.
2. `0x10a22` sets `rbx = 0x6f3db214` and reads `[rsp + rbx - 0x6f3db214]`, masking a `[rsp]` load behind a 32-bit displacement before pushing bytecode seed `0xffffffffdf26d2b5` and jumping to VM #5 (`0x140330e68`).

Emulation from `0x14001a000` records the `.be0` and native transition sequence:
- **Steps `1..25`:** Runs the `0x109cd` stub and enters `.be0` (`0x330e68`, VM #5).
- **Steps `25..17,301`:** VM #5 preserves `RCX` (`DriverObject`) and `RDX` (`RegistryPath`), then exits `.be0` to `0x14001a02c` (`__security_init_cookie` in `INIT`).
- **Steps `17,301..17,321`:** `__security_init_cookie` zeroes `.data+0x17126` (`2B = 0`), reads `g_SecurityCookie` at `0x140017120` (`0x0000136cfbf29f11`), writes `~g_SecurityCookie` (`0xffffec93040d60ee`, or `-0x136cfbf29f12`) to `g_SecurityCookieComplement` at `0x140017128`, and re-enters `.be0` at `0x4e8c49`.
- **Steps `17,321..21,277`:** VM #5 restores `RCX = DriverObject` and `RDX = RegistryPath`, unwinds its frame, and jumps to `DriverMain` (`0x140010b20`), which enters VM #6 (`0x14037dbff`) at step `21,310`.

### 2.3 Dynamic IAT Reconstruction (`123` `.data` Slots, `124` Resolved APIs)

Inside `DriverMain` (`0x10b20`), execution calls `ntoskrnl.exe!__chkstk` with `RAX = 0x1b30` (`6,960` stack bytes; zeroing `RAX` in an emulator stub corrupts the following `sub rsp, rax` and faults at step `34,618`). With `RAX` preserved, `DriverMain` decodes UTF-16LE and ASCII symbol names inside the VM, calling `MmGetSystemRoutineAddress` `116` times and `FltGetRoutineAddress` `8` times (`124` resolutions) to fill **`123` 8-byte pointer slots** in `.data` (`0x140017290..0x1400177b0`; `wcslen` is used during bootstrap while `123` slots persist).

Compiled routines index these `.data` pointers relative to `g_GlobalMutex` (`0x1400171e0`) or nearby `.data` bases (`[rdi + 0x148]` = `0x17328` `KeWaitForSingleObject`, `[rdi + 0x188]` = `0x17368` `IofCompleteRequest`). All `123` `.data` IAT slots are listed below:

| # | `.data` RVA | Virtual Address | Offset vs `0x171e0` | Resolved Kernel / Minifilter Symbol |
|---:|---|---|---:|---|
| 1 | `0x17290` | `0x140017290` | `+0xb0` | `ntoskrnl!_stricmp` |
| 2 | `0x17298` | `0x140017298` | `+0xb8` | `ntoskrnl!_strnicmp` |
| 3 | `0x172a0` | `0x1400172a0` | `+0xc0` | `ntoskrnl!wcsncmp` |
| 4 | `0x172a8` | `0x1400172a8` | `+0xc8` | `ntoskrnl!_wcsnicmp` |
| 5 | `0x172b0` | `0x1400172b0` | `+0xd0` | `ntoskrnl!wcsncat` |
| 6 | `0x172b8` | `0x1400172b8` | `+0xd8` | `ntoskrnl!wcsstr` |
| 7 | `0x172c0` | `0x1400172c0` | `+0xe0` | `ntoskrnl!_wcsicmp` |
| 8 | `0x172c8` | `0x1400172c8` | `+0xe8` | `ntoskrnl!_wcslwr` |
| 9 | `0x172d0` | `0x1400172d0` | `+0xf0` | `ntoskrnl!RtlInitAnsiString` |
| 10 | `0x172d8` | `0x1400172d8` | `+0xf8` | `ntoskrnl!RtlInitUnicodeString` |
| 11 | `0x172e0` | `0x1400172e0` | `+0x100` | `ntoskrnl!RtlAnsiStringToUnicodeString` |
| 12 | `0x172e8` | `0x1400172e8` | `+0x108` | `ntoskrnl!RtlUnicodeStringToAnsiString` |
| 13 | `0x172f0` | `0x1400172f0` | `+0x110` | `ntoskrnl!RtlFreeUnicodeString` |
| 14 | `0x172f8` | `0x1400172f8` | `+0x118` | `ntoskrnl!RtlFreeAnsiString` |
| 15 | `0x17300` | `0x140017300` | `+0x120` | `ntoskrnl!RtlGetVersion` |
| 16 | `0x17308` | `0x140017308` | `+0x128` | `ntoskrnl!KeInitializeEvent` |
| 17 | `0x17310` | `0x140017310` | `+0x130` | `ntoskrnl!KeSetEvent` |
| 18 | `0x17318` | `0x140017318` | `+0x138` | `ntoskrnl!KeInitializeMutex` |
| 19 | `0x17320` | `0x140017320` | `+0x140` | `ntoskrnl!KeReleaseMutex` |
| 20 | `0x17328` | `0x140017328` | `+0x148` | `ntoskrnl!KeWaitForSingleObject` |
| 21 | `0x17330` | `0x140017330` | `+0x150` | `ntoskrnl!ExAllocatePoolWithTag` |
| 22 | `0x17338` | `0x140017338` | `+0x158` | `ntoskrnl!ExAllocatePool` |
| 23 | `0x17340` | `0x140017340` | `+0x160` | `ntoskrnl!ExFreePoolWithTag` |
| 24 | `0x17348` | `0x140017348` | `+0x168` | `ntoskrnl!ProbeForRead` |
| 25 | `0x17350` | `0x140017350` | `+0x170` | `ntoskrnl!ProbeForWrite` |
| 26 | `0x17358` | `0x140017358` | `+0x178` | `ntoskrnl!PsCreateSystemThread` |
| 27 | `0x17360` | `0x140017360` | `+0x180` | `ntoskrnl!PsTerminateSystemThread` |
| 28 | `0x17368` | `0x140017368` | `+0x188` | `ntoskrnl!IofCompleteRequest` |
| 29 | `0x17370` | `0x140017370` | `+0x190` | `ntoskrnl!IoCreateDevice` |
| 30 | `0x17378` | `0x140017378` | `+0x198` | `ntoskrnl!IoCreateSymbolicLink` |
| 31 | `0x17380` | `0x140017380` | `+0x1a0` | `ntoskrnl!IoDeleteDevice` |
| 32 | `0x17388` | `0x140017388` | `+0x1a8` | `ntoskrnl!IoDeleteSymbolicLink` |
| 33 | `0x17390` | `0x140017390` | `+0x1b0` | `ntoskrnl!IoGetCurrentProcess` |
| 34 | `0x17398` | `0x140017398` | `+0x1b8` | `ntoskrnl!IoGetTopLevelIrp` |
| 35 | `0x173a0` | `0x1400173a0` | `+0x1c0` | `ntoskrnl!ObReferenceObjectByHandle` |
| 36 | `0x173a8` | `0x1400173a8` | `+0x1c8` | `ntoskrnl!ObfReferenceObject` |
| 37 | `0x173b0` | `0x1400173b0` | `+0x1d0` | `ntoskrnl!ObfDereferenceObject` |
| 38 | `0x173b8` | `0x1400173b8` | `+0x1d8` | `ntoskrnl!ObRegisterCallbacks` |
| 39 | `0x173c0` | `0x1400173c0` | `+0x1e0` | `ntoskrnl!ObUnRegisterCallbacks` |
| 40 | `0x173c8` | `0x1400173c8` | `+0x1e8` | `ntoskrnl!ZwOpenFile` |
| 41 | `0x173d0` | `0x1400173d0` | `+0x1f0` | `ntoskrnl!ZwQueryInformationFile` |
| 42 | `0x173d8` | `0x1400173d8` | `+0x1f8` | `ntoskrnl!ZwReadFile` |
| 43 | `0x173e0` | `0x1400173e0` | `+0x200` | `ntoskrnl!ZwClose` |
| 44 | `0x173e8` | `0x1400173e8` | `+0x208` | `ntoskrnl!MmIsAddressValid` |
| 45 | `0x173f0` | `0x1400173f0` | `+0x210` | `ntoskrnl!PsSetCreateProcessNotifyRoutineEx` |
| 46 | `0x173f8` | `0x1400173f8` | `+0x218` | `ntoskrnl!PsSetCreateThreadNotifyRoutine` |
| 47 | `0x17400` | `0x140017400` | `+0x220` | `ntoskrnl!PsRemoveCreateThreadNotifyRoutine` |
| 48 | `0x17408` | `0x140017408` | `+0x228` | `ntoskrnl!PsSetLoadImageNotifyRoutine` |
| 49 | `0x17410` | `0x140017410` | `+0x230` | `ntoskrnl!PsRemoveLoadImageNotifyRoutine` |
| 50 | `0x17418` | `0x140017418` | `+0x238` | `ntoskrnl!PsGetCurrentProcessId` |
| 51 | `0x17420` | `0x140017420` | `+0x240` | `ntoskrnl!PsGetCurrentThreadId` |
| 52 | `0x17428` | `0x140017428` | `+0x248` | `ntoskrnl!PsGetProcessId` |
| 53 | `0x17430` | `0x140017430` | `+0x250` | `ntoskrnl!PsGetThreadId` |
| 54 | `0x17438` | `0x140017438` | `+0x258` | `ntoskrnl!PsGetThreadProcessId` |
| 55 | `0x17440` | `0x140017440` | `+0x260` | `ntoskrnl!ZwDeviceIoControlFile` |
| 56 | `0x17448` | `0x140017448` | `+0x268` | `ntoskrnl!RtlRandomEx` |
| 57 | `0x17450` | `0x140017450` | `+0x270` | `ntoskrnl!PsLookupProcessByProcessId` |
| 58 | `0x17458` | `0x140017458` | `+0x278` | `ntoskrnl!PsLookupThreadByThreadId` |
| 59 | `0x17460` | `0x140017460` | `+0x280` | `ntoskrnl!PsGetThreadProcess` |
| 60 | `0x17468` | `0x140017468` | `+0x288` | `ntoskrnl!IoQueryFileDosDeviceName` |
| 61 | `0x17470` | `0x140017470` | `+0x290` | `ntoskrnl!ObOpenObjectByPointer` |
| 62 | `0x17478` | `0x140017478` | `+0x298` | `ntoskrnl!ObQueryNameString` |
| 63 | `0x17480` | `0x140017480` | `+0x2a0` | `ntoskrnl!ZwOpenDirectoryObject` |
| 64 | `0x17488` | `0x140017488` | `+0x2a8` | `ntoskrnl!PsGetProcessImageFileName` |
| 65 | `0x17490` | `0x140017490` | `+0x2b0` | `ntoskrnl!PsGetProcessInheritedFromUniqueProcessId` |
| 66 | `0x17498` | `0x140017498` | `+0x2b8` | `ntoskrnl!ZwQueryInformationThread` |
| 67 | `0x174a0` | `0x1400174a0` | `+0x2c0` | `ntoskrnl!ZwQuerySystemInformation` |
| 68 | `0x174b0` | `0x1400174b0` | `+0x2d0` | `ntoskrnl!PsAcquireProcessExitSynchronization` |
| 69 | `0x174d0` | `0x1400174d0` | `+0x2f0` | `ntoskrnl!PsReleaseProcessExitSynchronization` |
| 70 | `0x174d8` | `0x1400174d8` | `+0x2f8` | `ntoskrnl!ExfUnblockPushLock` |
| 71 | `0x174e0` | `0x1400174e0` | `+0x300` | `ntoskrnl!ExEnumHandleTable` |
| 72 | `0x174e8` | `0x1400174e8` | `+0x308` | `ntoskrnl!ZwQueryDirectoryObject` |
| 73 | `0x174f0` | `0x1400174f0` | `+0x310` | `ntoskrnl!ObOpenObjectByName` |
| 74 | `0x174f8` | `0x1400174f8` | `+0x318` | `ntoskrnl!CmUnRegisterCallback` |
| 75 | `0x17500` | `0x140017500` | `+0x320` | `ntoskrnl!MmProbeAndLockPages` |
| 76 | `0x17508` | `0x140017508` | `+0x328` | `ntoskrnl!MmUnlockPages` |
| 77 | `0x17510` | `0x140017510` | `+0x330` | `ntoskrnl!IoAllocateMdl` |
| 78 | `0x17518` | `0x140017518` | `+0x338` | `ntoskrnl!IoFreeMdl` |
| 79 | `0x17520` | `0x140017520` | `+0x340` | `ntoskrnl!ObReferenceObjectByName` |
| 80 | `0x17528` | `0x140017528` | `+0x348` | `ntoskrnl!ZwOpenSection` |
| 81 | `0x17530` | `0x140017530` | `+0x350` | `ntoskrnl!KeStackAttachProcess` |
| 82 | `0x17538` | `0x140017538` | `+0x358` | `ntoskrnl!KeUnstackDetachProcess` |
| 83 | `0x17540` | `0x140017540` | `+0x360` | `ntoskrnl!PsGetProcessPeb` |
| 84 | `0x17548` | `0x140017548` | `+0x368` | `ntoskrnl!PsGetProcessWow64Process` |
| 85 | `0x17550` | `0x140017550` | `+0x370` | `ntoskrnl!RtlWalkFrameChain` |
| 86 | `0x17558` | `0x140017558` | `+0x378` | `ntoskrnl!KeInitializeApc` |
| 87 | `0x17560` | `0x140017560` | `+0x380` | `ntoskrnl!KeInsertQueueApc` |
| 88 | `0x17568` | `0x140017568` | `+0x388` | `ntoskrnl!ZwTerminateProcess` |
| 89 | `0x17570` | `0x140017570` | `+0x390` | `ntoskrnl!MmUnmapViewOfSection` |
| 90 | `0x17578` | `0x140017578` | `+0x398` | `ntoskrnl!PsSuspendProcess` |
| 91 | `0x17580` | `0x140017580` | `+0x3a0` | `ntoskrnl!PsResumeProcess` |
| 92 | `0x17588` | `0x140017588` | `+0x3a8` | `ntoskrnl!ZwCreateSection` |
| 93 | `0x176b0` | `0x1400176b0` | `+0x4d0` | `ntoskrnl!ZwMapViewOfSection` |
| 94 | `0x176b8` | `0x1400176b8` | `+0x4d8` | `ntoskrnl!ZwUnmapViewOfSection` |
| 95 | `0x176c8` | `0x1400176c8` | `+0x4e8` | `ntoskrnl!IoThreadToProcess` |
| 96 | `0x176d8` | `0x1400176d8` | `+0x4f8` | `ntoskrnl!ZwAllocateVirtualMemory` |
| 97 | `0x176e0` | `0x1400176e0` | `+0x500` | `ntoskrnl!ZwFreeVirtualMemory` |
| 98 | `0x176e8` | `0x1400176e8` | `+0x508` | `ntoskrnl!PsGetContextThread` |
| 99 | `0x176f0` | `0x1400176f0` | `+0x510` | `ntoskrnl!MmCopyVirtualMemory` |
| 100 | `0x176f8` | `0x1400176f8` | `+0x518` | `ntoskrnl!ZwOpenThread` |
| 101 | `0x17700` | `0x140017700` | `+0x520` | `ntoskrnl!MmMapIoSpace` |
| 102 | `0x17708` | `0x140017708` | `+0x528` | `ntoskrnl!MmUnmapIoSpace` |
| 103 | `0x17710` | `0x140017710` | `+0x530` | `ntoskrnl!MmGetPhysicalAddress` |
| 104 | `0x17718` | `0x140017718` | `+0x538` | `ntoskrnl!KeDelayExecutionThread` |
| 105 | `0x17720` | `0x140017720` | `+0x540` | `ntoskrnl!RtlCompareUnicodeString` |
| 106 | `0x17728` | `0x140017728` | `+0x548` | `ntoskrnl!PsGetProcessSessionId` |
| 107 | `0x17730` | `0x140017730` | `+0x550` | `ntoskrnl!MmCopyMemory` |
| 108 | `0x17738` | `0x140017738` | `+0x558` | `ntoskrnl!ZwTraceControl` |
| 109 | `0x17740` | `0x140017740` | `+0x560` | `ntoskrnl!RtlImageNtHeader` |
| 110 | `0x17748` | `0x140017748` | `+0x568` | `ntoskrnl!IoFileObjectType` |
| 111 | `0x17750` | `0x140017750` | `+0x570` | `ntoskrnl!PsProcessType` |
| 112 | `0x17758` | `0x140017758` | `+0x578` | `ntoskrnl!PsThreadType` |
| 113 | `0x17760` | `0x140017760` | `+0x580` | `ntoskrnl!PsInitialSystemProcess` |
| 114 | `0x17768` | `0x140017768` | `+0x588` | `ntoskrnl!IoDriverObjectType` |
| 115 | `0x17770` | `0x140017770` | `+0x590` | `ntoskrnl!NtBuildNumber` |
| 116 | `0x17778` | `0x140017778` | `+0x598` | `fltmgr!FltRegisterFilter` |
| 117 | `0x17780` | `0x140017780` | `+0x5a0` | `fltmgr!FltUnregisterFilter` |
| 118 | `0x17788` | `0x140017788` | `+0x5a8` | `fltmgr!FltStartFiltering` |
| 119 | `0x17790` | `0x140017790` | `+0x5b0` | `fltmgr!FltGetFileNameInformation` |
| 120 | `0x17798` | `0x140017798` | `+0x5b8` | `fltmgr!FltReleaseFileNameInformation` |
| 121 | `0x177a0` | `0x1400177a0` | `+0x5c0` | `fltmgr!FltReadFile` |
| 122 | `0x177a8` | `0x1400177a8` | `+0x5c8` | `fltmgr!FltQueryInformationFile` |
| 123 | `0x177b0` | `0x1400177b0` | `+0x5d0` | `fltmgr!FltGetRequestorProcess` |

After filling `0x17290..0x177b0`, `DriverMain` runs the `41` initialization calls below and writes `6` dispatch pointers into `DRIVER_OBJECT`:

- `DriverObject->DriverUnload` (`+0x68`) = `0x140002180` (`BeDriverUnload`)
- `DriverObject->MajorFunction[IRP_MJ_CREATE]` (`+0x70`) = `0x140002158` (`BeDispatchCreate`)
- `DriverObject->MajorFunction[IRP_MJ_CLOSE]` (`+0x80`) = `0x1400020b4` (`BeDispatchClose`)
- `DriverObject->MajorFunction[IRP_MJ_READ]` (`+0x88`) = `0x1400037c4` (`BeDispatchRead`)
- `DriverObject->MajorFunction[IRP_MJ_WRITE]` (`+0x90`) = `0x140005860` (`BeDispatchWrite`)
- `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]` (`+0xe0`) = `0x1400126e8` (`BeDispatchDeviceControl`)

#### Observed `DriverMain` Initialization Call Sequence

| Call # | Target API | Observed Register / Stack Arguments |
|---:|---|---|
| 1 | `ntoskrnl.exe!__chkstk` | `rax=0x1b30` |
| 2 | `ntoskrnl!KeInitializeMutex` | `rcx=0x1400171e0, rdx=0x0, r8=0x2b992ddfa232, r9=0x0` |
| 3 | `ntoskrnl!_wcsnicmp` | `rcx=0x0, rdx=0x703fabf0, r8=0xf, r9=0x0` |
| 4 | `ntoskrnl!RtlInitUnicodeString` | `str=\Device\BattlEye` |
| 5 | `ntoskrnl!IoCreateDevice` | `device_name=\Device\BattlEye, dev_obj=0x61000000` |
| 6 | `ntoskrnl!RtlInitUnicodeString` | `str=\DosDevices\BattlEye` |
| 7 | `ntoskrnl!IoCreateSymbolicLink` | `symlink=\DosDevices\BattlEye, target=\Device\BattlEye` |
| 8 | `ntoskrnl!KeWaitForSingleObject` | `rcx=0x1400171e0, rdx=0x0, r8=0x0, r9=0x0` |
| 9 | `ntoskrnl!RtlInitUnicodeString` | `str=363220` |
| 10 | `ntoskrnl!ObRegisterCallbacks` | `rcx=0x703fa3d8, rdx=0x140017130, r8=0x3, r9=0x0` |
| 11 | `ntoskrnl!KeReleaseMutex` | `rcx=0x1400171e0, rdx=0x0, r8=0x3, r9=0x0` |
| 12 | `ntoskrnl!PsSetLoadImageNotifyRoutine` | `rcx=0x140002c64, rdx=0x0, r8=0x3, r9=0x0` |
| 13 | `ntoskrnl!PsSetCreateThreadNotifyRoutine` | `rcx=0x140001ea8, rdx=0x0, r8=0x3, r9=0x0` |
| 14 | `fltmgr!FltRegisterFilter` | `rcx=0x60000000, rdx=0x703fa6f8, r8=0x1400178d8, r9=0x0` |
| 15 | `fltmgr!FltStartFiltering` | `rcx=0x0, rdx=0x703fa6f8, r8=0x1400178d8, r9=0x0` |
| 16 | `ntoskrnl!RtlGetVersion` | `rcx=0x140017590, rdx=0x703fa6f8, r8=0x1400178d8, r9=0x0` |
| 17 | `ntoskrnl!PsSetCreateProcessNotifyRoutineEx` | `rcx=0x140001b54, rdx=0x0, r8=0x1400178d8, r9=0x0` |
| 18 | `ntoskrnl!ZwQuerySystemInformation` | `rcx=0xb, rdx=0x703fa4e8, r8=0x0, r9=0x703fa4e8` |
| 19 | `ntoskrnl!ExAllocatePoolWithTag` | `size=0x378, ret=0x61001000` |
| 20 | `ntoskrnl!ZwQuerySystemInformation` | `rcx=0xb, rdx=0x61001000, r8=0x378, r9=0x0` |
| 21 | `ntoskrnl!ExFreePoolWithTag` | `rcx=0x61001000, rdx=0x0, r8=0x378, r9=0x0` |
| 22 | `ntoskrnl!RtlInitUnicodeString` | `str=Driver` |
| 23 | `ntoskrnl!RtlInitUnicodeString` | `str=\Driver` |
| 24 | `ntoskrnl!ZwOpenDirectoryObject` | `rcx=0x703fa560, rdx=0x1, r8=0x703fa568, r9=0x0` |
| 25 | `ntoskrnl!ExAllocatePool` | `size=0x1000, ret=0x61001400` |
| 26 | `ntoskrnl!ZwQueryDirectoryObject` | `rcx=0x0, rdx=0x61001400, r8=0x1000, r9=0x0` |
| 27 | `ntoskrnl!ExFreePoolWithTag` | `rcx=0x61001400, rdx=0x0, r8=0x1000, r9=0x0` |
| 28 | `ntoskrnl!ZwClose` | `rcx=0x0, rdx=0x0, r8=0x1000, r9=0x0` |
| 29 | `ntoskrnl!RtlInitUnicodeString` | `str=\FileSystem` |
| 30 | `ntoskrnl!ZwOpenDirectoryObject` | `rcx=0x703fa560, rdx=0x1, r8=0x703fa568, r9=0x0` |
| 31 | `ntoskrnl!ExAllocatePool` | `size=0x1000, ret=0x61002400` |
| 32 | `ntoskrnl!ZwQueryDirectoryObject` | `rcx=0x0, rdx=0x61002400, r8=0x1000, r9=0x0` |
| 33 | `ntoskrnl!ExFreePoolWithTag` | `rcx=0x61002400, rdx=0x0, r8=0x1000, r9=0x0` |
| 34 | `ntoskrnl!ZwClose` | `rcx=0x0, rdx=0x0, r8=0x1000, r9=0x0` |
| 35 | `ntoskrnl!KeInitializeEvent` | `rcx=0x140017848, rdx=0x0, r8=0x0, r9=0x0` |
| 36 | `ntoskrnl!PsCreateSystemThread` | `rcx=0x703fa538, rdx=0x1fffff, r8=0x703fa6c0, r9=0x0` |
| 37 | `ntoskrnl!ObReferenceObjectByHandle` | `rcx=0x0, rdx=0x1fffff, r8=0x0, r9=0x0` |
| 38 | `ntoskrnl!ZwClose` | `rcx=0x0, rdx=0x1fffff, r8=0x0, r9=0x0` |
| 39 | `ntoskrnl!RtlInitUnicodeString` | `str=\Device\PhysicalMemory` |
| 40 | `ntoskrnl!ZwOpenSection` | `rcx=0x703fa418, rdx=0x80000000, r8=0x703fa378, r9=0x0` |
| 41 | `ntoskrnl!ObReferenceObjectByHandle` | `rcx=0x0, rdx=0x0, r8=0x0, r9=0x0` |

### 2.4 Integrity Checks, Trap Instructions, and Non-Callable PDATA Entries

Testing all `224` `RUNTIME_FUNCTION` entries at `0x4e8cd0` turned up three types of traps and non-callable records:

1. **Assertion and single-step interrupts:** Entry `0x3000` (`1,653` bytes in `.text`) branches into `.be0` and executes `int 0x2c` (`CD 2C`, `KiRaiseAssertion`) at `0x1404c7201`. Entry `0x4de2ce` executes `int1` (`F1`, `ICEBP`). Executing unreferenced PDATA entries without trap handling halts naive emulators or debuggers.
2. **Data and bytecode ranges registered in PDATA:** Around `80` `.be0` PDATA entries (`0x4c3768`, `0x4cb963`, `0x4cbb7b`, `0x4cc446`, etc.) fault immediately with `UC_ERR_INSN_INVALID` (`fbld`, privileged `in eax, 0x52`, or invalid opcodes) because VMProtect registers unwind records over internal jump targets and bytecode blocks that are not standalone C functions.
3. **PE header and `HalDispatchTable` checks:** `0xe3e4` (`1,085,955` VM instructions, covered in Section 9) checks `IMAGE_DOS_HEADER.e_lfanew` (`+0x3c`) and `IMAGE_OPTIONAL_HEADER64.DataDirectory` (`+0x88`, `+0x8c`) while writing `"HalDispatchT"` on the stack. `DriverMain` queries `SystemModuleInformation` (`ZwQuerySystemInformation` class `0xB`, length `0x378`), enumerates `\Driver` and `\FileSystem` via `ZwOpenDirectoryObject` / `ZwQueryDirectoryObject`, and opens `\Device\PhysicalMemory` via `ZwOpenSection`.

---

## 3. Runtime Memory Layout

### 3.1 `.data` Global State Map (`0x140017000..0x140018011`)

Matching `.data` reads and writes across `DriverMain`, `BeDispatch*`, `BeDriverUnload`, and `BeCreateProcessNotifyCallbackEx` gives the global layout below:

| RVA | Virtual Address | Size | Reconstructed Symbol & Purpose |
|---|---|---:|---|
| `0x17000` | `0x140017000` | `4 B` | Process notify state / sentinel (`cmp dword [0x140017000], -1` in `0x1b54`) |
| `0x17120` | `0x140017120` | `8 B` | `__security_cookie` (`0x0000136cfbf29f11` on disk) |
| `0x17128` | `0x140017128` | `8 B` | `__security_cookie_complement` (`~cookie` written at boot step `17,318`) |
| `0x17130` | `0x140017130` | `8 B` | `ObRegisterCallbacks` registration handle (`rdx` output in `DriverMain` call #10) |
| `0x17138` | `0x140017138` | `8 B` | Tracked parent/process field (`[r15 - 0x10]` written in `0x1b54`) |
| `0x17148` | `0x140017148` | `96 B` | Process creation tracking block (`r15` base in `BeCreateProcessNotifyCallbackEx` `0x1b54`: `+0x00` PID, `+0x08` ImageFileName ptr, `+0x10` CommandLine, `+0x18` 16B XMM zeroed block, `+0x2c`/`+0x2d` active flags, `+0x2f` lock byte) |
| `0x17173` | `0x140017173` | `1 B` | `g_DeviceOpened` (`1` set by `BeDispatchCreate`, `0` cleared by `BeDispatchClose`) |
| `0x171b0` | `0x1400171b0` | `8 B` | Active client session pointer |
| `0x171e0` | `0x1400171e0` | `56 B` | `g_GlobalMutex` (`KMUTANT` initialized by `KeInitializeMutex`; base register `rdi` in `BeDispatchClose` and `BeDriverUnload`) |
| `0x17240` | `0x140017240` | `8 B` | Tracked `EPROCESS` pointer (`[0x17148 + 0xf8]` in `0x1b54`) |
| `0x17290..0x177b0` | `0x140017290..` | `1,320 B` | `123` dynamically resolved `ntoskrnl.exe` & `FLTMGR.SYS` IAT pointers |
| `0x17590` | `0x140017590` | `284 B` | `RTL_OSVERSIONINFOW` buffer filled by `RtlGetVersion` (`DriverMain` call #16) |
| `0x177cc` | `0x1400177cc` | `2 B` | Dynamic struct offset `uint16_t` (`movzx eax, word ptr [0x1400177cc]` in `0x26ac`) |
| `0x17848` | `0x140017848` | `24 B` | `KEVENT` initialized by `KeInitializeEvent` before `PsCreateSystemThread` |
| `0x178d8` | `0x1400178d8` | `8 B` | `g_FilterHandle` (`PFLT_FILTER` written by `FltRegisterFilter`, passed to `FltUnregisterFilter` at `[0x171e0 + 0x6f8]` in `BeDriverUnload`) |
| `0x17908` | `0x140017908` | `1 B` | `g_CleanupFlag` (`[0x171e0 + 0x728] = 1` in `BeDispatchClose`) |
| `0x17e88` | `0x140017e88` | `8 B` | Unpopulated indirect jump pointer referenced by `0x4d8725` (`0xd014`; target `unverified`) |

### 3.2 Emulated Kernel Memory Map

To run virtualized functions in `Unicorn` without faulting on kernel intrinsics (`KeGetCurrentThread`, `PsGetCurrentProcess`, `MmIsAddressValid`, `SharedUserData`), we mapped fake kernel structures at fixed addresses:

```text
0x000FF78000000000 .. +0x1000   52-bit masked alias of KUSER_SHARED_DATA (used when bit 52..63 are masked)
0xFFFFF78000000000 .. +0x1000   Canonical KUSER_SHARED_DATA:
                                  +0x008 / +0x014 : InterruptTime / SystemTime = 0x01DB000012345678
                                  +0x030          : 0x62030000
                                  +0x26C          : NtMajorVersion=10, NtMinorVersion=0, NtBuildNumber=22621
GS_BASE = 0x62000000 (+0x1000)  KPCR:    +0x018 Self = 0x62000000, +0x188 CurrentThread = 0x62010000
0x62010000 .. +0x1000           KTHREAD: +0x0B8 / +0x220 ApcState.Process / Process = 0x62020000
0x62020000 .. +0x1000           EPROCESS (4 KiB object; returned via PsLookupProcessByProcessId *RDX)
0x70000000 .. 0x70200000        2 MiB Native Thread Stack + VMProtect VREG/VSTACK (RSP_init = 0x701FC000)
0x60000000 .. 0x60200000        2 MiB Argument & 2-Level Pointer Region:
                                  RCX=0x60000000, RDX=0x60010000 (+0x18->0x60012000 SystemBuffer,
                                  +0xB8->0x60011000 CurrentStackLocation), R8=0x60020000, R9=0x60030000
                                  2-level 4 KiB pointer tables: 0x60100000+bi*0x10000 -> 0x60180000+bi*0x10000
0x61000000 .. 0x61200000        2 MiB Kernel Pool Heap (ExAllocatePool* -> 0x61000000+; ObRef out -> 0x61080000)
0x55550000 .. +0x1000           Return Sentinel Page (0xC3 RET pushed at [RSP_init] to catch function returns)
0x50000000 .. 0x50010000        Synthetic API Dispatch Stubs (0x10-byte stride); 0x5000E000 = callable routine stub
0x140000000 .. 0x1404EB000      Mapped BEDaisy.sys Image
0x1404EB000 .. 0x140533000      Added .devirt R-X Section (0x48000 bytes / 288 KiB) in rebuilt BEDaisy.sys
```

### 3.3 VM Context and Native Stack Frame Layout

VMProtect 3.8+ does not allocate a heap `VMContext` struct. On entering a virtualized function, `VMENTER` pushes all 15 non-RSP general-purpose registers plus `RFLAGS` onto the native stack (`VSP`), then subtracts `~0x1d8..0x200` bytes from `RSP` to allocate a scratch Virtual Register array (`VREG = rsp`).

In the `VMEXIT` trace of `BeDispatchCreate` (`0x2158`, steps `27,479..27,523` in Section 4.4), `mov rsp, r11` sets `RSP = VSP` (`r11`) and pops the saved hardware registers in reverse order. That exit sequence gives the exact 128-byte native context layout at `VSP`:

```text
Offset from VSP (at VMEXIT)   Popped Register   Instruction in 0x2158 VMEXIT Trace
---------------------------   ---------------   ----------------------------------
[VSP + 0x00]                  RBP               0x140452097: pop rbp
[VSP + 0x08]                  RSI               0x140452098: pop rsi
[VSP + 0x10]                  R12               0x1404520a4: pop r12
[VSP + 0x18]                  R11               0x1404520a6: pop r11
[VSP + 0x20]                  R14               0x1404520ab: pop r14
[VSP + 0x28]                  R15               0x1404520bc: pop r15
[VSP + 0x30]                  R9                0x1404520c1: pop r9
[VSP + 0x38]                  R10               0x1404520c3: pop r10
[VSP + 0x40]                  RDX               0x1404520c8: pop rdx
[VSP + 0x48]                  RFLAGS            0x1404520cf: popfq
[VSP + 0x50]                  R8                0x1404520d5: pop r8
[VSP + 0x58]                  R13               0x1402e9883: pop r13
[VSP + 0x60]                  RCX               0x1402e9885: pop rcx
[VSP + 0x68]                  RBX               0x1402e988e: pop rbx
[VSP + 0x70]                  RDI               0x1402d2164: pop rdi
[VSP + 0x78]                  RAX (computed)    0x1402d216d..0x35e752: load RAX, lea rsp,[rsp+0x18], ret
[VSP + 0x80]                  Return Address    0x55550000 (caller RIP)
```

Each of the 10 VM instances permutes its own push/pop register order during `VMENTER` and `VMEXIT` so fixed byte signatures cannot match VM prologues. After `VMENTER`, consecutive `VPOP_REG64` handlers move the saved values from `[VSP]` into `[rsp + imm8]` (`vreg[0..31]`), leaving `VSP` as the operand evaluation stack (`VSTACK`).

---

## 4. Virtual Machine Architecture

### 4.1 Register Bindings of All 10 VM Instances

Tracing all `87` virtualized routines from `.text`, `INIT`, and `.be0` into `.be0` isolated **10 distinct VM entry points**. All 10 use a stack-machine model (`VREG = rsp`) with per-instance register assignments for `VIP`, `VSP`, scan direction, and indirect branch registers:

| VM # | Entry RVA | VirtualAddr | Protected Funcs | Sample Func | `VIP` | `VSP` | `VREG` | Bytecode Scan | Primary Dispatch (`Hits/40`) | Alternate Dispatch Regs (`Hits/40`) |
|---:|---|---|---:|---|:---:|:---:|:---:|:---:|---|---|
| 1 | `0x2c91b5` | `0x1402c91b5` | `11` | `0x37c4` (`BeDispatchRead`) | `rsi` | `rbx` | `rsp` | Backward (`-`) | `r8` (`24`) | `rdx` (`4`), `r9` (`3`), `rdi` (`3`) |
| 2 | `0x2ccb80` | `0x1402ccb80` | `7` | `0x4b70` (`BeQueryFileSystemObjectName`) | `rsi` | `r8` | `rsp` | Forward (`+`) | `r11` (`32`) | `rbp` (`3`), `rax` (`3`), `rcx` (`1`) |
| 3 | `0x2d1cfa` | `0x1402d1cfa` | `7` | `0x4e08` | `rdi` | `rsi` | `rsp` | Backward (`-`) | `r9` (`33`) | `rdx` (`2`), `r11` (`2`), `rbx` (`2`) |
| 4 | `0x2f327d` | `0x1402f327d` | `10` | `0x2158` (`BeDispatchCreate`) | `r9` | `rbx` | `rsp` | Forward (`+`) | `rdi` (`27`) | `rsi` (`4`), `rcx` (`3`), `rax` (`3`) |
| 5 | `0x330e68` | `0x140330e68` | `7` | `0x141c` / `GsDriverEntry` | `r9` | `r11` | `rsp` | Forward (`+`) | `r10` (`27`) | `rdx` (`7`), `rdi` (`3`), `rsi` (`2`) |
| 6 | `0x37dbff` | `0x14037dbff` | `12` | `0x20b4` (`BeDispatchClose`) | `r9` | `rbx` | `rsp` | Forward (`+`) | `rbp` (`28`) | `rax` (`4`), `rdx` (`3`), `rdi` (`2`) |
| 7 | `0x4258a8` | `0x1404258a8` | `9` | `0x1004` / `0x12494` | `r11` | `rbp` | `rsp` | Backward (`-`) | `r10` (`22`) | `rdx` (`9`), `rax` (`6`), `rbx` (`1`) |
| 8 | `0x43af94` | `0x14043af94` | `7` | `0x10d8` | `r8` | `rsi` | `rsp` | Backward (`-`) | `r10` (`31`) | `rax` (`5`), `rdi` (`1`), `rbx` (`1`) |
| 9 | `0x4a163e` | `0x1404a163e` | `10` | `0xcae8` / `0x10a40` | `rbp` | `rsi` | `rsp` | Forward (`+`) | `r8` (`29`) | `rdx` (`5`), `r11` (`2`), `rdi` (`1`) |
| 10 | `0x4a4c62` | `0x1404a4c62` | `7` | `0x1350` | `r9` | `rbp` | `rsp` | Backward (`-`) | `rbx` (`27`) | `rdi` (`3`), `rax` (`3`), `rcx` (`2`) |

Five VMs (`#1, #3, #7, #8, #10`) decrement `VIP` (`backward`), scanning bytecode from high to low addresses; the other five (`#2, #4, #5, #6, #9`) increment `VIP` (`forward`).

### 4.2 Bytecode Instruction Format and Operand Encoding

VMProtect 3.8+ does not use a 1-byte opcode table lookup. Instead, each bytecode packet stores an encrypted signed 32-bit relative offset to the next handler (added to the current handler's base register, e.g., `adc rdi, rbp`), plus any immediate operand consumed by the current handler:

```text
1. Implicit Stack / ALU Ops (vip_delta = +4 or -4):
   +--------------------------------------+
   | Encrypted int32 next_handler_delta   |  (4 bytes)
   +--------------------------------------+

2. Virtual Register Move Ops: VPUSH_REG64 / VPOP_REG64 (vip_delta = +5 or +6):
   +--------------------+-----------------+--------------------------------------+
   | Encrypted imm8 reg | Optional pad 1B | Encrypted int32 next_handler_delta   |  (5 or 6 bytes)
   +--------------------+-----------------+--------------------------------------+
   imm8 is scaled (multiples of 8, indexing [rsp + vreg_offset] in 0x00..0xF8).

3. 64-Bit Constant Push: VPUSH_IMM64 (vip_delta = +12):
   +--------------------------------------+--------------------------------------+
   | Encrypted uint64 immediate_constant  | Encrypted int32 next_handler_delta   |  (12 bytes)
   +--------------------------------------+--------------------------------------+
```

### 4.3 `VMENTER` Disassembly (`0x2158` -> `0x113cba` -> `0x2f327d`)

Jump-folded disassembly of `BeDispatchCreate` (`0x2158`) entering VM #4 (`0x2f327d`):

```x86asm
0x140002158 (+0x002158):  e95d1b1100              jmp      0x140113cba
0x140113cba (+0x113cba):  56                      push     rsi
0x140113cbb (+0x113cbb):  9c                      pushfq
0x140113cbc (+0x113cbc):  48be8d75a11783bd06aa    movabs   rsi, 0xaa06bd8317a1758d
0x140113cc6 (+0x113cc6):  66c1e63a                shl      si, 0x3a
0x140113cca (+0x113cca):  400f99c6                setns    sil
0x140113cce (+0x113cce):  be0133a1e2              mov      esi, 0xe2a13301
0x140113cd3 (+0x113cd3):  48c1eeae                shr      rsi, 0xae
0x140113cd7 (+0x113cd7):  400f99c6                setns    sil
0x140113cdb (+0x113cdb):  488bb4f400000000        mov      rsi, qword ptr [rsp + rsi*8]
0x140113ce3 (+0x113ce3):  48c7442408869b19c3      mov      qword ptr [rsp + 8], 0xffffffffc3199b86
0x140113cec (+0x113cec):  ff742400                push     qword ptr [rsp]
0x140113cf0 (+0x113cf0):  9d                      popfq
0x140113cf1 (+0x113cf1):  4c895c2400              mov      qword ptr [rsp], r11
0x140113cf6 (+0x113cf6):  e982f51d00              jmp      0x1402f327d
0x1402f327d (+0x2f327d):  56                      push     rsi
0x1402f327e (+0x2f327e):  beafd9b052              mov      esi, 0x52b0d9af
0x1402f3283 (+0x2f3283):  56                      push     rsi
0x1402f3284 (+0x2f3284):  4c89b43451264fad        mov      qword ptr [rsp + rsi - 0x52b0d9af], r14
0x1402f328c (+0x2f328c):  55                      push     rbp
0x1402f328d (+0x2f328d):  e9292d1900              jmp      0x140485fbb
0x140485fbb (+0x485fbb):  56                      push     rsi
0x140485fbc (+0x485fbc):  e99ec4f6ff              jmp      0x1403f245f
0x1403f245f (+0x3f245f):  4c89b43451264fad        mov      qword ptr [rsp + rsi - 0x52b0d9af], r14
0x1403f2467 (+0x3f2467):  e9bf980400              jmp      0x14043bd2b
0x14043bd2b (+0x43bd2b):  0fb7ee                  movzx    ebp, si
0x14043bd2e (+0x43bd2e):  9c                      pushfq
0x14043bd2f (+0x43bd2f):  4881f6b00532bc          xor      rsi, 0xffffffffbc3205b0
0x14043bd36 (+0x43bd36):  488d2c7527d983ac        lea      rbp, [rsi*2 - 0x537c26d9]
0x14043bd3e (+0x43bd3e):  4154                    push     r12
0x14043bd40 (+0x43bd40):  660fc1f5                xadd     bp, si
0x14043bd44 (+0x43bd44):  66c1feae                sar      si, 0xae
0x14043bd48 (+0x43bd48):  0f8892500600            js       0x1404a0de0
0x14043bd4e (+0x43bd4e):  bb1d463b47              mov      ebx, 0x473b461d
0x14043bd53 (+0x43bd53):  4d8d8418e1b9c4b8        lea      r8, [r8 + rbx - 0x473b461f]
0x14043bd5b (+0x43bd5b):  410fb7bc18e3b9c4b8      movzx    edi, word ptr [r8 + rbx - 0x473b461d]
0x14043bd64 (+0x43bd64):  0fb6cb                  movzx    ecx, bl
0x14043bd67 (+0x43bd67):  448bcb                  mov      r9d, ebx
0x14043bd6a (+0x43bd6a):  ba1356b209              mov      edx, 0x9b25613
0x14043bd6f (+0x43bd6f):  664133fb                xor      di, r11w
0x14043bd73 (+0x43bd73):  66d1cf                  ror      di, 1
0x14043bd76 (+0x43bd76):  66f7df                  neg      di
0x14043bd79 (+0x43bd79):  48f7da                  neg      rdx
0x14043bd7c (+0x43bd7c):  49ffc1                  inc      r9
0x14043bd7f (+0x43bd7f):  41c0f126                sal      r9b, 0x26
0x14043bd83 (+0x43bd83):  66d1c7                  rol      di, 1
0x14043bd86 (+0x43bd86):  80f1b4                  xor      cl, 0xb4
0x14043bd89 (+0x43bd89):  0f8b90b3f3ff            jnp      0x14037711f
0x14043bd8f (+0x43bd8f):  6681d7ae63              adc      di, 0x63ae
0x14043bd94 (+0x43bd94):  0fbeeb                  movsx    ebp, bl
0x14043bd97 (+0x43bd97):  664433df                xor      r11w, di
0x14043bd9b (+0x43bd9b):  480fb3dd                btr      rbp, rbx
0x14043bd9f (+0x43bd9f):  400fc0dd                xadd     bpl, bl
0x14043bda3 (+0x43bda3):  c0cbe4                  ror      bl, 0xe4
0x14043bda6 (+0x43bda6):  488db45622ac6413        lea      rsi, [rsi + rdx*2 + 0x1364ac22]
0x14043bdae (+0x43bdae):  660fbae189              bt       cx, 0x89
0x14043bdb3 (+0x43bdb3):  41c0c1a5                rol      r9b, 0xa5
0x14043bdb7 (+0x43bdb7):  89bc3157ffffff          mov      dword ptr [rcx + rsi - 0xa9], edi
0x14043bdbe (+0x43bdbe):  480f43ca                cmovae   rcx, rdx
0x14043bdc2 (+0x43bdc2):  4e8d84032bb9c4b8        lea      r8, [rbx + r8 - 0x473b46d5]
0x14043bdca (+0x43bdca):  48ffcd                  dec      rbp
0x14043bdcd (+0x43bdcd):  458b8c081356b209        mov      r9d, dword ptr [r8 + rcx + 0x9b25613]
0x14043bdd5 (+0x43bdd5):  d3e3                    shl      ebx, cl
0x14043bdd7 (+0x43bdd7):  0fb7fa                  movzx    edi, dx
0x14043bdda (+0x43bdda):  0f82731cebff            jb       0x1402eda53
0x14043bde0 (+0x43bde0):  0fb7d0                  movzx    edx, ax
0x14043bde3 (+0x43bde3):  415a                    pop      r10
0x14043bde5 (+0x43bde5):  490bd9                  or       rbx, r9
0x14043bde8 (+0x43bde8):  ffe3                    jmp      rbx
```

Execution steps inside `VMENTER`:
- `0x113cba..0x113cf6` pushes `rsi` and `RFLAGS`, zeroes `sil` via constant shift (`0xe2a13301 >> 0xae == 0`), writes the per-function encrypted seed `0xffffffffc3199b86` (`-0x3ce6647a`) to `[rsp + 8]`, stores `r11` at `[rsp]`, and jumps to `0x1402f327d`.
- `0x2f327d..0x43bd3e` pushes the remaining caller registers using constant-offset addressing: `mov esi, 0x52b0d9af; push rsi; mov [rsp + rsi - 0x52b0d9af], r14` overwrites the dummy `rsi` slot at `[rsp]` with `r14`.
- `0x43bd4e..0x43bde8` initializes the rolling key (`r11w` / `r8d`), computes initial `VIP` (`r9`) and first handler address (`rbx`), and enters the first `VPOP_REG64` handler via `jmp rbx` (`0x14043bde8`).

### 4.4 `VMEXIT` Disassembly (`BeDispatchCreate` Steps `27,459..27,523`)

At the end of `BeDispatchCreate` (`27,523` instructions), VM #4 runs its `VMEXIT` sequence starting at `0x140452083` (`step 27,479`):

```x86asm
step=27459 0x140301e98 (+0x301e98): imul     edi, edi
step=27460 0x140301e9b (+0x301e9b): add      r10, rax
step=27461 0x140301e9e (+0x301e9e): btc      rdi, rdx
step=27462 0x140301ea2 (+0x301ea2): add      edx, esi
step=27463 0x140301ea4 (+0x301ea4): ja       0x14039e56d
step=27464 0x14039e56d (+0x39e56d): mov      eax, 0xcc3a28b8
step=27465 0x14039e572 (+0x39e572): inc      rax
step=27466 0x14039e575 (+0x39e575): lea      rax, [rsp + 0x1d8]
step=27467 0x14039e57d (+0x39e57d): push     -0x766ce3e9
step=27468 0x14039e582 (+0x39e582): jno      0x140433cb0
step=27469 0x140433cb0 (+0x433cb0): sar      dword ptr [rsp + 4], 1
step=27470 0x140433cb4 (+0x433cb4): cmp      r11, rax
step=27471 0x140433cb7 (+0x433cb7): jmp      0x140382b56
step=27472 0x140382b56 (+0x382b56): lea      rsp, [rsp + 8]
step=27473 0x140382b5b (+0x382b5b): ja       0x1402e3b69
step=27474 0x1402e3b69 (+0x2e3b69): push     -0x4c456f6d
step=27475 0x1402e3b6e (+0x2e3b6e): push     0x3ae7d13
step=27476 0x1402e3b73 (+0x2e3b73): jmp      0x1403026e1
step=27477 0x1403026e1 (+0x3026e1): lea      rsp, [rsp + 0x10]
step=27478 0x1403026e6 (+0x3026e6): jmp      r10
step=27479 0x140452083 (+0x452083): mov      eax, 0xfd0d8e81
step=27480 0x140452088 (+0x452088): mov      rsp, r11
step=27481 0x14045208b (+0x45208b): movsx    r12d, ax
step=27482 0x14045208f (+0x45208f): movsx    edi, r12b
step=27483 0x140452093 (+0x452093): movsx    r10d, r12b
step=27484 0x140452097 (+0x452097): pop      rbp
step=27485 0x140452098 (+0x452098): pop      rsi
step=27486 0x140452099 (+0x452099): shr      r12d, 5
step=27487 0x14045209d (+0x45209d): movzx    r15d, r12b
step=27488 0x1404520a1 (+0x4520a1): neg      r10b
step=27489 0x1404520a4 (+0x4520a4): pop      r12
step=27490 0x1404520a6 (+0x4520a6): pop      r11
step=27491 0x1404520a8 (+0x4520a8): movsx    edx, ax
step=27492 0x1404520ab (+0x4520ab): pop      r14
step=27493 0x1404520ad (+0x4520ad): sets     r15b
step=27494 0x1404520b1 (+0x4520b1): lea      rcx, [r15*8 - 0x4459341]
step=27495 0x1404520b9 (+0x4520b9): movsx    ebx, ax
step=27496 0x1404520bc (+0x4520bc): pop      r15
step=27497 0x1404520be (+0x4520be): sal      eax, 0x54
step=27498 0x1404520c1 (+0x4520c1): pop      r9
step=27499 0x1404520c3 (+0x4520c3): pop      r10
step=27500 0x1404520c5 (+0x4520c5): neg      di
step=27501 0x1404520c8 (+0x4520c8): pop      rdx
step=27502 0x1404520c9 (+0x4520c9): mov      r13d, 0x3ba07792
step=27503 0x1404520cf (+0x4520cf): popfq    
step=27504 0x1404520d0 (+0x4520d0): xchg     al, cl
step=27505 0x1404520d2 (+0x4520d2): cwde     
step=27506 0x1404520d3 (+0x4520d3): xchg     rcx, rax
step=27507 0x1404520d5 (+0x4520d5): pop      r8
step=27508 0x1404520d7 (+0x4520d7): cdqe     
step=27509 0x1404520d9 (+0x4520d9): jmp      0x1402e9880
step=27510 0x1402e9880 (+0x2e9880): not      dil
step=27511 0x1402e9883 (+0x2e9883): pop      r13
step=27512 0x1402e9885 (+0x2e9885): pop      rcx
step=27513 0x1402e9886 (+0x2e9886): lea      rbx, [rbx*2 + 0x413c2c9f]
step=27514 0x1402e988e (+0x2e988e): pop      rbx
step=27515 0x1402e988f (+0x2e988f): jmp      0x1402d2164
step=27516 0x1402d2164 (+0x2d2164): pop      rdi
step=27517 0x1402d2165 (+0x2d2165): push     rax
step=27518 0x1402d2166 (+0x2d2166): xchg     byte ptr [rsp + rax + 0x4459405], al
step=27519 0x1402d216d (+0x2d216d): mov      rax, qword ptr [rsp + rax + 0x4459309]
step=27520 0x1402d2175 (+0x2d2175): push     -0x2a4d647d
step=27521 0x1402d217a (+0x2d217a): jmp      0x14035e752
step=27522 0x14035e752 (+0x35e752): lea      rsp, [rsp + 0x18]
step=27523 0x14035e757 (+0x35e757): ret
```

Execution steps inside `VMEXIT`:
1. At `step 27,480` (`0x140452088`), `mov rsp, r11` discards the `VREG` scratch region by moving `RSP` up to `VSP` (`r11`), where prior `VPUSH_REG64` handlers placed the outgoing register state.
2. Between `0x452097` and `0x2d2164`, mixed with dead writes to registers right before they are overwritten by `pop` (`movsx r12d, ax` before `pop r12`; `sets r15b` before `pop r15`; `lea rbx, ...` before `pop rbx`), the exit stub pops `rbp, rsi, r12, r11, r14, r15, r9, r10, rdx, rflags (popfq), r8, r13, rcx, rbx, rdi`.
3. `0x2d2165..0x35e757` loads `STATUS_SUCCESS` (`0`) into `RAX`, advances `RSP` by `0x18` (`lea rsp, [rsp + 0x18]`), and executes `ret` (`0x14035e757`) to `0x55550000`.

---

## 5. Dispatcher Structures and Handler Duplication

### 5.1 Direct-Threaded Dispatch

None of the 10 VMs in `BEDaisy.sys` use a central dispatch loop. Each handler ends with its own inline fetch-decrypt-jump sequence:

```text
  Handler A (e.g., 0x3d08d1 VPOP_REG64)
     |-- 1. Run stack/vreg operation (mov rsi, [rbx]; VSP += 8; store to [rsp + imm8])
     |-- 2. Read encrypted 32-bit transition delta from [VIP] and update VIP
     |-- 3. Decrypt delta with rolling key register (r8) and update rolling key
     |-- 4. Sign-extend 32-bit delta and add to handler base anchor (rdi += sext32(delta))
     +-- 5. jmp rdi  ------------------>  Handler B (e.g., 0x2e7029 VPOP_REG64)
                                             |-- 1. Run stack/vreg operation ...
                                             +-- 5. jmp rsi  ---------->  Handler C ...
```

In step 4 (`0x1402d1844: movsxd rbp, ebp; 0x1402d184a: adc rdi, rbp; 0x1402d1850: jmp rdi`), `rdi` still holds the entry address of the current handler (`0x1402d1774`), so adding the decrypted signed 32-bit offset `ebp` computes `rdi = current_handler_va + delta` without any global jump table in `.rdata` or `.be0`. Conditional virtual branches (`VJMP`) compute target `VIP` / handler addresses dynamically on `VSTACK`.

### 5.2 First 35 Handler Dispatches of `BeDispatchCreate` (`0x2158`)

During `BeDispatchCreate` (`27,523` instructions), VM #4 executes `420` handler dispatches across **`316` distinct handler addresses** in `.be0`. Below are the first `35` dispatches (`index 0..34`):

| Dispatch # | Handler RVA | Native Insns | `VSP` Delta | `VIP` Delta | Exit Branch | Decoded Handler Operation |
|---:|---|---:|---:|---:|---|---|
| 0 | `0x113cba` | `139` | `+1881128824` | `+2792602873` | `jmp r11` | `VM_ENTRY (push native ctx, init VIP/VSP/KEY)` |
| 1 | `0x3d08d1` | `74` | `+8` | `+5` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 2 | `0x2e7029` | `75` | `+8` | `+5` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 3 | `0x441dcf` | `79` | `+8` | `+5` | `jmp rsi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 4 | `0x43b4ea` | `81` | `+8` | `+5` | `jmp rsi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 5 | `0x2f0bde` | `74` | `+8` | `+5` | `jmp rcx` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 6 | `0x2ff8ba` | `76` | `+8` | `+5` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 7 | `0x32b024` | `70` | `+8` | `+5` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 8 | `0x3c331e` | `81` | `+8` | `+5` | `jmp rax` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 9 | `0x3a44d8` | `79` | `+8` | `+5` | `jmp rax` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 10 | `0x2d3778` | `76` | `+8` | `+5` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 11 | `0x36b436` | `77` | `+8` | `+5` | `jmp rbp` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 12 | `0x3d08d1` | `74` | `+8` | `+5` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 13 | `0x2e7029` | `75` | `+8` | `+5` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 14 | `0x48cf1f` | `61` | `+8` | `+6` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 15 | `0x441dcf` | `79` | `+8` | `+5` | `jmp rsi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 16 | `0x43b4ea` | `81` | `+8` | `+5` | `jmp rsi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 17 | `0x2f0bde` | `74` | `+8` | `+5` | `jmp rcx` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 18 | `0x3042e6` | `59` | `-8` | `+12` | `jmp rdi` | `VPUSH_IMM64 (VSP -= 8; *VSP = imm64)` |
| 19 | `0x3baa2d` | `75` | `-8` | `+5` | `jmp rdi` | `VPUSH_REG64 (VSP -= 8; *VSP = vreg[imm8])` |
| 20 | `0x2d1774` | `49` | `+8` | `+4` | `jmp rdi` | `VWRITE_MEM / VALU_BIN64 (pop2, push1+flags or store)` |
| 21 | `0x2cb368` | `72` | `+8` | `+6` | `jmp r11` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 22 | `0x319448` | `45` | `-8` | `+4` | `jmp rdi` | `VPUSH_VSP64 (VSP -= 8; *VSP = old_VSP)` |
| 23 | `0x3a9126` | `73` | `+8` | `+6` | `jmp rcx` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 24 | `0x303e31` | `76` | `-8` | `+5` | `jmp rdi` | `VPUSH_REG64 (VSP -= 8; *VSP = vreg[imm8])` |
| 25 | `0x36e65c` | `63` | `+8` | `+6` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 26 | `0x425947` | `77` | `-8` | `+5` | `jmp rdi` | `VPUSH_REG64 (VSP -= 8; *VSP = vreg[imm8])` |
| 27 | `0x33767b` | `86` | `+8` | `+6` | `jmp rax` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 28 | `0x428942` | `74` | `-8` | `+5` | `jmp rdi` | `VPUSH_REG64 (VSP -= 8; *VSP = vreg[imm8])` |
| 29 | `0x3645f6` | `65` | `+8` | `+6` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 30 | `0x4201d3` | `75` | `-8` | `+5` | `jmp rdi` | `VPUSH_REG64 (VSP -= 8; *VSP = vreg[imm8])` |
| 31 | `0x471914` | `70` | `+8` | `+6` | `jmp rdi` | `VPOP_REG64 (vreg[imm8] = *VSP; VSP += 8)` |
| 32 | `0x344c77` | `61` | `-8` | `+5` | `jmp rdi` | `VPUSH_REG64 (VSP -= 8; *VSP = vreg[imm8])` |
| 33 | `0x2cca24` | `57` | `-8` | `+4` | `jmp rdi` | `VPUSH_VSP64 (VSP -= 8; *VSP = old_VSP)` |
| 34 | `0x48ed42` | `58` | `-8` | `+5` | `jmp rdi` | `VPUSH_REG64 (VSP -= 8; *VSP = vreg[imm8])` |

Dispatches `1..17` are 17 back-to-back `VPOP_REG64` operations moving saved registers into `vreg` slots on `[rsp]`, yet they execute across `14` separate `.be0` handler copies (`0x3d08d1`, `0x2e7029`, `0x441dcf`, `0x43b4ea`, `0x2f0bde`, `0x2ff8ba`, `0x32b024`, `0x3c331e`, `0x3a44d8`, `0x2d3778`, `0x36b436`, `0x48cf1f`), ranging from `61` to `81` native instructions and rotating exit registers across `rdi`, `rsi`, `rcx`, `rax`, and `rbp`.

---

## 6. Interpreter Internals: Handler Disassembly and Algebraic Reduction

We examine four complete handlers from `BEDaisy.sys` VM #4 (`VIP = r9`, `VSP = rbx`, `VREG = rsp`, rolling key = `r8`, anchor = `rdi`).

### 6.1 `0x2d1774` (`VADD64`: `pop a, b; push a + b`)

```x86asm
0x1402d1774 (+0x2d1774):  b895b21541              mov      eax, 0x4115b295
0x1402d1779 (+0x2d1779):  8bf0                    mov      esi, eax
0x1402d177b (+0x2d177b):  488bac1e6b4deabe        mov      rbp, qword ptr [rsi + rbx - 0x4115b295]
0x1402d1783 (+0x2d1783):  440fbed0                movsx    r10d, al
0x1402d1787 (+0x2d1787):  410fbfca                movsx    ecx, r10w
0x1402d178b (+0x2d178b):  488b941e734deabe        mov      rdx, qword ptr [rsi + rbx - 0x4115b28d]
0x1402d1793 (+0x2d1793):  480fbbc6                btc      rsi, rax
0x1402d1797 (+0x2d1797):  488d9c33734dcabe        lea      rbx, [rbx + rsi - 0x4135b28d]
0x1402d179f (+0x2d179f):  4813ea                  adc      rbp, rdx
0x1402d17a2 (+0x2d17a2):  51                      push     rcx
0x1402d17a3 (+0x2d17a3):  41bb1b271b2e            mov      r11d, 0x2e1b271b
0x1402d17a9 (+0x2d17a9):  0fbaf029                btr      eax, 0x29
0x1402d17ad (+0x2d17ad):  4889ac036b4feabe        mov      qword ptr [rbx + rax - 0x4115b095], rbp
0x1402d17b5 (+0x2d17b5):  48f7d6                  not      rsi
0x1402d17b8 (+0x2d17b8):  438bac59cab1c9a3        mov      ebp, dword ptr [r9 + r11*2 - 0x5c364e36]
0x1402d17c0 (+0x2d17c0):  4e8d8c086f4feabe        lea      r9, [rax + r9 - 0x4115b091]
0x1402d17c8 (+0x2d17c8):  99                      cdq
0x1402d17c9 (+0x2d17c9):  f6ac04724feabe          imul     byte ptr [rsp + rax - 0x4115b08e]
0x1402d17d0 (+0x2d17d0):  4133e8                  xor      ebp, r8d
0x1402d17d3 (+0x2d17d3):  48c1ea66                shr      rdx, 0x66
0x1402d17d7 (+0x2d17d7):  4c319c040000ebbe        xor      qword ptr [rsp + rax - 0x41150000], r11
0x1402d17df (+0x2d17df):  6641c1faae              sar      r10w, 0xae
0x1402d17e4 (+0x2d17e4):  f7dd                    neg      ebp
0x1402d17e6 (+0x2d17e6):  c1c503                  rol      ebp, 3
0x1402d17e9 (+0x2d17e9):  46329c1cebd8e4d1        xor      r11b, byte ptr [rsp + r11 - 0x2e1b2715]
0x1402d17f1 (+0x2d17f1):  488d34951ffbb7f0        lea      rsi, [rdx*4 - 0xf4804e1]
0x1402d17f9 (+0x2d17f9):  411bea                  sbb      ebp, r10d
0x1402d17fc (+0x2d17fc):  c1c502                  rol      ebp, 2
0x1402d17ff (+0x2d17ff):  99                      cdq
0x1402d1800 (+0x2d1800):  0fcd                    bswap    ebp
0x1402d1802 (+0x2d1802):  66442b9c040300ebbe      sub      r11w, word ptr [rsp + rax - 0x4114fffd]
0x1402d180b (+0x2d180b):  feca                    dec      dl
0x1402d180d (+0x2d180d):  4c898474c209901e        mov      qword ptr [rsp + rsi*2 + 0x1e9009c2], r8
0x1402d1815 (+0x2d1815):  488d94c0af04b2dd        lea      rdx, [rax + rax*8 - 0x224dfb51]
0x1402d181d (+0x2d181d):  4c0fabd9                bts      rcx, r11
0x1402d1821 (+0x2d1821):  31ac040000ebbe          xor      dword ptr [rsp + rax - 0x41150000], ebp
0x1402d1828 (+0x2d1828):  440fbfc2                movsx    r8d, dx
0x1402d182c (+0x2d182c):  4402d0                  add      r10b, al
0x1402d182f (+0x2d182f):  56                      push     rsi
0x1402d1830 (+0x2d1830):  4c8b84040800ebbe        mov      r8, qword ptr [rsp + rax - 0x4114fff8]
0x1402d1838 (+0x2d1838):  441bde                  sbb      r11d, esi
0x1402d183b (+0x2d183b):  66c1e8c5                shr      ax, 0xc5
0x1402d183f (+0x2d183f):  6641c1c2ef              rol      r10w, 0xef
0x1402d1844 (+0x2d1844):  4863ed                  movsxd   rbp, ebp
0x1402d1847 (+0x2d1847):  c0f122                  sal      cl, 0x22
0x1402d184a (+0x2d184a):  4813fd                  adc      rdi, rbp
0x1402d184d (+0x2d184d):  415a                    pop      r10
0x1402d184f (+0x2d184f):  5a                      pop      rdx
0x1402d1850 (+0x2d1850):  ffe7                    jmp      rdi
```

**Reduction of `0x2d1774` (`49` native instructions -> `4` VM operations):**
1. **Load `op1` and `op2` from `VSP` (`rbx`):**
   - `0x2d1774`: `eax = 0x4115b295`, `esi = 0x4115b295`.
   - `0x2d177b`: `mov rbp, [rsi + rbx - 0x4115b295]`. Since `rsi == 0x4115b295`, the constant cancels to `0`: **`rbp = *(uint64_t*)rbx`** (`op1`).
   - `0x2d178b`: `mov rdx, [rsi + rbx - 0x4115b28d]`. `0x4115b295 - 0x4115b28d = +8`: **`rdx = *(uint64_t*)(rbx + 8)`** (`op2`).
2. **Increment `VSP += 8` and add `op1 + op2` through `btc` + `adc`:**
   - `0x2d1793`: `btc rsi, rax`. `btc` masks bit offset mod 64: `0x4115b295 & 0x3f = 0x15` (`21`). Bit `21` (`0x200000`) of `0x4115b295` is `0`, so `btc` sets **`CF = 0`** and sets bit `21` in `rsi` (`rsi = 0x4115b295 | 0x200000 = 0x4135b295`).
   - `0x2d1797`: `lea rbx, [rbx + rsi - 0x4135b28d]`. `0x4135b295 - 0x4135b28d = +8`, giving **`rbx = rbx + 8`** (`VSP += 8`) while leaving `CF = 0` untouched.
   - `0x2d179f`: `adc rbp, rdx` with `CF == 0` computes **`rbp = op1 + op2`**.
3. **Write sum to `*VSP` through `btr` masking:**
   - `0x2d17a9`: `btr eax, 0x29`. `0x29 & 0x1f = 9` (`0x200`). Bit `9` of `0x4115b295` is `1`, so clearing bit `9` produces `eax = 0x4115b095`.
   - `0x2d17ad`: `mov [rbx + rax - 0x4115b095], rbp` writes **`*(uint64_t*)rbx = op1 + op2`**.
4. **Decode next handler offset (`VIP += 4`):**
   - `0x2d17a3`: `r11d = 0x2e1b271b`, so `r11*2 - 0x5c364e36 == 0`. `0x2d17b8: mov ebp, [r9 + r11*2 - 0x5c364e36]` reads **`ebp = *(uint32_t*)r9`**.
   - `0x2d17c0`: `lea r9, [rax + r9 - 0x4115b091]` (`0x4115b095 - 0x4115b091 = +4`) sets **`r9 = r9 + 4`**.
   - `0x2d17d0..0x2d1800` decrypts `ebp` with `r8d` (`xor ebp, r8d; neg ebp; rol ebp, 3; sbb ebp, r10d; rol ebp, 2; bswap ebp`), updates `r8` (`0x2d180d..0x2d1830`), sign-extends `ebp`, computes `rdi += rbp` (`0x2d184a`), pops scratch values, and jumps via **`jmp rdi`** (`0x2d1850`).

### 6.2 `0x3d08d1` (`VPOP_REG64`: `vreg[imm8] = *VSP; VSP += 8`)

```x86asm
0x1403d08d1 (+0x3d08d1):  488b33                  mov      rsi, qword ptr [rbx]
0x1403d08d4 (+0x3d08d4):  b9ad052401              mov      ecx, 0x12405ad
0x1403d08d9 (+0x3d08d9):  4c8d944987f295b6        lea      r10, [rcx + rcx*2 - 0x496a0d79]
0x1403d08e1 (+0x3d08e1):  0fbfd1                  movsx    edx, cx
0x1403d08e4 (+0x3d08e4):  488d9c0b5bfadbfe        lea      rbx, [rbx + rcx - 0x12405a5]
0x1403d08ec (+0x3d08ec):  410fb6ac0953fadbfe      movzx    ebp, byte ptr [r9 + rcx - 0x12405ad]
0x1403d08f5 (+0x3d08f5):  f7d1                    not      ecx
0x1403d08f7 (+0x3d08f7):  4f8d8c1173fcfd45        lea      r9, [r9 + r10 + 0x45fdfc73]
0x1403d08ff (+0x3d08ff):  e98e440b00              jmp      0x140484d92
0x140484d92 (+0x484d92):  440fbfd9                movsx    r11d, cx
0x140484d96 (+0x484d96):  4180ca1d                or       r10b, 0x1d
0x140484d9a (+0x484d9a):  4132e8                  xor      bpl, r8b
0x140484d9d (+0x484d9d):  410fbec2                movsx    eax, r10b
0x140484da1 (+0x484da1):  40f6dd                  neg      bpl
0x140484da4 (+0x484da4):  4080c5b2                add      bpl, 0xb2
0x140484da8 (+0x484da8):  66c1f962                sar      cx, 0x62
0x140484dac (+0x484dac):  66c1e205                shl      dx, 5
0x140484db0 (+0x484db0):  4080f50d                xor      bpl, 0xd
0x140484db4 (+0x484db4):  f6d1                    not      cl
0x140484db6 (+0x484db6):  40f6dd                  neg      bpl
0x140484db9 (+0x484db9):  66f7e1                  mul      cx
0x140484dbc (+0x484dbc):  66440fc1d9              xadd     cx, r11w
0x140484dc1 (+0x484dc1):  4432c5                  xor      r8b, bpl
0x140484dc4 (+0x484dc4):  66c1c06c                rol      ax, 0x6c
0x140484dc8 (+0x484dc8):  4803ec                  add      rbp, rsp
0x140484dcb (+0x484dcb):  41c1eb11                shr      r11d, 0x11
0x140484dcf (+0x484dcf):  41f7d3                  not      r11d
0x140484dd2 (+0x484dd2):  0f8568bbfdff            jne      0x140460940
0x140484dd8 (+0x484dd8):  410fb6941b8aab56eb      movzx    edx, byte ptr [r11 + rbx - 0x14a95476]
0x140484de1 (+0x484de1):  0fb7cb                  movzx    ecx, bx
0x140484de4 (+0x484de4):  33d9                    xor      ebx, ecx
0x140484de6 (+0x484de6):  4012f3                  adc      sil, bl
0x140484de9 (+0x484de9):  4132d0                  xor      dl, r8b
0x140484dec (+0x484dec):  480fc1f1                xadd     rcx, rsi
0x140484df0 (+0x484df0):  48f7d6                  not      rsi
0x140484df3 (+0x484df3):  0fbbf3                  btc      ebx, esi
0x140484df6 (+0x484df6):  32d3                    xor      dl, bl
0x140484df8 (+0x484df8):  440fb6cb                movzx    r9d, bl
0x140484dfc (+0x484dfc):  48c1c18a                rol      rcx, 0x8a
0x140484e00 (+0x484e00):  488db4c9bb1c0f55        lea      rsi, [rcx + rcx*8 + 0x550f1cbb]
0x140484e08 (+0x484e08):  f6d2                    not      dl
0x140484e0a (+0x484e0a):  d0ca                    ror      dl, 1
0x140484e0c (+0x484e0c):  0fbae18c                bt       ecx, 0x8c
0x140484e10 (+0x484e10):  441bce                  sbb      r9d, esi
0x140484e13 (+0x484e13):  49f7d9                  neg      r9
0x140484e16 (+0x484e16):  1ad3                    sbb      dl, bl
0x140484e18 (+0x484e18):  0fb7c6                  movzx    eax, si
0x140484e1b (+0x484e1b):  4432c2                  xor      r8b, dl
0x140484e1e (+0x484e1e):  480fabf1                bts      rcx, rsi
0x140484e22 (+0x484e22):  0fabc8                  bts      eax, ecx
0x140484e25 (+0x484e25):  4803d4                  add      rdx, rsp
0x140484e28 (+0x484e28):  4402ce                  add      r9b, sil
0x140484e2b (+0x484e2b):  51                      push     rcx
0x140484e2c (+0x484e2c):  4159                    pop      r9
0x140484e2e (+0x484e2e):  8b8c1a00fe56eb          mov      ecx, dword ptr [rdx + rbx - 0x14a90200]
0x140484e35 (+0x484e35):  ba1cd2a6e9              mov      edx, 0xe9a6d21c
0x140484e3a (+0x484e3a):  bf9b810341              mov      edi, 0x4103819b
0x140484e3f (+0x484e3f):  6603ff                  add      di, di
0x140484e42 (+0x484e42):  488dac9dfcf75bad        lea      rbp, [rbp + rbx*4 - 0x52a40804]
0x140484e4a (+0x484e4a):  898c2b00fe56eb          mov      dword ptr [rbx + rbp - 0x14a90200], ecx
0x140484e51 (+0x484e51):  4a8d0c4d0ea885ee        lea      rcx, [r9*2 - 0x117a57f2]
0x140484e59 (+0x484e59):  4d0fbbc9                btc      r9, r9
0x140484e5d (+0x484e5d):  4d8d9c1bfcfd56eb        lea      r11, [r11 + rbx - 0x14a90204]
0x140484e65 (+0x484e65):  41c0c103                rol      r9b, 3
0x140484e69 (+0x484e69):  418b9c9b00f85bad        mov      ebx, dword ptr [r11 + rbx*4 - 0x52a40800]
0x140484e71 (+0x484e71):  6641c1f98d              sar      r9w, 0x8d
0x140484e76 (+0x484e76):  0fc0e1                  xadd     cl, ah
0x140484e79 (+0x484e79):  c0c244                  rol      dl, 0x44
0x140484e7c (+0x484e7c):  4133d8                  xor      ebx, r8d
0x140484e7f (+0x484e7f):  4002d7                  add      dl, dil
0x140484e82 (+0x484e82):  66c1c029                rol      ax, 0x29
0x140484e86 (+0x484e86):  4899                    cqo
0x140484e88 (+0x484e88):  f7db                    neg      ebx
0x140484e8a (+0x484e8a):  66c1ceeb                ror      si, 0xeb
0x140484e8e (+0x484e8e):  490fc9                  bswap    r9
0x140484e91 (+0x484e91):  0fcb                    bswap    ebx
0x140484e93 (+0x484e93):  66c1cec6                ror      si, 0xc6
0x140484e97 (+0x484e97):  41c1e932                shr      r9d, 0x32
0x140484e9b (+0x484e9b):  81f32ef93e10            xor      ebx, 0x103ef92e
0x140484ea1 (+0x484ea1):  56                      push     rsi
0x140484ea2 (+0x484ea2):  ffc3                    inc      ebx
0x140484ea4 (+0x484ea4):  42f6544c07              not      byte ptr [rsp + r9*2 + 7]
0x140484ea9 (+0x484ea9):  6687ce                  xchg     si, cx
0x140484eac (+0x484eac):  0fcb                    bswap    ebx
0x140484eae (+0x484eae):  5f                      pop      rdi
0x140484eaf (+0x484eaf):  4150                    push     r8
0x140484eb1 (+0x484eb1):  42311c8c                xor      dword ptr [rsp + r9*4], ebx
0x140484eb5 (+0x484eb5):  48ffc9                  dec      rcx
0x140484eb8 (+0x484eb8):  440bce                  or       r9d, esi
0x140484ebb (+0x484ebb):  99                      cdq
0x140484ebc (+0x484ebc):  4158                    pop      r8
0x140484ebe (+0x484ebe):  4a8d94091a9b3f34        lea      rdx, [rcx + r9 + 0x343f9b1a]
```

Key operations in `0x3d08d1..0x484e4a`:
- `0x3d08d1`: `mov rsi, qword ptr [rbx]` reads `*VSP`.
- `0x3d08d4..0x3d08e4`: `ecx = 0x12405ad`; `lea rbx, [rbx + rcx - 0x12405a5]` increments `rbx` by `+8` (`VSP += 8`).
- `0x3d08ec`: `movzx ebp, byte ptr [r9 + rcx - 0x12405ad]` reads encrypted `imm8` from `[r9]`, and `0x3d08f7` increments `r9` by `+1`.
- `0x484d9a..0x484dc8`: Decrypts `bpl` (`xor bpl, r8b; neg bpl; add bpl, 0xb2; xor bpl, 0x0d; neg bpl`), updates `r8b ^= bpl` (`0x484dc1`), computes `add rbp, rsp` (`0x484dc8`), and writes both 32-bit halves of `rsi` into `[rbp]`.

### 6.3 `0x3042e6` (`VPUSH_IMM64`: `VSP -= 8; *VSP = imm64`)

```x86asm
0x1403042e6 (+0x3042e6):  41bb92b0b4c0            mov      r11d, 0xc0b4b092
0x1403042ec (+0x3042ec):  498b1421                mov      rdx, qword ptr [r9 + riz]
0x1403042f0 (+0x3042f0):  e92b340f00              jmp      0x1403f7720
0x1403f7720 (+0x3f7720):  4b8d8c9b0d298b95        lea      rcx, [r11 + r11*4 - 0x6a74d6f3]
0x1403f7728 (+0x3f7728):  4981c108000000          add      r9, 8
0x1403f772f (+0x3f772f):  fec1                    inc      cl
0x1403f7731 (+0x3f7731):  0fb6f1                  movzx    esi, cl
0x1403f7734 (+0x3f7734):  4933d0                  xor      rdx, r8
0x1403f7737 (+0x3f7737):  4881f2a10433a8          xor      rdx, 0xffffffffa83304a1
0x1403f773e (+0x3f773e):  48c1c203                rol      rdx, 3
0x1403f7742 (+0x3f7742):  488d94169db728eb        lea      rdx, [rsi + rdx - 0x14d74863]
0x1403f774a (+0x3f774a):  4f8d941b024aa9b7        lea      r10, [r11 + r11 - 0x4856b5fe]
0x1403f7752 (+0x3f7752):  41d3e2                  shl      r10d, cl
0x1403f7755 (+0x3f7755):  48c1ca02                ror      rdx, 2
0x1403f7759 (+0x3f7759):  66410fbafa0f            btc      r10w, 0xf
0x1403f775f (+0x3f775f):  488d2ccd9e1a21cd        lea      rbp, [rcx*8 - 0x32dee562]
0x1403f7767 (+0x3f7767):  8bc5                    mov      eax, ebp
0x1403f7769 (+0x3f7769):  4c33c2                  xor      r8, rdx
0x1403f776c (+0x3f776c):  488d8d9c77125e          lea      rcx, [rbp + 0x5e12779c]
0x1403f7773 (+0x3f7773):  6641c1cb0a              ror      r11w, 0xa
0x1403f7778 (+0x3f7778):  488d9c1e10ffffff        lea      rbx, [rsi + rbx - 0xf0]
0x1403f7780 (+0x3f7780):  6698                    cbw
0x1403f7782 (+0x3f7782):  4487de                  xchg     esi, r11d
0x1403f7785 (+0x3f7785):  4a89945300b4a8da        mov      qword ptr [rbx + r10*2 - 0x25574c00], rdx
0x1403f778d (+0x3f778d):  664123c3                and      ax, r11w
0x1403f7791 (+0x3f7791):  40c0c6c6                rol      sil, 0xc6
0x1403f7795 (+0x3f7795):  ba98240a8c              mov      edx, 0x8c0a2498
0x1403f779a (+0x3f779a):  438bb40b18ffffff        mov      esi, dword ptr [r11 + r9 - 0xe8]
0x1403f77a2 (+0x3f77a2):  4f8d8c191cffffff        lea      r9, [r9 + r11 - 0xe4]
0x1403f77aa (+0x3f77aa):  41c0c306                rol      r11b, 6
0x1403f77ae (+0x3f77ae):  4133f0                  xor      esi, r8d
0x1403f77b1 (+0x3f77b1):  d1ce                    ror      esi, 1
0x1403f77b3 (+0x3f77b3):  6641c1e3cb              shl      r11w, 0xcb
0x1403f77b8 (+0x3f77b8):  f7de                    neg      esi
0x1403f77ba (+0x3f77ba):  f6f9                    idiv     cl
0x1403f77bc (+0x3f77bc):  ffce                    dec      esi
0x1403f77be (+0x3f77be):  490fabcb                bts      r11, rcx
0x1403f77c2 (+0x3f77c2):  f7de                    neg      esi
0x1403f77c4 (+0x3f77c4):  d1ce                    ror      esi, 1
0x1403f77c6 (+0x3f77c6):  410bc2                  or       eax, r10d
0x1403f77c9 (+0x3f77c9):  4150                    push     r8
0x1403f77cb (+0x3f77cb):  440fb7c1                movzx    r8d, cx
0x1403f77cf (+0x3f77cf):  4231b45400b4a8da        xor      dword ptr [rsp + r10*2 - 0x25574c00], esi
0x1403f77d7 (+0x3f77d7):  660fa3ca                bt       dx, cx
0x1403f77db (+0x3f77db):  4e8d1cdd06ad1333        lea      r11, [r11*8 + 0x3313ad06]
0x1403f77e3 (+0x3f77e3):  6641c1c3e4              rol      r11w, 0xe4
0x1403f77e8 (+0x3f77e8):  4158                    pop      r8
0x1403f77ea (+0x3f77ea):  490fca                  bswap    r10
0x1403f77ed (+0x3f77ed):  49f7d2                  not      r10
0x1403f77f0 (+0x3f77f0):  4863f6                  movsxd   rsi, esi
0x1403f77f3 (+0x3f77f3):  4813fe                  adc      rdi, rsi
0x1403f77f6 (+0x3f77f6):  4e8d94120f7b20d8        lea      r10, [rdx + r10 - 0x27df84f1]
0x1403f77fe (+0x3f77fe):  480fbaf538              btr      rbp, 0x38
0x1403f7803 (+0x3f7803):  13d1                    adc      edx, ecx
0x1403f7805 (+0x3f7805):  0f8e9aaaf8ff            jle      0x1403822a5
0x1403f780b (+0x3f780b):  4152                    push     r10
0x1403f780d (+0x3f780d):  41c0fbe6                sar      r11b, 0xe6
0x1403f7811 (+0x3f7811):  6633cd                  xor      cx, bp
0x1403f7814 (+0x3f7814):  458bc3                  mov      r8d, r11d
0x1403f7817 (+0x3f7817):  8bc3                    mov      eax, ebx
0x1403f7819 (+0x3f7819):  480fbbc0                btc      rax, rax
0x1403f781d (+0x3f781d):  6681d1a01e              adc      cx, 0x1ea0
0x1403f7822 (+0x3f7822):  c0c081                  rol      al, 0x81
0x1403f7825 (+0x3f7825):  4881f39d4f06f6          xor      rbx, 0xfffffffff6064f9d
0x1403f782c (+0x3f782c):  4898                    cdqe
0x1403f782e (+0x3f782e):  6681f1280c              xor      cx, 0xc28
0x1403f7833 (+0x3f7833):  6641c1c3c1              rol      r11w, 0xc1
0x1403f7838 (+0x3f7838):  4113c2                  adc      eax, r10d
0x1403f783b (+0x3f783b):  4af71c1c                neg      qword ptr [rsp + r11]
0x1403f783f (+0x3f783f):  66d1c1                  rol      cx, 1
0x1403f7842 (+0x3f7842):  664231440405            xor      word ptr [rsp + r8 + 5], ax
0x1403f7848 (+0x3f7848):  420fc05cdc06            xadd     byte ptr [rsp + r11*8 + 6], bl
0x1403f784e (+0x3f784e):  66ffc1                  inc      cx
0x1403f7851 (+0x3f7851):  4180ca11                or       r10b, 0x11
0x1403f7855 (+0x3f7855):  4981eb272fa390          sub      r11, -0x6f5cd0d9
0x1403f785c (+0x3f785c):  66f7d1                  not      cx
0x1403f785f (+0x3f785f):  0f8737020200            ja       0x140417a9c
0x1403f7865 (+0x3f7865):  4532d0                  xor      r10b, r8b
0x1403f7868 (+0x3f7868):  66ffc1                  inc      cx
0x1403f786b (+0x3f786b):  81f3bfa0217d            xor      ebx, 0x7d21a0bf
0x1403f7871 (+0x3f7871):  4898                    cdqe
0x1403f7873 (+0x3f7873):  6633e9                  xor      bp, cx
```

`0x3042ec` reads `mov rdx, qword ptr [r9]`, `0x3f7728` advances `add r9, 8`, `0x3f7734..0x3f7755` decrypts `rdx` (`xor rdx, r8; xor rdx, 0xffffffffa83304a1; rol rdx, 3; lea rdx, [rsi + rdx - 0x14d74863]; ror rdx, 2`), `0x3f7769` updates `xor r8, rdx`, `0x3f7778` decrements `rbx` by `8` (`VSP -= 8`), and `0x3f7785` stores `*VSP = rdx` (`vip_delta = +12`).

### 6.4 `0x319448` (`VPUSH_VSP64`: `tmp = VSP; VSP -= 8; *VSP = tmp`)

```x86asm
0x140319448 (+0x319448):  babfc7bb9e              mov      edx, 0x9ebbc7bf
0x14031944d (+0x31944d):  0fb6c2                  movzx    eax, dl
0x140319450 (+0x319450):  488db4c214a2a837        lea      rsi, [rdx + rax*8 + 0x37a8a214]
0x140319458 (+0x319458):  468b940841ffffff        mov      r10d, dword ptr [rax + r9 - 0xbf]
0x140319460 (+0x319460):  4d8d8c4186feffff        lea      r9, [r9 + rax*2 - 0x17a]
0x140319468 (+0x319468):  f7d2                    not      edx
0x14031946a (+0x31946a):  4533d0                  xor      r10d, r8d
0x14031946d (+0x31946d):  448bd8                  mov      r11d, eax
0x140319470 (+0x319470):  8bca                    mov      ecx, edx
0x140319472 (+0x319472):  41f7da                  neg      r10d
0x140319475 (+0x319475):  4899                    cqo
0x140319477 (+0x319477):  41f7d2                  not      r10d
0x14031947a (+0x31947a):  c0e882                  shr      al, 0x82
0x14031947d (+0x31947d):  488d8c90a9a5a945        lea      rcx, [rax + rdx*4 + 0x45a9a5a9]
0x140319485 (+0x319485):  410fbfeb                movsx    ebp, r11w
0x140319489 (+0x319489):  410fca                  bswap    r10d
0x14031948c (+0x31948c):  66f7d2                  not      dx
0x14031948f (+0x31948f):  48ffc2                  inc      rdx
0x140319492 (+0x319492):  41ffc2                  inc      r10d
0x140319495 (+0x319495):  41c1c202                rol      r10d, 2
0x140319499 (+0x319499):  48f7ea                  imul     rdx
0x14031949c (+0x31949c):  49d3f3                  sal      r11, cl
0x14031949f (+0x31949f):  468d94166409d4b6        lea      r10d, [rsi + r10 - 0x492bf69c]
0x1403194a7 (+0x3194a7):  4112d3                  adc      dl, r11b
0x1403194aa (+0x3194aa):  0fca                    bswap    edx
0x1403194ac (+0x3194ac):  98                      cwde
0x1403194ad (+0x3194ad):  4150                    push     r8
0x1403194af (+0x3194af):  443114d4                xor      dword ptr [rsp + rdx*8], r10d
0x1403194b3 (+0x3194b3):  49ffc3                  inc      r11
0x1403194b6 (+0x3194b6):  4158                    pop      r8
0x1403194b8 (+0x3194b8):  4d63d2                  movsxd   r10, r10d
0x1403194bb (+0x3194bb):  41f6fb                  idiv     r11b
0x1403194be (+0x3194be):  4903fa                  add      rdi, r10
0x1403194c1 (+0x3194c1):  410fb3cb                btr      r11d, ecx
0x1403194c5 (+0x3194c5):  660fc1d1                xadd     cx, dx
0x1403194c9 (+0x3194c9):  4c8bd3                  mov      r10, rbx
0x1403194cc (+0x3194cc):  0f8aa86c1900            jp       0x1404b017a
0x1403194d2 (+0x3194d2):  6623d5                  and      dx, bp
0x1403194d5 (+0x3194d5):  f6d8                    neg      al
0x1403194d7 (+0x3194d7):  51                      push     rcx
0x1403194d8 (+0x3194d8):  66440fc1cb              xadd     bx, r9w
0x1403194dd (+0x3194dd):  40c0f7e6                sal      dil, 0xe6
0x1403194e1 (+0x3194e1):  1c99                    sbb      al, 0x99
0x1403194e3 (+0x3194e3):  41f6d9                  neg      r9b
0x1403194e6 (+0x3194e6):  81746c0232169268        xor      dword ptr [rsp + rbp*2 + 2], 0x68921632
0x1403194ee (+0x3194ee):  0f9204ac                setb     byte ptr [rsp + rbp*4]
0x1403194f2 (+0x3194f2):  4432d0                  xor      r10b, al
0x1403194f5 (+0x3194f5):  66c1742c03c7            sal      word ptr [rsp + rbp + 3], 0xc7
0x1403194fb (+0x3194fb):  0f86106b1600            jbe      0x140480011
0x140319501 (+0x319501):  48f7da                  neg      rdx
0x140319504 (+0x319504):  31bc6c0000ffff          xor      dword ptr [rsp + rbp*2 - 0x10000], edi
0x14031950b (+0x31950b):  48d3f1                  sal      rcx, cl
0x14031950e (+0x31950e):  440fb7d3                movzx    r10d, bx
0x140319512 (+0x319512):  480fbaf595              btr      rbp, 0x95
0x140319517 (+0x319517):  415a                    pop      r10
0x140319519 (+0x319519):  4863ff                  movsxd   rdi, edi
0x14031951c (+0x31951c):  c0eb61                  shr      bl, 0x61
0x14031951f (+0x31951f):  4c13df                  adc      r11, rdi
0x140319522 (+0x319522):  66ffcb                  dec      bx
0x140319525 (+0x319525):  0fca                    bswap    edx
0x140319527 (+0x319527):  c0e1e6                  shl      cl, 0xe6
0x14031952a (+0x31952a):  41ffe3                  jmp      r11
```

### 6.5 Mutated Code and Jump-Chain Folding (`2,858` Links)

Outside the 87 virtualized functions, `123` routines in `.be0` and `.text` use VMProtect's mutation pass without bytecode virtualization. Static normalization across all `137` non-virtualized routines (`48,789` raw instructions) collapsed **`2,858` unconditional `jmp` links**. Disassembly of `0x4d6efe` (the `.be0` target of `0xc2fc` `BeCaptureStackWalkAndSignal`):

```x86asm
0x1404d6efe (+0x4d6efe):  4053                    push     rbx
0x1404d6f00 (+0x4d6f00):  4883ec20                sub      rsp, 0x20
0x1404d6f04 (+0x4d6f04):  c0f581                  sal      ch, 0x81
0x1404d6f07 (+0x4d6f07):  4184fd                  test     r13b, dil
0x1404d6f0a (+0x4d6f0a):  498b19                  mov      rbx, qword ptr [r9]
0x1404d6f0d (+0x4d6f0d):  48c7c20862add3          mov      rdx, 0xffffffffd3ad6208
0x1404d6f14 (+0x4d6f14):  4533c0                  xor      r8d, r8d
0x1404d6f17 (+0x4d6f17):  480fb7d1                movzx    rdx, cx
0x1404d6f1b (+0x4d6f1b):  66400fbecf              movsx    cx, dil
0x1404d6f20 (+0x4d6f20):  f6d1                    not      cl
0x1404d6f22 (+0x4d6f22):  ba00010000              mov      edx, 0x100
0x1404d6f27 (+0x4d6f27):  410f40c8                cmovo    ecx, r8d
0x1404d6f2b (+0x4d6f2b):  0f99c1                  setns    cl
0x1404d6f2e (+0x4d6f2e):  488d4b70                lea      rcx, [rbx + 0x70]
0x1404d6f32 (+0x4d6f32):  ff151806b4ff            call     qword ptr [rip - 0x4bf9e8]
0x1404d6f38 (+0x4d6f38):  488d4b58                lea      rcx, [rbx + 0x58]
0x1404d6f3c (+0x4d6f3c):  4584f9                  test     r9b, r15b
0x1404d6f3f (+0x4d6f3f):  452bc0                  sub      r8d, r8d
0x1404d6f42 (+0x4d6f42):  e900000000              jmp      0x1404d6f47
0x1404d6f47 (+0x4d6f47):  33d2                    xor      edx, edx
0x1404d6f49 (+0x4d6f49):  6641f7c38df9            test     r11w, 0xf98d
0x1404d6f4f (+0x4d6f4f):  4881f892552375          cmp      rax, 0x75235592
0x1404d6f56 (+0x4d6f56):  f9                      stc
0x1404d6f57 (+0x4d6f57):  898370080000            mov      dword ptr [rbx + 0x870], eax
0x1404d6f5d (+0x4d6f5d):  66ffcb                  dec      bx
0x1404d6f60 (+0x4d6f60):  48ffc3                  inc      rbx
0x1404d6f63 (+0x4d6f63):  4883c420                add      rsp, 0x20
0x1404d6f67 (+0x4d6f67):  0f92c3                  setb     bl
0x1404d6f6a (+0x4d6f6a):  490fb7db                movzx    rbx, r11w
0x1404d6f6e (+0x4d6f6e):  5b                      pop      rbx
0x1404d6f6f (+0x4d6f6f):  e900000000              jmp      0x1404d6f74
0x1404d6f74 (+0x4d6f74):  48ff259503b4ff          jmp      qword ptr [rip - 0x4bfc6b]
```

The live instructions in `0x4d6efe` execute four C operations:
1. `rdi = *(void**)r9;` (`0x4d6f0a: mov rbx, qword ptr [r9]`)
2. `eax = RtlWalkFrameChain((PVOID*)((char*)rdi + 0x70), 0x100, 0);` (`0x4d6f14..0x4d6f32`, calling `[0x140017550]`)
3. `*(uint32_t*)((char*)rdi + 0x870) = eax;` (`0x4d6f57`)
4. `return KeSetEvent((PRKEVENT)((char*)rdi + 0x58), 0, FALSE);` (`0x4d6f38..0x4d6f74`, tail-jumping via `[0x140017310]`)

All interspersed instructions (`sal ch, 0x81`, `test r13b, dil`, `mov rdx, 0xffffffffd3ad6208`, `cmovo ecx, r8d`, `setns cl`, `cmp rax, 0x75235592`, `stc`, `dec bx; inc rbx`, `setb bl`, `movzx rbx, r11w`) write to dead partial registers or flags overwritten before any consumer reads them.

---

## 7. Encryption Algorithms and Runtime String Decryption

### 7.1 VMProtect 3.8+ Rolling-Key Bytecode Cipher

All 10 VMs decrypt bytecode inline with add/rotate/xor (ARX) ops and a rolling key register `K`. There is no shared decryption routine or lookup table; each handler has its own `8`, `16`, `32`, or `64`-bit math and XORs the decrypted value back into `K`.

Four examples pulled from `.be0` handlers:

#### Example 1: VM #1 (`0x2c91b5`, `VIP = rsi`, `K = r11`)
```c
// 8-bit operand decryption (0x1402c9221 .. 0x1402c925b)
uint8_t enc8 = *(uint8_t*)(VIP + offset);
uint8_t x    = enc8 ^ (uint8_t)K;
x = x + 0x95;
x = (x >> 1) | (x << 7);          // ror8(x, 1)
x = x - carry_mask;               // sub r10b, cl
uint8_t plain8 = (x << 1) | (x >> 7); // rol8(x, 1)
K = (K & ~0xFFULL) | ((uint8_t)K ^ plain8); // xor r11b, r10b (feedback)

// 32-bit delta decryption (0x1402c9287 .. 0x1402c92b3)
uint32_t enc32 = *(uint32_t*)(VIP + offset32);
uint32_t y     = enc32 ^ (uint32_t)K;
y = y + (uint32_t)(rax * 2) + 0x47e02096U;
y = (y << 2) | (y >> 30);         // rol32(y, 2)
uint32_t plain32 = y + (uint32_t)(rdx * 2) - 0x5a7cf593U;
```

#### Example 2: VM #4 `VPOP_REG64` (`0x3d08d1`, `VIP = r9`, `K = r8`)
```c
// 8-bit vreg index decryption (0x1403d08ec .. 0x140484dc1)
uint8_t enc8 = *VIP++;
uint8_t x    = enc8 ^ (uint8_t)K;
x = (uint8_t)(-x);                // neg bpl
x = x + 0xB2;                     // add bpl, 0xb2
x = x ^ 0x0D;                     // xor bpl, 0x0d
uint8_t vreg_off = (uint8_t)(-x); // neg bpl
K = (K & ~0xFFULL) | ((uint8_t)K ^ vreg_off); // xor r8b, bpl
```
**Reversing the cipher:**
Given plaintext byte `vreg_off` and key byte `K_8`, set `y = -vreg_off` and `x_prev = (y ^ 0x0D) - 0xB2`; then `enc8 = (-x_prev) ^ K_8` and the next key byte is `K_8' = K_8 ^ vreg_off`. Every step (`neg`, `add`, `xor`, `rol`/`ror`, `bswap`) is invertible mod $2^w$.

#### Example 3: VM #4 `VPUSH_IMM64` (`0x3042e6`, `VIP = r9`, `K = r8`)
```c
// 64-bit constant decryption (0x1403042ec .. 0x1403f7769)
uint64_t enc64 = *(uint64_t*)VIP;
VIP += 8;
uint64_t x = enc64 ^ K ^ 0xFFFFFFFFA83304A1ULL;
x = (x << 3) | (x >> 61);         // rol64(x, 3)
x = x + 0x91ULL - 0x14D74863ULL;  // lea rdx, [rsi + rdx - 0x14d74863] (esi = 0x91)
uint64_t plain64 = (x >> 2) | (x << 62); // ror64(x, 2)
K ^= plain64;                     // xor r8, rdx
```

#### Example 4: VM #6 (`0x37dbff`, `VIP = r9`, `K = ebp`)
```c
// 32-bit fetch + bswap (0x14037dca6 .. 0x14037dcc9)
uint32_t enc32   = *(uint32_t*)VIP;
VIP += 4;
uint32_t plain32 = __builtin_bswap32(enc32 ^ K);
```

Because we only mark function arguments, external memory reads, and API return values as symbolic in `Triton`, `VIP` and `K` stay concrete during tracing. `Triton` folds the rolling-key math into plain constants while keeping actual data operations symbolic.

### 7.2 Runtime String Decryption (`143` Recovered Strings)

Non-`.be0` sections of `BEDaisy.sys` contain `238` printable ASCII strings and `0` UTF-16LE strings. Instead of storing encrypted strings in `.rdata` or `.data` and decrypting them in bulk at startup, `BEDaisy.sys` writes strings onto the thread stack (`0x701FB...`) right before calling kernel APIs and reclaims the stack space upon return:

1. **VM stack construction (`VPUSH_IMM64` + `VWRITE_MEM`):** Inside virtualized routines (`DriverMain` `0x10b20`, `BeDriverUnload` `0x2180`, `0x36a4`, `0x4b70`, `0xed80`, `0x12494`, `0x138f0`), 64-bit and 32-bit character chunks are decrypted from bytecode via `VPUSH_IMM64`, written to `[VSP + offset]` on the native stack (`0x701fbef0..0x701fbfc0`), and passed to `RtlInitUnicodeString` or `_stricmp`.
2. **Mutated inline stack writes:** In mutated `.be0` functions such as `0xd190 -> 0x4d8b15` (disassembled below), stack space (`sub rsp, 0x1a0`) is zeroed with `xorps xmm0, xmm0; movdqu [rbp - 0x10], xmm0` while `OBJECT_ATTRIBUTES` (`Length = 0x30` at `[rbp - 0x30]`, `Attributes = 0x240` at `[rbp - 0x18]`) and ASCII string `"dxgkrnl.sys"` are assembled on the stack and passed to `_stricmp`.

```x86asm
0x14000d190 (+0x00d190):  e980b94c00              jmp      0x1404d8b15
0x1404d8b15 (+0x4d8b15):  48895c2410              mov      qword ptr [rsp + 0x10], rbx
0x1404d8b1a (+0x4d8b1a):  55                      push     rbp
0x1404d8b1b (+0x4d8b1b):  56                      push     rsi
0x1404d8b1c (+0x4d8b1c):  4180fb05                cmp      r11b, 5
0x1404d8b20 (+0x4d8b20):  4080f5ab                xor      bpl, 0xab
0x1404d8b24 (+0x4d8b24):  57                      push     rdi
0x1404d8b25 (+0x4d8b25):  40b515                  mov      bpl, 0x15
0x1404d8b28 (+0x4d8b28):  4154                    push     r12
0x1404d8b2a (+0x4d8b2a):  4155                    push     r13
0x1404d8b2c (+0x4d8b2c):  4156                    push     r14
0x1404d8b2e (+0x4d8b2e):  410fc1c6                xadd     r14d, eax
0x1404d8b32 (+0x4d8b32):  4157                    push     r15
0x1404d8b34 (+0x4d8b34):  c6c417                  mov      ah, 0x17
0x1404d8b37 (+0x4d8b37):  660fabed                bts      bp, bp
0x1404d8b3b (+0x4d8b3b):  488dac2460ffffff        lea      rbp, [rsp - 0xa0]
0x1404d8b43 (+0x4d8b43):  4881eca0010000          sub      rsp, 0x1a0
0x1404d8b4a (+0x4d8b4a):  488b05cfe5b3ff          mov      rax, qword ptr [rip - 0x4c1a31]
0x1404d8b51 (+0x4d8b51):  410fce                  bswap    r14d
0x1404d8b54 (+0x4d8b54):  664487f2                xchg     dx, r14w
0x1404d8b58 (+0x4d8b58):  d2ce                    ror      dh, cl
0x1404d8b5a (+0x4d8b5a):  4833c4                  xor      rax, rsp
0x1404d8b5d (+0x4d8b5d):  03d3                    add      edx, ebx
0x1404d8b5f (+0x4d8b5f):  452bf7                  sub      r14d, r15d
0x1404d8b62 (+0x4d8b62):  48898590000000          mov      qword ptr [rbp + 0x90], rax
0x1404d8b69 (+0x4d8b69):  4132d5                  xor      dl, r13b
0x1404d8b6c (+0x4d8b6c):  4881c2923412d7          add      rdx, -0x28edcb6e
0x1404d8b73 (+0x4d8b73):  4d8bf1                  mov      r14, r9
0x1404d8b76 (+0x4d8b76):  4c894da8                mov      qword ptr [rbp - 0x58], r9
0x1404d8b7a (+0x4d8b7a):  48894da0                mov      qword ptr [rbp - 0x60], rcx
0x1404d8b7e (+0x4d8b7e):  4c8d4dc0                lea      r9, [rbp - 0x40]
0x1404d8b82 (+0x4d8b82):  480fbfd4                movsx    rdx, sp
0x1404d8b86 (+0x4d8b86):  4533ff                  xor      r15d, r15d
0x1404d8b89 (+0x4d8b89):  668bd7                  mov      dx, di
0x1404d8b8c (+0x4d8b8c):  4c8945e0                mov      qword ptr [rbp - 0x20], r8
0x1404d8b90 (+0x4d8b90):  0f57c0                  xorps    xmm0, xmm0
0x1404d8b93 (+0x4d8b93):  c744242820000000        mov      dword ptr [rsp + 0x28], 0x20
0x1404d8b9b (+0x4d8b9b):  458ac6                  mov      r8b, r14b
0x1404d8b9e (+0x4d8b9e):  4899                    cqo
0x1404d8ba0 (+0x4d8ba0):  4c8d45d0                lea      r8, [rbp - 0x30]
0x1404d8ba4 (+0x4d8ba4):  0f90c1                  seto     cl
0x1404d8ba7 (+0x4d8ba7):  44897c245c              mov      dword ptr [rsp + 0x5c], r15d
0x1404d8bac (+0x4d8bac):  c6c686                  mov      dh, 0x86
0x1404d8baf (+0x4d8baf):  4899                    cqo
0x1404d8bb1 (+0x4d8bb1):  410fb7d4                movzx    edx, r12w
0x1404d8bb5 (+0x4d8bb5):  488d4d98                lea      rcx, [rbp - 0x68]
0x1404d8bb9 (+0x4d8bb9):  418ad3                  mov      dl, r11b
0x1404d8bbc (+0x4d8bbc):  f7d2                    not      edx
0x1404d8bbe (+0x4d8bbe):  4c897dd8                mov      qword ptr [rbp - 0x28], r15
0x1404d8bc2 (+0x4d8bc2):  ba00000080              mov      edx, 0x80000000
0x1404d8bc7 (+0x4d8bc7):  c745d030000000          mov      dword ptr [rbp - 0x30], 0x30
0x1404d8bce (+0x4d8bce):  e900000000              jmp      0x1404d8bd3
0x1404d8bd3 (+0x4d8bd3):  f30f7f45f0              movdqu   xmmword ptr [rbp - 0x10], xmm0
0x1404d8bd8 (+0x4d8bd8):  c745e840020000          mov      dword ptr [rbp - 0x18], 0x240
0x1404d8bdf (+0x4d8bdf):  c744242007000000        mov      dword ptr [rsp + 0x20], 7
0x1404d8be7 (+0x4d8be7):  e900000000              jmp      0x1404d8bec
0x1404d8bec (+0x4d8bec):  ff15d6e7b3ff            call     qword ptr [rip - 0x4c182a]
0x1404d8bf2 (+0x4d8bf2):  85c0                    test     eax, eax
0x1404d8bf4 (+0x4d8bf4):  0f88280c0000            js       0x1404d9822
0x1404d8bfa (+0x4d8bfa):  ba00200000              mov      edx, 0x2000
```

Emulating `DriverEntry` (`0x1a000`, `800,000` steps) and all `224` PDATA functions (`250,000` steps each) with hooks on `RtlInitUnicodeString`, `RtlInitAnsiString`, `MmGetSystemRoutineAddress`, `FltGetRoutineAddress`, `ZwOpen*`, `IoCreate*`, `RtlCompareUnicodeString`, `_stricmp`, and `wcs*` plus stack/heap buffer scans at API calls and function exits recovered **`143` unique runtime-decrypted strings (`100%` absent from non-`.be0` static plaintext)**:

- **`130` Kernel & Minifilter API Names:** All `124` `DriverMain` IAT imports plus `6` stack-constructed names inside worker routines:
  - `PsSetLoadImageNotifyRoutineEx` (`0xf6dc`, `0xfcfc`)
  - `ZwProtectVirtualMemory` (`0x12494`, `0x12660` alongside `:\WINDOWS\SYSTEM32\NTDLL.DLL`)
  - `ZwSuspendThread` (`0x13034`, `0x4e74e0`)
  - `NtCancelTimer` (`0xcae8`, `0x4d7e32`)
  - `HalDispatchT` (prefix of `HalDispatchTable` on exit stack of `0xe3e4`)
- **`13` Operational Strings (Devices, Object Directories, Modules, Tags):**
  - `\Device\BattlEye` and `\DosDevices\BattlEye` (`DriverMain`, `BeDriverUnload` `0x2180`)
  - `363220` (`ObRegisterCallbacks` altitude in `DriverMain` and `0x36a4`)
  - `\Device\PhysicalMemory` (`ZwOpenSection` in `DriverMain`, `0x138f0`, `0x4e8427`)
  - `:\WINDOWS\SYSTEM32\NTDLL.DLL` (`0xcae8`, `0x11858`, `0x12494`, `0x12660`, `0x13034`) and `ntdll.dll` (`0x11468`)
  - `\Driver` and `Driver` (`DriverMain` and `0xed80` directory enumeration)
  - `\FileSystem` (`DriverMain` and `0x4b70` object name check)
  - `dxgkrnl.sys` (`0xd190` / `0x4d8b15`) and `DxgCoreInter` (`DxgCoreInterface` in `0xdfdc`)
  - `csrss.exe` (`0xe114`)
  - `Circular Ke` (`Circular Kernel Context Logger` ETW session check in `0x10764`)
  - `BEPatent` (`0x11b40`)

#### All `143` Dynamically Recovered Strings

| # | Decrypted String | Encoding | Category | Source Function RVAs | Recovery Point |
|---:|---|---|---|---|---|
| 1 | `363220` | `UTF-16LE` | `other` | `0x36a4` | `RtlInitUnicodeString, api_RtlInitUnicodeString_stack` |
| 2 | `:\WINDOWS\SYSTEM32\NTDLL.DLL` | `UTF-16LE` | `file_or_driver_path` | `0xcae8`, `0x11858`, `0x12494`, `0x12660`, `0x13034` (+2) | `api_RtlInitUnicodeString_stack, api_ZwCreateSection_stack` |
| 3 | `\Device\PhysicalMemory` | `UTF-16LE` | `device_symlink` | `0x138f0`, `0x4e8427` | `RtlInitUnicodeString, ZwOpenSection` |
| 4 | `\DosDevices\BattlEye` | `UTF-16LE` | `device_symlink` | `0x2180` | `RtlInitUnicodeString, api_FltUnregisterFilter_stack` |
| 5 | `\Driver` | `UTF-16LE` | `nt_object_path` | `0xed80` | `RtlInitUnicodeString, ZwOpenDirectoryObject` |
| 6 | `\FileSystem` | `UTF-16LE` | `nt_object_path` | `0x4b70` | `exit_stack` |
| 7 | `\Registry\Machine\System\CurrentControlSet\Services\BEDaisy` | `UTF-16LE` | `kernel_api` | `0x1a000` | `api_MmGetSystemRoutineAddress_buf, exit_buf` |
| 8 | `_stricmp` | `UTF-16LE` | `kernel_api` | `0x6248`, `0x1a000`, `0x4e8c37` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 9 | `_strnicmp` | `UTF-16LE` | `kernel_api` | `0x6248`, `0x1a000`, `0x4e8c37` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 10 | `_wcsicmp` | `UTF-16LE` | `kernel_api` | `0x6248`, `0x1a000`, `0x4e8c37` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 11 | `_wcslwr` | `UTF-16LE` | `kernel_api` | `0x6248`, `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 12 | `_wcsnicmp` | `UTF-16LE` | `kernel_api` | `0x6248`, `0x1a000`, `0x4e8c37` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 13 | `BEPatent` | `ASCII` | `other` | `0x11b40` | `exit_stack` |
| 14 | `Circular Ke` | `UTF-16LE` | `other` | `0x10764` | `exit_stack` |
| 15 | `CmUnRegisterCallback` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 16 | `csrss.exe` | `ASCII` | `file_or_driver_path` | `0xe114` | `exit_stack` |
| 17 | `Driver` | `UTF-16LE` | `other` | `0xed80` | `RtlInitUnicodeString` |
| 18 | `DxgCoreInter` | `ASCII` | `other` | `0xdfdc` | `exit_stack` |
| 19 | `dxgkrnl.sys` | `ASCII` | `file_or_driver_path` | `0xd190`, `0x4d8b15` | `_stricmp, api__stricmp_stack` |
| 20 | `ExAllocatePool` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 21 | `ExAllocatePoolWithTag` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 22 | `ExEnumHandleTable` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 23 | `ExFreePoolWithTag` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 24 | `ExfUnblockPushLock` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 25 | `FltGetFileNameInformation` | `ASCII` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 26 | `FltGetRequestorProcess` | `ASCII` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 27 | `FltQueryInformationFile` | `ASCII` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 28 | `FltReadFile` | `ASCII` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 29 | `FltRegisterFilter` | `ASCII` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 30 | `FltReleaseFileNameInformation` | `ASCII` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 31 | `FltStartFiltering` | `ASCII` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 32 | `FltUnregisterFilter` | `ASCII` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 33 | `HalDispatchT` | `ASCII` | `kernel_api` | `0xe3e4` | `exit_stack` |
| 34 | `IoAllocateMdl` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 35 | `IoCreateDevice` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 36 | `IoCreateSymbolicLink` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 37 | `IoDeleteDevice` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 38 | `IoDeleteSymbolicLink` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 39 | `IoDriverObjectType` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 40 | `IofCompleteRequest` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 41 | `IoFileObjectType` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 42 | `IoFreeMdl` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 43 | `IoGetCurrentProcess` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 44 | `IoGetTopLevelIrp` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 45 | `IoQueryFileDosDeviceName` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 46 | `IoThreadToProcess` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 47 | `KeDelayExecutionThread` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 48 | `KeInitializeApc` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 49 | `KeInitializeEvent` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 50 | `KeInitializeMutex` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 51 | `KeInsertQueueApc` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 52 | `KeReleaseMutex` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 53 | `KeSetEvent` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 54 | `KeStackAttachProcess` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 55 | `KeUnstackDetachProcess` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 56 | `KeWaitForSingleObject` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 57 | `MmCopyMemory` | `UTF-16LE` | `kernel_api` | `0xddec`, `0xffc8`, `0x1a000`, `0x4e00c6` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 58 | `MmCopyVirtualMemory` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 59 | `MmGetPhysicalAddress` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 60 | `MmIsAddressValid` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 61 | `MmMapIoSpace` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 62 | `MmProbeAndLockPages` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 63 | `MmUnlockPages` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 64 | `MmUnmapIoSpace` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 65 | `MmUnmapViewOfSection` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 66 | `NtBuildNumber` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 67 | `NtCancelTimer` | `ASCII` | `kernel_api` | `0xcae8`, `0x4d7e32` | `api_RtlInitUnicodeString_stack, api_ZwCreateSection_stack` |
| 68 | `ntdll.dll` | `UTF-16LE` | `file_or_driver_path` | `0x11468` | `exit_stack` |
| 69 | `ObfDereferenceObject` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 70 | `ObfReferenceObject` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 71 | `ObOpenObjectByName` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 72 | `ObOpenObjectByPointer` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 73 | `ObQueryNameString` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 74 | `ObReferenceObjectByHandle` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 75 | `ObReferenceObjectByName` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 76 | `ObRegisterCallbacks` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 77 | `ObUnRegisterCallbacks` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 78 | `ProbeForRead` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 79 | `ProbeForWrite` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 80 | `PsAcquireProcessExitSynchronization` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 81 | `PsCreateSystemThread` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 82 | `PsGetContextThread` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 83 | `PsGetCurrentProcessId` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 84 | `PsGetCurrentThreadId` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 85 | `PsGetProcessId` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 86 | `PsGetProcessImageFileName` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 87 | `PsGetProcessInheritedFromUniqueProcessId` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 88 | `PsGetProcessPeb` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 89 | `PsGetProcessSessionId` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 90 | `PsGetProcessWow64Process` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 91 | `PsGetThreadId` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 92 | `PsGetThreadProcess` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 93 | `PsGetThreadProcessId` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 94 | `PsInitialSystemProcess` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 95 | `PsLookupProcessByProcessId` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 96 | `PsLookupThreadByThreadId` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 97 | `PsProcessType` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 98 | `PsReleaseProcessExitSynchronization` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 99 | `PsRemoveCreateThreadNotifyRoutine` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 100 | `PsRemoveLoadImageNotifyRoutine` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 101 | `PsResumeProcess` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 102 | `PsSetCreateProcessNotifyRoutineEx` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 103 | `PsSetCreateThreadNotifyRoutine` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 104 | `PsSetLoadImageNotifyRoutine` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 105 | `PsSetLoadImageNotifyRoutineEx` | `UTF-16LE` | `kernel_api` | `0xf6dc`, `0xfcfc` | `MmGetSystemRoutineAddress, api_MmGetSystemRoutineAddress_stack` |
| 106 | `PsSuspendProcess` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 107 | `PsTerminateSystemThread` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 108 | `PsThreadType` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 109 | `RtlAnsiStringToUnicodeString` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 110 | `RtlCompareUnicodeString` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 111 | `RtlFreeAnsiString` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 112 | `RtlFreeUnicodeString` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 113 | `RtlGetVersion` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 114 | `RtlImageNtHeader` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 115 | `RtlInitAnsiString` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 116 | `RtlInitUnicodeString` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 117 | `RtlRandomEx` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 118 | `RtlUnicodeStringToAnsiString` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 119 | `RtlWalkFrameChain` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 120 | `wcslen` | `UTF-16LE` | `kernel_api` | `0x6248`, `0x1a000`, `0x4e8c37` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 121 | `wcsncat` | `UTF-16LE` | `kernel_api` | `0x6248`, `0x1a000`, `0x4e8c37` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 122 | `wcsncmp` | `UTF-16LE` | `kernel_api` | `0x6248`, `0x1a000`, `0x4e8c37` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 123 | `wcsstr` | `UTF-16LE` | `kernel_api` | `0x6248`, `0x1a000`, `0x4e8c37` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 124 | `ZwAllocateVirtualMemory` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 125 | `ZwClose` | `UTF-16LE` | `kernel_api` | `0x1199c`, `0x12494`, `0x13034`, `0x1a000`, `0x4e74e0` | `IAT_RECONSTRUCTED, MmGetSystemRoutineAddress` |
| 126 | `ZwCreateSection` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 127 | `ZwDeviceIoControlFile` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 128 | `ZwFreeVirtualMemory` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 129 | `ZwMapViewOfSection` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 130 | `ZwOpenDirectoryObject` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 131 | `ZwOpenFile` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 132 | `ZwOpenSection` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 133 | `ZwOpenThread` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 134 | `ZwProtectVirtualMemory` | `ASCII` | `kernel_api` | `0x12494`, `0x12660` | `api_RtlInitUnicodeString_stack, api_ZwCreateSection_stack` |
| 135 | `ZwQueryDirectoryObject` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 136 | `ZwQueryInformationFile` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 137 | `ZwQueryInformationThread` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 138 | `ZwQuerySystemInformation` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 139 | `ZwReadFile` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 140 | `ZwSuspendThread` | `ASCII` | `kernel_api` | `0x13034`, `0x4e74e0` | `api_MmGetSystemRoutineAddress_stack, api_RtlInitUnicodeString_stack` |
| 141 | `ZwTerminateProcess` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 142 | `ZwTraceControl` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |
| 143 | `ZwUnmapViewOfSection` | `UTF-16LE` | `kernel_api` | `0x1a000` | `IAT_RECONSTRUCTED` |

---

## 8. Mixed Boolean-Arithmetic (MBA) Structures and Simplification

MBA obfuscation in `BEDaisy.sys` appears in four specific forms:

### 8.1 Universal `VNAND` Gate Synthesis in VM ALU Handlers

VMProtect omits dedicated `xor`, `and`, `or`, and `not` bytecode instructions, building bitwise operations out of 64-bit `VNAND(a, b) = ~(a & b)` (or `~a | ~b`) handlers:

$$\neg x = \text{VNAND}(x, x)$$

$$x \wedge y = \neg \text{VNAND}(x, y)$$

$$x \oplus y = \text{VNAND}\big(\text{VNAND}(x, \text{VNAND}(x, y)),\; \text{VNAND}(y, \text{VNAND}(x, y))\big)$$

Before simplification, a 64-bit `a ^ b` lifts to `~(~(a & ~(a & b)) & ~(b & ~(a & b)))`. Equivalence to `a ^ b` was checked with `Z3` (`Solver.check(mba_expr != (a ^ b)) == unsat` over `BitVec(64)`) and folded to native `xor` by `LLVM -O3` `instcombine`.

### 8.2 Unary/XOR Chains on `VIP` and Rolling Keys

In VM #6 (`0x37dc1a..0x37dc2c`), updating `r9d` runs five instructions:

```x86asm
inc  r9d                ; r9_1 = x + 1
not  r9d                ; r9_2 = ~(x + 1) = -x - 2
xor  r9d, 0xbc2af703    ; r9_3 = (-x - 2) ^ 0xbc2af703
dec  r9d                ; r9_4 = ((-x - 2) ^ 0xbc2af703) - 1
neg  r9d                ; r9_5 = 1 - ((-x - 2) ^ 0xbc2af703)
```

Applying $-u = \sim u + 1 \implies 1 - u = \sim u + 2$ reduces `dec; neg`:

$$r9_5 = \sim\big((\sim(x + 1)) \oplus \text{0xbc2af703}\big) + 2 = \big((x + 1) \oplus \text{0xbc2af703}\big) + 2$$

### 8.3 Flag-Coupled `btc`/`btr` Displacement Masking

In Section 6.1 (`0x2d1774`), VMProtect loads `eax = esi = 0x4115b295`, uses `btc rsi, rax` to clear `CF = 0` (consumed by `adc rbp, rdx`) while setting bit `21` of `rsi` (`+0x200000`), and then computes `lea rbx, [rbx + rsi - 0x4135b28d]` so `+0x200000` cancels `-0x4135b28d` down to `+8`. Static pattern matchers that ignore bit-test side effects on the base register miscalculate the stack displacement by `0x200000` bytes.

### 8.4 Signed-Overflow Null Checks in Lifted IR

Even after VM handler removal and `LLVM -O3`, lifted routines (`0xe3e4`, `0x4b70`, `0x26ac`, `0x4df5f9`) retain branchless null/sign tests emitted by VMProtect's compiler:

```llvm
; Lifted from 0x4b70 (BeQueryFileSystemObjectName) and 0xe3e4 (BeValidatePeImageDirectory):
%sum = add i64 %ptr, 9223372036854775807   ; %ptr + 0x7fffffffffffffff
%msk = or i64 %sum, %ptr
%ok  = icmp sgt i64 %msk, -1               ; sign_bit((%ptr + INT64_MAX) | %ptr) == 0
```

Evaluating `sign_bit((x + 0x7fffffffffffffff) | x)` across 64-bit `x`:
- For `x == 0`: `(0 + 0x7fffffffffffffff) | 0 = 0x7fffffffffffffff`, sign bit is `0` (`sgt -1` is `true`).
- For `1 <= x <= 0x7fffffffffffffff`: `x + 0x7fffffffffffffff` overflows into `0x8000000000000000 .. 0xfffffffffffffffe`, sign bit is `1` (`sgt -1` is `false`).
- For `x >= 0x8000000000000000`: `x` already has bit `63 == 1`, so `| x` sets sign bit `1` (`sgt -1` is `false`).

Therefore `((x + 0x7fffffffffffffff) | x) >s -1` is an obfuscated test for **`x == 0`** (and `<s 0` tests **`x != 0`**). In `0x4b70` (`0x140525211`), `mov rax, [rcx+0x20]; lea rcx, [rax + r15]; or rcx, rax; js bail` branches to fallback when `[rcx+0x20] != 0`. In `0x26ac` (`0x1405110bf`), `lea ecx, [rax + 0x7f]; or cl, al; js ...` performs the same 8-bit `al != 0` check.

---

## 9. Partial Devirtualization and Reconstructed Functions

### 9.1 How the Symbolic Lifter Works

Instead of writing static opcode lifters for 10 separate VMs and hundreds of duplicated handlers, we trace functions in `Unicorn` + `Triton`, lower the symbolic expressions to `LLVM` IR (`x86_64-pc-windows-msvc`), and compile verified functions into `.devirt`:

```text
+--------------------------------------------------------------------------------+
| 1. Trace in Unicorn + Triton                                                   |
|    - Mark entry RCX, RDX, R8, R9 as symbolic (arg1_rcx .. arg4_r9)             |
|    - Hook reads from .data globals, argument structs, and pool memory;         |
|      split uncovered byte ranges (16/8/4/2/1B) into LOAD(addr_ast) events      |
|    - Hook IAT stubs -> mark RAX as call_ret_k -> record CALL(...)              |
|    - Hook external writes -> record STORE(addr_ast, val_ast)                   |
|    - Record symbolic branches (JCC, stack/image table jumps, symbolic RIP)     |
+--------------------------------------------------------------------------------+
                                        |
                                        v
+--------------------------------------------------------------------------------+
| 2. Hoist Early Entry Checks                                                    |
|    - Walk events before the first memory write or state-changing API call      |
|    - Move checks that only depend on arguments/globals to the top of the       |
|      function; if a check fails at runtime, jump to the relocated prologue     |
+--------------------------------------------------------------------------------+
                                        |
                                        v
+--------------------------------------------------------------------------------+
| 3. Solve Alternate Branches with Z3                                            |
|    - Negate remaining branch conditions in Z3 (constraining MmIsAddressValid   |
|      to mapped kernel pointers)                                                |
|    - UNSAT -> dead VMProtect opaque branch, drop it                            |
|    - SAT   -> re-run with Z3's input values to trace the other side and join   |
|      both paths with br i1 in LLVM SSA IR                                      |
+--------------------------------------------------------------------------------+
                                        |
                                        v
+--------------------------------------------------------------------------------+
| 4. Compile with LLVM (-O3) and Compare in Unicorn                              |
|    - Lower Triton ASTs (including raw LXOR node 227, rotates, bswap, i128 XMM) |
|    - Run LLVM -O3 (instcombine, gvn, reassociate, simplifycfg, dce)            |
|    - Run the compiled bytes and the original function on 7 test inputs         |
|      (3 zeroed + 4 random buffers) and check RAX, RSP, writes, and API calls   |
+--------------------------------------------------------------------------------+
                                        |
                                        v
+--------------------------------------------------------------------------------+
| 5. Patch PE64 and Rebuild Import Table                                         |
|    - Write the 84 functions and fallback prologues into .devirt (R-X)          |
|    - Patch 5-byte jmp rel32 hooks at the original .text / .be0 entry points    |
|    - Build a 130-entry read-only .idata table, strip the dead 20,656-byte      |
|      signature overlay, fix PE CheckSum (0x52edbb), and re-test from disk      |
+--------------------------------------------------------------------------------+
```

### 9.2 Reconstructed Functions in `.devirt`

Disassembly from `.devirt` in the rebuilt `BEDaisy.sys` alongside C equivalents for nine functions:

#### 1. `GsDriverEntry` (`0x109cd`: `21,275` VM insns -> `9` stub insns / `29` total with cookie init)
```x86asm
0x1404eb600 (+0x4eb600):  4883ec28                sub      rsp, 0x28
0x1404eb604 (+0x4eb604):  48894c2430              mov      qword ptr [rsp + 0x30], rcx
0x1404eb609 (+0x4eb609):  4889542438              mov      qword ptr [rsp + 0x38], rdx
0x1404eb60e (+0x4eb60e):  e819eab2ff              call     0x14001a02c
0x1404eb613 (+0x4eb613):  488b542438              mov      rdx, qword ptr [rsp + 0x38]
0x1404eb618 (+0x4eb618):  488b4c2430              mov      rcx, qword ptr [rsp + 0x30]
0x1404eb61d (+0x4eb61d):  e8fe54b2ff              call     0x140010b20
0x1404eb622 (+0x4eb622):  4883c428                add      rsp, 0x28
0x1404eb626 (+0x4eb626):  c3                      ret
```
```c
NTSTATUS GsDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    __security_init_cookie();                 // 0x14001a02c (initializes 0x17120 & ~cookie at 0x17128)
    return DriverMain(DriverObject, RegistryPath); // 0x140010b20 (remains virtualized in .be0)
}
```

#### 2. `BeDispatchCreate` / `IRP_MJ_CREATE` (`0x2158`: `27,523` VM insns -> `11` native insns, `99.96%` reduction)
```x86asm
0x1404eb0b0 (+0x4eb0b0):  4883ec28                sub      rsp, 0x28
0x1404eb0b4 (+0x4eb0b4):  4889d1                  mov      rcx, rdx
0x1404eb0b7 (+0x4eb0b7):  48b87371014001000000    movabs   rax, 0x140017173
0x1404eb0c1 (+0x4eb0c1):  c60001                  mov      byte ptr [rax], 1
0x1404eb0c4 (+0x4eb0c4):  c7423000000000          mov      dword ptr [rdx + 0x30], 0
0x1404eb0cb (+0x4eb0cb):  48c7423800000000        mov      qword ptr [rdx + 0x38], 0
0x1404eb0d3 (+0x4eb0d3):  31d2                    xor      edx, edx
0x1404eb0d5 (+0x4eb0d5):  ff90f5010000            call     qword ptr [rax + 0x1f5]
0x1404eb0db (+0x4eb0db):  31c0                    xor      eax, eax
0x1404eb0dd (+0x4eb0dd):  4883c428                add      rsp, 0x28
0x1404eb0e1 (+0x4eb0e1):  c3                      ret
```
```c
NTSTATUS BeDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    g_DeviceOpened = 1;                       // *(uint8_t*)0x140017173 = 1
    Irp->IoStatus.Status = STATUS_SUCCESS;    // *(NTSTATUS*)((char*)Irp + 0x30) = 0
    Irp->IoStatus.Information = 0;            // *(ULONG_PTR*)((char*)Irp + 0x38) = 0
    IofCompleteRequest(Irp, IO_NO_INCREMENT); // *(0x140017173 + 0x1f5) == [0x140017368]
    return STATUS_SUCCESS;
}
```

#### 3. `BeDispatchClose` / `IRP_MJ_CLOSE` (`0x20b4`: `225,683` VM insns -> `29` native insns, `99.99%` reduction)
```x86asm
0x1404eba10 (+0x4eba10):  56                      push     rsi
0x1404eba11 (+0x4eba11):  57                      push     rdi
0x1404eba12 (+0x4eba12):  4883ec28                sub      rsp, 0x28
0x1404eba16 (+0x4eba16):  4889d6                  mov      rsi, rdx
0x1404eba19 (+0x4eba19):  48bfe071014001000000    movabs   rdi, 0x1400171e0
0x1404eba23 (+0x4eba23):  c6479300                mov      byte ptr [rdi - 0x6d], 0
0x1404eba27 (+0x4eba27):  4889f9                  mov      rcx, rdi
0x1404eba2a (+0x4eba2a):  31d2                    xor      edx, edx
0x1404eba2c (+0x4eba2c):  4531c0                  xor      r8d, r8d
0x1404eba2f (+0x4eba2f):  4531c9                  xor      r9d, r9d
0x1404eba32 (+0x4eba32):  ff9748010000            call     qword ptr [rdi + 0x148]
0x1404eba38 (+0x4eba38):  4889f9                  mov      rcx, rdi
0x1404eba3b (+0x4eba3b):  31d2                    xor      edx, edx
0x1404eba3d (+0x4eba3d):  4531c0                  xor      r8d, r8d
0x1404eba40 (+0x4eba40):  4531c9                  xor      r9d, r9d
0x1404eba43 (+0x4eba43):  ff9740010000            call     qword ptr [rdi + 0x140]
0x1404eba49 (+0x4eba49):  c6872807000001          mov      byte ptr [rdi + 0x728], 1
0x1404eba50 (+0x4eba50):  c7463000000000          mov      dword ptr [rsi + 0x30], 0
0x1404eba57 (+0x4eba57):  48c7463800000000        mov      qword ptr [rsi + 0x38], 0
0x1404eba5f (+0x4eba5f):  4889f1                  mov      rcx, rsi
0x1404eba62 (+0x4eba62):  31d2                    xor      edx, edx
0x1404eba64 (+0x4eba64):  4531c0                  xor      r8d, r8d
0x1404eba67 (+0x4eba67):  4531c9                  xor      r9d, r9d
0x1404eba6a (+0x4eba6a):  ff9788010000            call     qword ptr [rdi + 0x188]
0x1404eba70 (+0x4eba70):  31c0                    xor      eax, eax
0x1404eba72 (+0x4eba72):  4883c428                add      rsp, 0x28
0x1404eba76 (+0x4eba76):  5f                      pop      rdi
0x1404eba77 (+0x4eba77):  5e                      pop      rsi
0x1404eba78 (+0x4eba78):  c3                      ret
```
```c
NTSTATUS BeDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    g_DeviceOpened = 0;                                           // [0x1400171e0 - 0x6d] = [0x140017173] = 0
    KeWaitForSingleObject(&g_GlobalMutex, Executive, KernelMode, FALSE, NULL); // [0x17328]
    KeReleaseMutex(&g_GlobalMutex, FALSE);                        // [0x17320]
    g_CleanupFlag = 1;                                            // [0x1400171e0 + 0x728] = [0x140017908] = 1
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IofCompleteRequest(Irp, IO_NO_INCREMENT);                     // [0x17368]
    return STATUS_SUCCESS;
}
```

#### 4. `BeDispatchDeviceControl` Unopened Fast-Reject Path (`0x126e8`: `106,140` VM insns -> `10` native insns)
```x86asm
0x1404eb910 (+0x4eb910):  4883ec28                sub      rsp, 0x28
0x1404eb914 (+0x4eb914):  4889d1                  mov      rcx, rdx
0x1404eb917 (+0x4eb917):  48c7423800000000        mov      qword ptr [rdx + 0x38], 0
0x1404eb91f (+0x4eb91f):  c74230100000c0          mov      dword ptr [rdx + 0x30], 0xc0000010
0x1404eb926 (+0x4eb926):  48b86873014001000000    movabs   rax, 0x140017368
0x1404eb930 (+0x4eb930):  31d2                    xor      edx, edx
0x1404eb932 (+0x4eb932):  ff10                    call     qword ptr [rax]
0x1404eb934 (+0x4eb934):  b8100000c0              mov      eax, 0xc0000010
0x1404eb939 (+0x4eb939):  4883c428                add      rsp, 0x28
0x1404eb93d (+0x4eb93d):  c3                      ret
```
```c
// Fast-reject path when session state is inactive; active IOCTL dispatch remains in .be0 via guard bailout:
NTSTATUS BeDispatchDeviceControl_FastReject(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = 0xC0000010;        // STATUS_INVALID_DEVICE_REQUEST
    IofCompleteRequest(Irp, IO_NO_INCREMENT);
    return 0xC0000010;
}
```

#### 5. `BeDriverUnload` (`0x2180`: `363,317` VM insns -> `82` native insns, `99.98%` reduction)
```x86asm
0x1404ebdc0 (+0x4ebdc0):  56                      push     rsi
0x1404ebdc1 (+0x4ebdc1):  57                      push     rdi
0x1404ebdc2 (+0x4ebdc2):  4883ec28                sub      rsp, 0x28
0x1404ebdc6 (+0x4ebdc6):  4889ce                  mov      rsi, rcx
0x1404ebdc9 (+0x4ebdc9):  48bfe071014001000000    movabs   rdi, 0x1400171e0
0x1404ebdd3 (+0x4ebdd3):  b9b0bf1f70              mov      ecx, 0x701fbfb0
0x1404ebdd8 (+0x4ebdd8):  bac0bf1f70              mov      edx, 0x701fbfc0
0x1404ebddd (+0x4ebddd):  ff97f8000000            call     qword ptr [rdi + 0xf8]
0x1404ebde3 (+0x4ebde3):  4889f9                  mov      rcx, rdi
0x1404ebde6 (+0x4ebde6):  31d2                    xor      edx, edx
0x1404ebde8 (+0x4ebde8):  4531c0                  xor      r8d, r8d
0x1404ebdeb (+0x4ebdeb):  4531c9                  xor      r9d, r9d
0x1404ebdee (+0x4ebdee):  ff9748010000            call     qword ptr [rdi + 0x148]
0x1404ebdf4 (+0x4ebdf4):  4889f9                  mov      rcx, rdi
0x1404ebdf7 (+0x4ebdf7):  31d2                    xor      edx, edx
0x1404ebdf9 (+0x4ebdf9):  4531c0                  xor      r8d, r8d
0x1404ebdfc (+0x4ebdfc):  4531c9                  xor      r9d, r9d
0x1404ebdff (+0x4ebdff):  ff9740010000            call     qword ptr [rdi + 0x140]
0x1404ebe05 (+0x4ebe05):  488d8f74a9feff          lea      rcx, [rdi - 0x1568c]
0x1404ebe0c (+0x4ebe0c):  ba01000000              mov      edx, 1
0x1404ebe11 (+0x4ebe11):  4531c0                  xor      r8d, r8d
0x1404ebe14 (+0x4ebe14):  4531c9                  xor      r9d, r9d
0x1404ebe17 (+0x4ebe17):  ff9710020000            call     qword ptr [rdi + 0x210]
0x1404ebe1d (+0x4ebe1d):  4889f9                  mov      rcx, rdi
0x1404ebe20 (+0x4ebe20):  31d2                    xor      edx, edx
0x1404ebe22 (+0x4ebe22):  4531c0                  xor      r8d, r8d
0x1404ebe25 (+0x4ebe25):  4531c9                  xor      r9d, r9d
0x1404ebe28 (+0x4ebe28):  ff9748010000            call     qword ptr [rdi + 0x148]
0x1404ebe2e (+0x4ebe2e):  4889f9                  mov      rcx, rdi
0x1404ebe31 (+0x4ebe31):  31d2                    xor      edx, edx
0x1404ebe33 (+0x4ebe33):  4531c0                  xor      r8d, r8d
0x1404ebe36 (+0x4ebe36):  4531c9                  xor      r9d, r9d
0x1404ebe39 (+0x4ebe39):  ff9740010000            call     qword ptr [rdi + 0x140]
0x1404ebe3f (+0x4ebe3f):  488b8ff8060000          mov      rcx, qword ptr [rdi + 0x6f8]
0x1404ebe46 (+0x4ebe46):  31d2                    xor      edx, edx
0x1404ebe48 (+0x4ebe48):  4531c0                  xor      r8d, r8d
0x1404ebe4b (+0x4ebe4b):  4531c9                  xor      r9d, r9d
0x1404ebe4e (+0x4ebe4e):  ff97a0050000            call     qword ptr [rdi + 0x5a0]
0x1404ebe54 (+0x4ebe54):  488d8fc8acfeff          lea      rcx, [rdi - 0x15338]
0x1404ebe5b (+0x4ebe5b):  31d2                    xor      edx, edx
0x1404ebe5d (+0x4ebe5d):  4531c0                  xor      r8d, r8d
0x1404ebe60 (+0x4ebe60):  4531c9                  xor      r9d, r9d
0x1404ebe63 (+0x4ebe63):  ff9720020000            call     qword ptr [rdi + 0x220]
0x1404ebe69 (+0x4ebe69):  488d8f84bafeff          lea      rcx, [rdi - 0x1457c]
0x1404ebe70 (+0x4ebe70):  31d2                    xor      edx, edx
0x1404ebe72 (+0x4ebe72):  4531c0                  xor      r8d, r8d
0x1404ebe75 (+0x4ebe75):  4531c9                  xor      r9d, r9d
0x1404ebe78 (+0x4ebe78):  ff9730020000            call     qword ptr [rdi + 0x230]
0x1404ebe7e (+0x4ebe7e):  4889f9                  mov      rcx, rdi
0x1404ebe81 (+0x4ebe81):  31d2                    xor      edx, edx
0x1404ebe83 (+0x4ebe83):  4531c0                  xor      r8d, r8d
0x1404ebe86 (+0x4ebe86):  4531c9                  xor      r9d, r9d
0x1404ebe89 (+0x4ebe89):  ff9748010000            call     qword ptr [rdi + 0x148]
0x1404ebe8f (+0x4ebe8f):  4889f9                  mov      rcx, rdi
0x1404ebe92 (+0x4ebe92):  31d2                    xor      edx, edx
0x1404ebe94 (+0x4ebe94):  4531c0                  xor      r8d, r8d
0x1404ebe97 (+0x4ebe97):  4531c9                  xor      r9d, r9d
0x1404ebe9a (+0x4ebe9a):  ff9740010000            call     qword ptr [rdi + 0x140]
0x1404ebea0 (+0x4ebea0):  4889f9                  mov      rcx, rdi
0x1404ebea3 (+0x4ebea3):  31d2                    xor      edx, edx
0x1404ebea5 (+0x4ebea5):  4531c0                  xor      r8d, r8d
0x1404ebea8 (+0x4ebea8):  4531c9                  xor      r9d, r9d
0x1404ebeab (+0x4ebeab):  ff9748010000            call     qword ptr [rdi + 0x148]
0x1404ebeb1 (+0x4ebeb1):  4889f9                  mov      rcx, rdi
0x1404ebeb4 (+0x4ebeb4):  31d2                    xor      edx, edx
0x1404ebeb6 (+0x4ebeb6):  4531c0                  xor      r8d, r8d
0x1404ebeb9 (+0x4ebeb9):  4531c9                  xor      r9d, r9d
0x1404ebebc (+0x4ebebc):  ff9740010000            call     qword ptr [rdi + 0x140]
0x1404ebec2 (+0x4ebec2):  b9b0bf1f70              mov      ecx, 0x701fbfb0
0x1404ebec7 (+0x4ebec7):  31d2                    xor      edx, edx
0x1404ebec9 (+0x4ebec9):  4531c0                  xor      r8d, r8d
0x1404ebecc (+0x4ebecc):  4531c9                  xor      r9d, r9d
0x1404ebecf (+0x4ebecf):  ff97a8010000            call     qword ptr [rdi + 0x1a8]
0x1404ebed5 (+0x4ebed5):  488b4e08                mov      rcx, qword ptr [rsi + 8]
0x1404ebed9 (+0x4ebed9):  488b87a0010000          mov      rax, qword ptr [rdi + 0x1a0]
0x1404ebee0 (+0x4ebee0):  31d2                    xor      edx, edx
0x1404ebee2 (+0x4ebee2):  4531c0                  xor      r8d, r8d
0x1404ebee5 (+0x4ebee5):  4531c9                  xor      r9d, r9d
0x1404ebee8 (+0x4ebee8):  4883c428                add      rsp, 0x28
0x1404ebeec (+0x4ebeec):  5f                      pop      rdi
0x1404ebeed (+0x4ebeed):  5e                      pop      rsi
0x1404ebeee (+0x4ebeee):  48ffe0                  jmp      rax
```
Reconstructed teardown logic (`rdi = 0x1400171e0 = &g_GlobalMutex`, `rsi = DriverObject`):
```c
VOID BeDriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\BattlEye");    // [0x172d8]
    KeWaitForSingleObject(&g_GlobalMutex, 0, 0, 0, NULL);         // [0x17328]
    KeReleaseMutex(&g_GlobalMutex, FALSE);                        // [0x17320]
    PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)0x140001b54, TRUE); // [0x173f0] remove=TRUE
    KeWaitForSingleObject(&g_GlobalMutex, 0, 0, 0, NULL);
    KeReleaseMutex(&g_GlobalMutex, FALSE);
    FltUnregisterFilter(g_FilterHandle);                          // [0x17780], arg=[0x1400178d8]
    PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)0x140001ea8); // [0x17400]
    PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)0x140002c64);       // [0x17410]
    KeWaitForSingleObject(&g_GlobalMutex, 0, 0, 0, NULL);
    KeReleaseMutex(&g_GlobalMutex, FALSE);
    KeWaitForSingleObject(&g_GlobalMutex, 0, 0, 0, NULL);
    KeReleaseMutex(&g_GlobalMutex, FALSE);
    IoDeleteSymbolicLink(&symLink);                               // [0x17388]
    IoDeleteDevice(DriverObject->DeviceObject);                   // [0x17380] tail-call on [rsi + 0x08]
}
```

#### 6. `BeCreateProcessNotifyCallbackEx` (`0x1b54` / `0x4c458c`: `107 -> 49` insns, XMM 16-byte split + 4 hoisted guards)
```x86asm
0x140525000 (+0x525000):  4157                    push     r15
0x140525002 (+0x525002):  4156                    push     r14
0x140525004 (+0x525004):  56                      push     rsi
0x140525005 (+0x525005):  57                      push     rdi
0x140525006 (+0x525006):  53                      push     rbx
0x140525007 (+0x525007):  4883ec20                sub      rsp, 0x20
0x14052500b (+0x52500b):  48b84871014001000000    movabs   rax, 0x140017148
0x140525015 (+0x525015):  4d85c0                  test     r8, r8
0x140525018 (+0x525018):  0f84be000000            je       0x1405250dc
0x14052501e (+0x52501e):  80782f00                cmp      byte ptr [rax + 0x2f], 0
0x140525022 (+0x525022):  0f85b4000000            jne      0x1405250dc
0x140525028 (+0x525028):  83b8b8feffffff          cmp      dword ptr [rax - 0x148], -1
0x14052502f (+0x52502f):  0f85a7000000            jne      0x1405250dc
0x140525035 (+0x525035):  4883b8f800000000        cmp      qword ptr [rax + 0xf8], 0
0x14052503d (+0x52503d):  0f8599000000            jne      0x1405250dc
0x140525043 (+0x525043):  498b7018                mov      rsi, qword ptr [r8 + 0x18]
0x140525047 (+0x525047):  483b30                  cmp      rsi, qword ptr [rax]
0x14052504a (+0x52504a):  0f858c000000            jne      0x1405250dc
0x140525050 (+0x525050):  4889cf                  mov      rdi, rcx
0x140525053 (+0x525053):  4889d3                  mov      rbx, rdx
0x140525056 (+0x525056):  4d89c6                  mov      r14, r8
0x140525059 (+0x525059):  4989c7                  mov      r15, rax
0x14052505c (+0x52505c):  ff90d0020000            call     qword ptr [rax + 0x2d0]
0x140525062 (+0x525062):  4989bfb8070000          mov      qword ptr [r15 + 0x7b8], rdi
0x140525069 (+0x525069):  49891f                  mov      qword ptr [r15], rbx
0x14052506c (+0x52506c):  41c6472c01              mov      byte ptr [r15 + 0x2c], 1
0x140525071 (+0x525071):  4989bff8000000          mov      qword ptr [r15 + 0xf8], rdi
0x140525078 (+0x525078):  49895ff0                mov      qword ptr [r15 - 0x10], rbx
0x14052507c (+0x52507c):  0f57c0                  xorps    xmm0, xmm0
0x14052507f (+0x52507f):  498b4620                mov      rax, qword ptr [r14 + 0x20]
0x140525083 (+0x525083):  410f294718              movaps   xmmword ptr [r15 + 0x18], xmm0
0x140525088 (+0x525088):  49894710                mov      qword ptr [r15 + 0x10], rax
0x14052508c (+0x52508c):  49897708                mov      qword ptr [r15 + 8], rsi
0x140525090 (+0x525090):  41c6872a0e000000        mov      byte ptr [r15 + 0xe2a], 0
0x140525098 (+0x525098):  49c7473000000000        mov      qword ptr [r15 + 0x30], 0
0x1405250a0 (+0x5250a0):  410f2987880e0000        movaps   xmmword ptr [r15 + 0xe88], xmm0
0x1405250a8 (+0x5250a8):  49c7473800000000        mov      qword ptr [r15 + 0x38], 0
0x1405250b0 (+0x5250b0):  410f2987780e0000        movaps   xmmword ptr [r15 + 0xe78], xmm0
0x1405250b8 (+0x5250b8):  41c6472a00              mov      byte ptr [r15 + 0x2a], 0
0x1405250bd (+0x5250bd):  49c7870001000000000000  mov      qword ptr [r15 + 0x100], 0
0x1405250c8 (+0x5250c8):  41c6472d01              mov      byte ptr [r15 + 0x2d], 1
0x1405250cd (+0x5250cd):  4889f0                  mov      rax, rsi
0x1405250d0 (+0x5250d0):  4883c420                add      rsp, 0x20
0x1405250d4 (+0x5250d4):  5b                      pop      rbx
0x1405250d5 (+0x5250d5):  5f                      pop      rdi
0x1405250d6 (+0x5250d6):  5e                      pop      rsi
0x1405250d7 (+0x5250d7):  415e                    pop      r14
0x1405250d9 (+0x5250d9):  415f                    pop      r15
0x1405250db (+0x5250db):  c3                      ret
0x1405250dc (+0x5250dc):  480544d44a00            add      rax, 0x4ad444
0x1405250e2 (+0x5250e2):  4883c420                add      rsp, 0x20
0x1405250e6 (+0x5250e6):  5b                      pop      rbx
0x1405250e7 (+0x5250e7):  5f                      pop      rdi
0x1405250e8 (+0x5250e8):  5e                      pop      rsi
0x1405250e9 (+0x5250e9):  415e                    pop      r14
0x1405250eb (+0x5250eb):  415f                    pop      r15
0x1405250ed (+0x5250ed):  48ffe0                  jmp      rax
```
```c
VOID BeCreateProcessNotifyCallbackEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (CreateInfo == NULL) return BeCreateProcessNotify_Fallback(Process, ProcessId, CreateInfo);
    if (*(uint8_t*)0x140017177 != 0 || *(int32_t*)0x140017000 != -1 || *(uint64_t*)0x140017240 != 0)
        return BeCreateProcessNotify_Fallback(Process, ProcessId, CreateInfo);
    if (CreateInfo->FileOpenNameAvailable_or_ImageName != *(uint64_t*)0x140017148)
        return BeCreateProcessNotify_Fallback(Process, ProcessId, CreateInfo);

    PsGetCurrentThreadId(); // [0x140017418]
    *(PEPROCESS*)0x140017900 = Process;
    *(HANDLE*)0x140017148    = ProcessId;
    *(uint8_t*)0x140017174   = 1;
    *(PEPROCESS*)0x140017240 = Process;
    *(HANDLE*)0x140017138    = ProcessId;
    *(uint64_t*)0x140017158  = *(uint64_t*)((char*)CreateInfo + 0x20);
    *(uint64_t*)0x140017150  = *(uint64_t*)((char*)CreateInfo + 0x18);
    *(uint8_t*)0x140017175   = 1;
}
```

#### 7. `BeValidatePeImageDirectory` (`0xe3e4`: `1,085,955` VM insns -> `32` native insns, `99.997%` reduction)
```x86asm
0x1405115a0 (+0x5115a0):  56                      push     rsi
0x1405115a1 (+0x5115a1):  57                      push     rdi
0x1405115a2 (+0x5115a2):  53                      push     rbx
0x1405115a3 (+0x5115a3):  48beffffffffffffff7f    movabs   rsi, 0x7fffffffffffffff
0x1405115ad (+0x5115ad):  488d0431                lea      rax, [rcx + rsi]
0x1405115b1 (+0x5115b1):  4989c2                  mov      r10, rax
0x1405115b4 (+0x5115b4):  4909ca                  or       r10, rcx
0x1405115b7 (+0x5115b7):  7939                    jns      0x1405115f2
0x1405115b9 (+0x5115b9):  448b513c                mov      r10d, dword ptr [rcx + 0x3c]
0x1405115bd (+0x5115bd):  4d89d3                  mov      r11, r10
0x1405115c0 (+0x5115c0):  4901cb                  add      r11, rcx
0x1405115c3 (+0x5115c3):  41c1fa1f                sar      r10d, 0x1f
0x1405115c7 (+0x5115c7):  49c1e220                shl      r10, 0x20
0x1405115cb (+0x5115cb):  4b8d3c13                lea      rdi, [r11 + r10]
0x1405115cf (+0x5115cf):  4b8d5c1a18              lea      rbx, [r10 + r11 + 0x18]
0x1405115d4 (+0x5115d4):  488d743e18              lea      rsi, [rsi + rdi + 0x18]
0x1405115d9 (+0x5115d9):  4809de                  or       rsi, rbx
0x1405115dc (+0x5115dc):  7914                    jns      0x1405115f2
0x1405115de (+0x5115de):  438bb41a88000000        mov      esi, dword ptr [r10 + r11 + 0x88]
0x1405115e6 (+0x5115e6):  488d3c31                lea      rdi, [rcx + rsi]
0x1405115ea (+0x5115ea):  4801f0                  add      rax, rsi
0x1405115ed (+0x5115ed):  4809f8                  or       rax, rdi
0x1405115f0 (+0x5115f0):  7810                    js       0x140511602
0x1405115f2 (+0x5115f2):  48b800f3504001000000    movabs   rax, 0x14050f300
0x1405115fc (+0x5115fc):  5b                      pop      rbx
0x1405115fd (+0x5115fd):  5f                      pop      rdi
0x1405115fe (+0x5115fe):  5e                      pop      rsi
0x1405115ff (+0x5115ff):  48ffe0                  jmp      rax
0x140511602 (+0x511602):  438b841a8c000000        mov      eax, dword ptr [r10 + r11 + 0x8c]
0x14051160a (+0x51160a):  448d90ffffff7f          lea      r10d, [rax + 0x7fffffff]
0x140511611 (+0x511611):  4109c2                  or       r10d, eax
0x140511614 (+0x511614):  78dc                    js       0x1405115f2
0x140511616 (+0x511616):  31c0                    xor      eax, eax
0x140511618 (+0x511618):  5b                      pop      rbx
0x140511619 (+0x511619):  5f                      pop      rdi
0x14051161a (+0x51161a):  5e                      pop      rsi
0x14051161b (+0x51161b):  c3                      ret
```
```c
NTSTATUS BeValidatePeImageDirectory(uint8_t* ImageBase) {
    if (ImageBase == NULL) return Fallback_0xe3e4(ImageBase);
    int64_t lfanew = *(int32_t*)(ImageBase + 0x3C);               // IMAGE_DOS_HEADER.e_lfanew
    uint8_t* ntHdr = ImageBase + lfanew;
    if (ntHdr + 0x18 == NULL) return Fallback_0xe3e4(ImageBase);
    uint32_t dirRva  = *(uint32_t*)(ntHdr + 0x88);                // OptionalHeader.DataDirectory[0].VirtualAddress
    if (ImageBase + dirRva == NULL) return Fallback_0xe3e4(ImageBase);
    uint32_t dirSize = *(uint32_t*)(ntHdr + 0x8C);                // OptionalHeader.DataDirectory[0].Size
    if (dirSize == 0) return Fallback_0xe3e4(ImageBase);
    return 0;
}
```

#### 8. `BeQueryFileSystemObjectName` (`0x4b70`: `665,857` VM insns -> `52` native insns, `99.992%` reduction)
```x86asm
0x1405251e0 (+0x5251e0):  4157                    push     r15
0x1405251e2 (+0x5251e2):  4156                    push     r14
0x1405251e4 (+0x5251e4):  4154                    push     r12
0x1405251e6 (+0x5251e6):  56                      push     rsi
0x1405251e7 (+0x5251e7):  57                      push     rdi
0x1405251e8 (+0x5251e8):  53                      push     rbx
0x1405251e9 (+0x5251e9):  4883ec28                sub      rsp, 0x28
0x1405251ed (+0x5251ed):  4c89ce                  mov      rsi, r9
0x1405251f0 (+0x5251f0):  4c89c7                  mov      rdi, r8
0x1405251f3 (+0x5251f3):  4889d3                  mov      rbx, rdx
0x1405251f6 (+0x5251f6):  4989ce                  mov      r14, rcx
0x1405251f9 (+0x5251f9):  49bfffffffffffffff7f    movabs   r15, 0x7fffffffffffffff
0x140525203 (+0x525203):  49ba9873014001000000    movabs   r10, 0x140017398
0x14052520d (+0x52520d):  488b4120                mov      rax, qword ptr [rcx + 0x20]
0x140525211 (+0x525211):  4a8d0c38                lea      rcx, [rax + r15]
0x140525215 (+0x525215):  4809c1                  or       rcx, rax
0x140525218 (+0x525218):  7879                    js       0x140525293
0x14052521a (+0x52521a):  4c89f1                  mov      rcx, r14
0x14052521d (+0x52521d):  4889da                  mov      rdx, rbx
0x140525220 (+0x525220):  4989f8                  mov      r8, rdi
0x140525223 (+0x525223):  4989f1                  mov      r9, rsi
0x140525226 (+0x525226):  4d89d4                  mov      r12, r10
0x140525229 (+0x525229):  41ff12                  call     qword ptr [r10]
0x14052522c (+0x52522c):  4d89e2                  mov      r10, r12
0x14052522f (+0x52522f):  4901c7                  add      r15, rax
0x140525232 (+0x525232):  4909c7                  or       r15, rax
0x140525235 (+0x525235):  785c                    js       0x140525293
0x140525237 (+0x525237):  ba48bf1f70              mov      edx, 0x701fbf48
0x14052523c (+0x52523c):  41b880000000            mov      r8d, 0x80
0x140525242 (+0x525242):  41b9e8be1f70            mov      r9d, 0x701fbee8
0x140525248 (+0x525248):  4c89f1                  mov      rcx, r14
0x14052524b (+0x52524b):  41ff9424e0000000        call     qword ptr [r12 + 0xe0]
0x140525253 (+0x525253):  4d89e2                  mov      r10, r12
0x140525256 (+0x525256):  85c0                    test     eax, eax
0x140525258 (+0x525258):  7839                    js       0x140525293
0x14052525a (+0x52525a):  b948bf1f70              mov      ecx, 0x701fbf48
0x14052525f (+0x52525f):  baf0be1f70              mov      edx, 0x701fbef0
0x140525264 (+0x525264):  41b801000000            mov      r8d, 1
0x14052526a (+0x52526a):  41b9e8be1f70            mov      r9d, 0x701fbee8
0x140525270 (+0x525270):  41ff942488030000        call     qword ptr [r12 + 0x388]
0x140525278 (+0x525278):  4d89e2                  mov      r10, r12
0x14052527b (+0x52527b):  8d88ffffff7f            lea      ecx, [rax + 0x7fffffff]
0x140525281 (+0x525281):  09c1                    or       ecx, eax
0x140525283 (+0x525283):  780e                    js       0x140525293
0x140525285 (+0x525285):  4883c428                add      rsp, 0x28
0x140525289 (+0x525289):  5b                      pop      rbx
0x14052528a (+0x52528a):  5f                      pop      rdi
0x14052528b (+0x52528b):  5e                      pop      rsi
0x14052528c (+0x52528c):  415c                    pop      r12
0x14052528e (+0x52528e):  415e                    pop      r14
0x140525290 (+0x525290):  415f                    pop      r15
0x140525292 (+0x525292):  c3                      ret
0x140525293 (+0x525293):  4981c2688c5000          add      r10, 0x508c68
0x14052529a (+0x52529a):  4c89f1                  mov      rcx, r14
0x14052529d (+0x52529d):  4889da                  mov      rdx, rbx
0x1405252a0 (+0x5252a0):  4989f8                  mov      r8, rdi
0x1405252a3 (+0x5252a3):  4989f1                  mov      r9, rsi
0x1405252a6 (+0x5252a6):  4883c428                add      rsp, 0x28
0x1405252aa (+0x5252aa):  5b                      pop      rbx
0x1405252ab (+0x5252ab):  5f                      pop      rdi
0x1405252ac (+0x5252ac):  5e                      pop      rsi
0x1405252ad (+0x5252ad):  415c                    pop      r12
0x1405252af (+0x5252af):  415e                    pop      r14
0x1405252b1 (+0x5252b1):  415f                    pop      r15
0x1405252b3 (+0x5252b3):  49ffe2                  jmp      r10
```

#### 9. `BeCaptureStackWalkAndSignal` (`0xc2fc` / `0x4d6efe`: `25 -> 12` insns)
```x86asm
0x140527000 (+0x527000):  56                      push     rsi
0x140527001 (+0x527001):  57                      push     rdi
0x140527002 (+0x527002):  53                      push     rbx
0x140527003 (+0x527003):  4883ec20                sub      rsp, 0x20
0x140527007 (+0x527007):  4c89ce                  mov      rsi, r9
0x14052700a (+0x52700a):  498b39                  mov      rdi, qword ptr [r9]
0x14052700d (+0x52700d):  488d4f70                lea      rcx, [rdi + 0x70]
0x140527011 (+0x527011):  48bb1073014001000000    movabs   rbx, 0x140017310
0x14052701b (+0x52701b):  ba00010000              mov      edx, 0x100
0x140527020 (+0x527020):  4531c0                  xor      r8d, r8d
0x140527023 (+0x527023):  ff9340020000            call     qword ptr [rbx + 0x240]
0x140527029 (+0x527029):  898770080000            mov      dword ptr [rdi + 0x870], eax
0x14052702f (+0x52702f):  4883c758                add      rdi, 0x58
0x140527033 (+0x527033):  488b03                  mov      rax, qword ptr [rbx]
0x140527036 (+0x527036):  4889f9                  mov      rcx, rdi
0x140527039 (+0x527039):  31d2                    xor      edx, edx
0x14052703b (+0x52703b):  4531c0                  xor      r8d, r8d
0x14052703e (+0x52703e):  4989f1                  mov      r9, rsi
0x140527041 (+0x527041):  4883c420                add      rsp, 0x20
0x140527045 (+0x527045):  5b                      pop      rbx
0x140527046 (+0x527046):  5f                      pop      rdi
0x140527047 (+0x527047):  5e                      pop      rsi
0x140527048 (+0x527048):  48ffe0                  jmp      rax
```
```c
LONG BeCaptureStackWalkAndSignal(uint64_t a1, uint64_t a2, uint64_t a3, void** CtxPtr) {
    (void)a1; (void)a2; (void)a3;
    uint8_t* ctx = (uint8_t*)(*CtxPtr);
    ULONG frames = RtlWalkFrameChain((PVOID*)(ctx + 0x70), 0x100, 0); // [0x140017550]
    *(ULONG*)(ctx + 0x870) = frames;
    return KeSetEvent((PRKEVENT)(ctx + 0x58), IO_NO_INCREMENT, FALSE); // tail-call [0x140017310]
}
```

### 9.3 List of the `84` Patched Functions (Out of `224` PDATA Entries)

Below are the `84` functions compiled into `.devirt` (`0x4eb000..0x533000`). Functions with early entry checks jump back to their relocated original prologue if runtime state takes an untraced path. The remaining `140` PDATA entries (`41` virtualized, `87` mutated, and `12` untouched native `.text` functions) were not patched:

| # | Orig RVA | Sec | Original Protection | Reconstructed Name | `.devirt` RVA | Size | Orig Insns | New Insns | Reduction | Kernel APIs Called |
|---:|---|---|---|---|---|---:|---:|---:|---:|---|
| 1 | `0x1004` | `.text` | `VIRTUALIZED` | `sub_140001004` | `0x4eb000` | `26 B` | `49,846` | `5` | `99.99%` | `ExAllocatePool` |
| 2 | `0x1250` | `.text` | `VIRTUALIZED` | `sub_140001250` | `0x4eb020` | `6 B` | `68,726` | `2` | `100.00%` | `-` |
| 3 | `0x1350` | `.text` | `VIRTUALIZED` | `sub_140001350` | `0x4eb030` | `58 B` | `45,312` | `16` | `99.96%` | `KeWaitForSingleObject, KeReleaseMutex` |
| 4 | `0x141c` | `.text` | `VIRTUALIZED` | `sub_14000141c` | `0x4eb9c0` | `65 B` | `221,854` | `18` | `99.99%` | `MmGetSystemRoutineAddress` |
| 5 | `0x15fc` | `.text` | `MUTATED` | `sub_1400015fc` | `0x4ebaa0` | `111 B` | `92` | `26` | `71.74%` | `ZwQuerySystemInformation` |
| 6 | `0x1b54` | `.text` | `MUTATED` | `BeCreateProcessNotifyCallbackEx` | `0x525000` | `240 B` | `107` | `49` | `54.21%` | `PsGetCurrentProcessId` |
| 7 | `0x1ea8` | `.text` | `MUTATED` | `BeCreateThreadNotifyCallback` | `0x4eb650` | `31 B` | `36` | `4` | `88.89%` | `-` |
| 8 | `0x2064` | `.text` | `VIRTUALIZED` | `sub_140002064` | `0x4eb070` | `57 B` | `50,763` | `17` | `99.97%` | `KeWaitForSingleObject, KeReleaseMutex` |
| 9 | `0x20b4` | `.text` | `VIRTUALIZED` | `BeDispatchClose` | `0x4eba10` | `105 B` | `225,683` | `29` | `99.99%` | `KeWaitForSingleObject, KeReleaseMutex` |
| 10 | `0x2158` | `.text` | `VIRTUALIZED` | `BeDispatchCreate` | `0x4eb0b0` | `50 B` | `27,523` | `11` | `99.96%` | `IofCompleteRequest` |
| 11 | `0x2180` | `.text` | `VIRTUALIZED` | `BeDriverUnload` | `0x4ebdc0` | `305 B` | `363,317` | `82` | `99.98%` | `RtlInitUnicodeString` |
| 12 | `0x255c` | `.text` | `MUTATED` | `sub_14000255c` | `0x4eb0f0` | `3 B` | `31` | `2` | `93.55%` | `-` |
| 13 | `0x264c` | `.text` | `MUTATED` | `sub_14000264c` | `0x511000` | `95 B` | `85` | `15` | `82.35%` | `-` |
| 14 | `0x26ac` | `.text` | `VIRTUALIZED` | `BeProcessNotifyDispatchHelper` | `0x511060` | `301 B` | `67,791` | `34` | `99.95%` | `PsAcquireProcessExitSynchronization, PsReleaseProcessExitSynchronization` |
| 15 | `0x2734` | `.text` | `MUTATED` | `sub_140002734` | `0x4eb670` | `37 B` | `82` | `9` | `89.02%` | `-` |
| 16 | `0x2838` | `.text` | `MUTATED` | `sub_140002838` | `0x4ebb10` | `95 B` | `67` | `23` | `65.67%` | `FltGetRequestorProcess` |
| 17 | `0x2c64` | `.text` | `MUTATED` | `BeLoadImageNotifyCallback` | `0x4eb6a0` | `26 B` | `47` | `4` | `91.49%` | `KeWaitForSingleObject, ExAllocatePoolWithTag, KeReleaseMutex, PsGetCurrentProcessId` |
| 18 | `0x36a4` | `.text` | `VIRTUALIZED` | `BeInitAltitudeString` | `0x4eb100` | `114 B` | `86,172` | `30` | `99.97%` | `KeWaitForSingleObject, RtlInitUnicodeString, ObRegisterCallbacks` |
| 19 | `0x37c4` | `.text` | `VIRTUALIZED` | `BeDispatchRead` | `0x4eb180` | `35 B` | `51,686` | `9` | `99.98%` | `IofCompleteRequest` |
| 20 | `0x4b70` | `.text` | `VIRTUALIZED` | `BeQueryFileSystemObjectName` | `0x5251e0` | `214 B` | `665,857` | `52` | `99.99%` | `IoGetTopLevelIrp, ObQueryNameString` |
| 21 | `0x4e08` | `.text` | `VIRTUALIZED` | `sub_140004e08` | `0x4eb1b0` | `35 B` | `52,117` | `7` | `99.99%` | `ZwQuerySystemInformation` |
| 22 | `0x4f0c` | `.text` | `VIRTUALIZED` | `sub_140004f0c` | `0x4eb1e0` | `32 B` | `50,745` | `6` | `99.99%` | `ExAllocatePoolWithTag` |
| 23 | `0x5860` | `.text` | `VIRTUALIZED` | `BeDispatchWrite` | `0x4eb200` | `35 B` | `51,999` | `9` | `99.98%` | `IofCompleteRequest` |
| 24 | `0x5fd4` | `.text` | `NATIVE_TEXT_OR_INIT` | `sub_140005fd4` | `0x4ebb70` | `3 B` | `130,017` | `2` | `100.00%` | `-` |
| 25 | `0x6248` | `.text` | `VIRTUALIZED` | `sub_140006248` | `0x4ebd90` | `47 B` | `67,189` | `11` | `99.98%` | `__chkstk, MmGetSystemRoutineAddress` |
| 26 | `0xc2fc` | `.text` | `MUTATED` | `BeCaptureStackWalkAndSignal` | `0x527000` | `75 B` | `25` | `12` | `52.00%` | `RtlWalkFrameChain` |
| 27 | `0xcfd8` | `.text` | `VIRTUALIZED` | `sub_14000cfd8` | `0x4eb230` | `3 B` | `41,825` | `2` | `100.00%` | `-` |
| 28 | `0xd0ac` | `.text` | `VIRTUALIZED` | `sub_14000d0ac` | `0x4eb6c0` | `72 B` | `197,182` | `16` | `99.99%` | `-` |
| 29 | `0xd888` | `.text` | `VIRTUALIZED` | `sub_14000d888` | `0x4eb240` | `26 B` | `52,957` | `5` | `99.99%` | `ExAllocatePool` |
| 30 | `0xda98` | `.text` | `MUTATED` | `BeAddOffset10000` | `0x4eb630` | `4 B` | `67` | `3` | `95.52%` | `-` |
| 31 | `0xdb04` | `.text` | `MUTATED` | `sub_14000db04` | `0x4eb260` | `4 B` | `3,486` | `2` | `99.94%` | `-` |
| 32 | `0xdbf4` | `.text` | `VIRTUALIZED` | `sub_14000dbf4` | `0x4eb270` | `42 B` | `56,266` | `10` | `99.98%` | `ZwQuerySystemInformation` |
| 33 | `0xddec` | `.text` | `VIRTUALIZED` | `sub_14000ddec` | `0x4eb2a0` | `402 B` | `91,227` | `118` | `99.87%` | `MmGetSystemRoutineAddress, MmGetPhysicalAddress` |
| 34 | `0xdfdc` | `.text` | `VIRTUALIZED` | `sub_14000dfdc` | `0x511190` | `124 B` | `493,144` | `32` | `99.99%` | `-` |
| 35 | `0xe114` | `.text` | `VIRTUALIZED` | `sub_14000e114` | `0x4eb710` | `42 B` | `113,124` | `10` | `99.99%` | `ZwQuerySystemInformation` |
| 36 | `0xe3e4` | `.text` | `VIRTUALIZED` | `BeValidatePeImageDirectory` | `0x5115a0` | `124 B` | `1,085,955` | `32` | `100.00%` | `-` |
| 37 | `0xe6d8` | `.text` | `VIRTUALIZED` | `sub_14000e6d8` | `0x4eb740` | `42 B` | `124,296` | `10` | `99.99%` | `ZwQuerySystemInformation` |
| 38 | `0xeaa0` | `.text` | `VIRTUALIZED` | `sub_14000eaa0` | `0x4eb440` | `58 B` | `41,537` | `16` | `99.96%` | `KeWaitForSingleObject, KeReleaseMutex` |
| 39 | `0xeb00` | `.text` | `VIRTUALIZED` | `sub_14000eb00` | `0x4eb770` | `142 B` | `142,875` | `38` | `99.97%` | `RtlInitUnicodeString, ZwOpenDirectoryObject` |
| 40 | `0xf388` | `.text` | `VIRTUALIZED` | `sub_14000f388` | `0x4eb800` | `97 B` | `153,886` | `23` | `99.99%` | `MmIsAddressValid, KeWaitForSingleObject` |
| 41 | `0xf99c` | `.text` | `MUTATED` | `sub_14000f99c` | `0x511210` | `358 B` | `353` | `58` | `83.57%` | `-` |
| 42 | `0xfb20` | `.text` | `MUTATED` | `BeAddOffset40` | `0x4eb640` | `5 B` | `962` | `3` | `99.69%` | `-` |
| 43 | `0x1029c` | `.text` | `VIRTUALIZED` | `sub_14001029c` | `0x4eb480` | `6 B` | `53,616` | `2` | `100.00%` | `-` |
| 44 | `0x10764` | `.text` | `VIRTUALIZED` | `sub_140010764` | `0x4eb490` | `36 B` | `48,528` | `8` | `99.98%` | `ExAllocatePool` |
| 45 | `0x10920` | `.text` | `VIRTUALIZED` | `sub_140010920` | `0x4eb4c0` | `23 B` | `53,811` | `6` | `99.99%` | `RtlImageNtHeader` |
| 46 | `0x109c8` | `.text` | `MUTATED` | `sub_1400109c8` | `0x511380` | `55 B` | `42` | `15` | `64.29%` | `-` |
| 47 | `0x109cd` | `.text` | `VIRTUALIZED_INIT` | `GsDriverEntry` | `0x4eb600` | `39 B` | `21,275` | `29` | `99.86%` | `-` |
| 48 | `0x10b10` | `.text` | `VIRTUALIZED` | `sub_140010b10` | `0x4ebcd0` | `83 B` | `87,209` | `26` | `99.97%` | `RtlInitUnicodeString, ZwOpenSection` |
| 49 | `0x10bb8` | `.text` | `VIRTUALIZED` | `sub_140010bb8` | `0x4eb4e0` | `3 B` | `48,463` | `2` | `100.00%` | `-` |
| 50 | `0x10c70` | `.text` | `VIRTUALIZED` | `sub_140010c70` | `0x4eb4f0` | `3 B` | `45,555` | `2` | `100.00%` | `-` |
| 51 | `0x112d8` | `.text` | `VIRTUALIZED` | `sub_1400112d8` | `0x4eba80` | `23 B` | `394,701` | `4` | `100.00%` | `-` |
| 52 | `0x11444` | `.text` | `VIRTUALIZED` | `sub_140011444` | `0x4eb500` | `72 B` | `34,496` | `23` | `99.93%` | `RtlInitUnicodeString, MmGetSystemRoutineAddress` |
| 53 | `0x11468` | `.text` | `VIRTUALIZED` | `sub_140011468` | `0x4eb550` | `23 B` | `74,474` | `6` | `99.99%` | `MmIsAddressValid` |
| 54 | `0x11858` | `.text` | `VIRTUALIZED` | `sub_140011858` | `0x4ebb80` | `118 B` | `192,850` | `27` | `99.99%` | `-` |
| 55 | `0x1199c` | `.text` | `VIRTUALIZED` | `sub_14001199c` | `0x5113c0` | `107 B` | `74,634` | `32` | `99.96%` | `RtlInitUnicodeString, MmGetSystemRoutineAddress` |
| 56 | `0x11a04` | `.text` | `VIRTUALIZED` | `sub_140011a04` | `0x4eb570` | `62 B` | `76,287` | `16` | `99.98%` | `KeWaitForSingleObject` |
| 57 | `0x122b0` | `.text` | `VIRTUALIZED` | `sub_1400122b0` | `0x511430` | `124 B` | `113,306` | `32` | `99.97%` | `-` |
| 58 | `0x122fc` | `.text` | `VIRTUALIZED` | `sub_1400122fc` | `0x4eb870` | `148 B` | `141,480` | `37` | `99.97%` | `RtlInitUnicodeString, ZwOpenFile` |
| 59 | `0x1251c` | `.text` | `VIRTUALIZED` | `sub_14001251c` | `0x4ebd30` | `92 B` | `95,690` | `23` | `99.98%` | `RtlInitUnicodeString, ZwOpenFile` |
| 60 | `0x125f8` | `.text` | `VIRTUALIZED` | `sub_1400125f8` | `0x4eb5b0` | `45 B` | `46,049` | `10` | `99.98%` | `ZwOpenThread` |
| 61 | `0x126e8` | `.text` | `VIRTUALIZED` | `BeDispatchDeviceControl` | `0x4eb910` | `46 B` | `106,140` | `10` | `99.99%` | `-` |
| 62 | `0x13334` | `.text` | `VIRTUALIZED` | `sub_140013334` | `0x4eb940` | `11 B` | `134,286` | `2` | `100.00%` | `-` |
| 63 | `0x136ac` | `.text` | `MUTATED` | `sub_1400136ac` | `0x511620` | `89 B` | `14` | `22` | `expanded_ssa` | `MmIsAddressValid` |
| 64 | `0x13740` | `.text` | `MUTATED` | `sub_140013740` | `0x511680` | `89 B` | `19` | `22` | `expanded_ssa` | `MmIsAddressValid` |
| 65 | `0x137d4` | `.text` | `MUTATED` | `sub_1400137d4` | `0x5116e0` | `89 B` | `14` | `22` | `expanded_ssa` | `MmIsAddressValid` |
| 66 | `0x13864` | `.text` | `MUTATED` | `sub_140013864` | `0x511740` | `89 B` | `17` | `22` | `expanded_ssa` | `MmIsAddressValid` |
| 67 | `0x4c3bba` | `.be0` | `MUTATED` | `sub_1404c3bba` | `0x4ebc00` | `111 B` | `91` | `26` | `71.43%` | `ZwQuerySystemInformation, ExAllocatePoolWithTag, ExFreePoolWithTag, PsInitialSystemProcess` |
| 68 | `0x4c458c` | `.be0` | `MUTATED` | `BeCreateProcessNotifyCallbackEx_be0` | `0x5250f0` | `240 B` | `106` | `49` | `53.77%` | `PsGetCurrentProcessId` |
| 69 | `0x4c4b82` | `.be0` | `MUTATED` | `BeCreateThreadNotifyCallback_be0` | `0x4eb950` | `31 B` | `35` | `4` | `88.57%` | `PsGetThreadProcessId, PsLookupThreadByThreadId, PsThreadType, ObOpenObjectByPointer` |
| 70 | `0x4c5ce8` | `.be0` | `MUTATED` | `sub_1404c5ce8` | `0x4eb5e0` | `3 B` | `30` | `2` | `93.33%` | `IoFileObjectType, PsThreadType, PsGetThreadProcess` |
| 71 | `0x4c5e9e` | `.be0` | `MUTATED` | `sub_1404c5e9e` | `0x5114b0` | `95 B` | `84` | `15` | `82.14%` | `ExfUnblockPushLock` |
| 72 | `0x4c60f7` | `.be0` | `MUTATED` | `sub_1404c60f7` | `0x4eb970` | `37 B` | `81` | `9` | `88.89%` | `_wcsnicmp` |
| 73 | `0x4c62ef` | `.be0` | `MUTATED` | `sub_1404c62ef` | `0x4ebc70` | `95 B` | `66` | `23` | `65.15%` | `FltGetRequestorProcess, PsGetCurrentThreadId, FltReadFile, IoQueryFileDosDeviceName` |
| 74 | `0x4c6a94` | `.be0` | `MUTATED` | `BeLoadImageNotifyCallback_be0` | `0x4eb9a0` | `26 B` | `46` | `4` | `91.30%` | `KeWaitForSingleObject, ExAllocatePoolWithTag, KeReleaseMutex, PsGetCurrentProcessId` |
| 75 | `0x4d6efe` | `.be0` | `MUTATED` | `BeCaptureStackWalkAndSignal_be0` | `0x527050` | `75 B` | `24` | `12` | `50.00%` | `RtlWalkFrameChain, KeSetEvent` |
| 76 | `0x4d9a8c` | `.be0` | `MUTATED` | `sub_1404d9a8c` | `0x511510` | `69 B` | `66` | `22` | `66.67%` | `-` |
| 77 | `0x4d9b8f` | `.be0` | `MUTATED` | `sub_1404d9b8f` | `0x4eb5f0` | `4 B` | `765` | `2` | `99.74%` | `-` |
| 78 | `0x4df5f9` | `.be0` | `MUTATED` | `sub_1404df5f9` | `0x523000` | `2477 B` | `961` | `520` | `45.89%` | `MmIsAddressValid, KeWaitForSingleObject, RtlInitUnicodeString, RtlUnicodeStringToAnsiString` |
| 79 | `0x4e14f5` | `.be0` | `MUTATED` | `sub_1404e14f5` | `0x511560` | `55 B` | `41` | `15` | `63.41%` | `-` |
| 80 | `0x4e237c` | `.be0` | `MUTATED` | `sub_1404e237c` | `0x5117a0` | `6 B` | `2` | `2` | `expanded_ssa` | `-` |
| 81 | `0x4e7fa2` | `.be0` | `MUTATED` | `sub_1404e7fa2` | `0x5117b0` | `89 B` | `13` | `22` | `expanded_ssa` | `MmIsAddressValid, MmUnmapViewOfSection` |
| 82 | `0x4e80ca` | `.be0` | `MUTATED` | `sub_1404e80ca` | `0x511810` | `89 B` | `18` | `22` | `expanded_ssa` | `MmIsAddressValid, MmUnmapViewOfSection` |
| 83 | `0x4e81fb` | `.be0` | `MUTATED` | `sub_1404e81fb` | `0x511870` | `89 B` | `13` | `22` | `expanded_ssa` | `MmIsAddressValid, MmUnmapViewOfSection` |
| 84 | `0x4e8301` | `.be0` | `MUTATED` | `sub_1404e8301` | `0x5118d0` | `89 B` | `16` | `22` | `expanded_ssa` | `MmIsAddressValid, MmUnmapViewOfSection` |

---

## 10. Bugs Hit Along the Way and How We Fixed Them

1. **`__chkstk` RAX Clobber (`DriverEntry` crash at step `34,618`):**
   - *Bug:* Stubbing every `ntoskrnl.exe` import with `xor eax, eax; ret`.
   - *Cause:* On x64 Windows, `__chkstk` receives the frame size in `RAX` (`0x1b30` in `DriverMain` at step `31,514`) and leaves `RAX` intact. Zeroing `RAX` broke the following `sub rsp, rax` and sent execution to unmapped `0x201f3dc0` at step `34,618`.
   - *Fix:* Kept `RAX` unchanged in the `__chkstk` stub, which let `DriverMain` finish resolving all `124` imports.

2. **LIEF `.l1` `RWX` Section Flag and Leftover Authenticode Overlay:**
   - *Bug:* Running `lief.PE.Builder` with `build_imports(True)` directly.
   - *Cause:* LIEF emits its new import section `.l1` as `0xE0000020` (`RWX`), leaves the dead `20,656`-byte Authenticode signature at the end of the file, and leaves `CheckSum` stale (`0x4e717c`).
   - *Fix:* Cleared `IMAGE_DIRECTORY_ENTRY_SECURITY`, renamed `.l1` to `.idata` with `0x40000040` (`R--`), truncated the file at the end of the last section, and recomputed `OptionalHeader.CheckSum` (`0x52edbb`).

3. **Triton `op.getAddress() == 0` and Raw `LXOR_NODE` (`227`):**
   - *Bug:* Calling `op.getAddress()` right after `TritonContext.disassembly(inst)` and matching only Python `AST_NODE` enum names.
   - *Cause:* `disassembly()` leaves memory operand addresses at `0` until `processing()` runs. Triton's C++ simplifier also emits `LXOR_NODE` with integer ID `227` (missing from Python's `AST_NODE` enum), which crashed lifting on `0x26ac`.
   - *Fix:* Built effective addresses directly from `base + index*scale + disp` ASTs and added handlers for raw node `227`, `BVROL`/`BVROR`, `BSWAP`, `IFF`, n-ary `LAND`/`LOR`, and `16`-byte XMM stores.

4. **Canonical vs 52-Bit Masked `KUSER_SHARED_DATA`:**
   - *Bug:* Mapping `KUSER_SHARED_DATA` only at `0xFFFFF78000000000`.
   - *Cause:* Several VM handlers mask the top address bits (`0x000FF7800000026C`) when reading `KUSER_SHARED_DATA` and also read `gs:[0x188]` (`KPCR -> CurrentThread`).
   - *Fix:* Mapped `KUSER_SHARED_DATA` at both `0xFFFFF78000000000` and `0x000FF78000000000` and pointed `GS_BASE = 0x62000000` (`KPCR -> KTHREAD -> EPROCESS`).

5. **Overlapping 8-Byte and 16-Byte `movups` Symbolic Reads in `0x1b54`:**
   - *Bug:* Skipping symbolization whenever `ctx.isMemorySymbolized(MemoryAccess(addr, 16))` returned `True`.
   - *Cause:* In `0x1b54`, an earlier 8-byte read at `[r8 + 0x18]` marked `0x60020018..0x6002001f` symbolic. When `movups xmm0, [rsi + 0x18]` later read 16 bytes from the same address, `isMemorySymbolized` returned `True` because of the low 8 bytes and left `[r8 + 0x20..0x27]` hardcoded to `0`, breaking random-input tests when `CreateInfo` had non-zero upper fields.
   - *Fix:* Split external reads into uncovered `16, 8, 4, 2, 1`-byte chunks so `[r8 + 0x20]` got its own symbol.

6. **Address Collision Between `ObReferenceObjectByHandle` and `FAKE_PE` (`0x12494` Crash):**
   - *Bug:* Mapping a dummy `"MZ"` PE header at `0x61080000`.
   - *Cause:* `ObReferenceObjectByHandle` also wrote `0x61080000` as its output object pointer, so `0x12494` read `"MZ"` bytes as kernel object fields and jumped to an unmapped address (`0x4e621c: call rax`). Dropping `FAKE_PE` and returning callable stub `0x5000e000` from `MmGetSystemRoutineAddress` let `0x12494` finish cleanly in `329,857` steps.

7. **Pointer Setup Mismatch Between Tracer and Test Runner:**
   - *Bug:* Initializing 2-level pointers inside `0x60000000..0x6003FFFF` during tracing, then zeroing `0x60000000` during `Unicorn` comparison runs.
   - *Fix:* Used the same 1st- and 2nd-level pointer setup (`0x60000000 -> 0x60100000 -> 0x60180000`) in both the tracer and test runner while randomizing leaf data at `0x60180000`, which fixed `0xc2fc` and `0x4d6efe`.

8. **Z3 `MmIsAddressValid` Non-Canonical Pointer Model (`unmapped(0x31)`) & `ZwQuerySystemInformation` Offset (`0xc2010050`):**
   - *Cause:* On `0x135ec`, Z3 satisfied `MmIsAddressValid(rcx) != 0` with `rcx = 1` and `call_ret = 32`, crashing at `[1 + 0x30] = 0x31`. Constraining `call_ret != 0 => ptr in {0x60100000, 0x60180000, 0x61000000}` fixed `unmapped(0x31)`. On `0x138f0` / `0x4e8427`, writing `*rdx = 0x62020000` in `PsLookupProcessByProcessId` fixed `unmapped(0x558)` and showed `SYSTEM_PROCESS_INFORMATION->NextEntryOffset` reading `0x61010000` from `[0x61000000]` (`0x61000000 + 0x61010000 + 0x50 = 0xc2010050`).

---

## 11. Before vs. After Summary, Unpatched Functions, and Open Questions

### 11.1 Before vs. After Comparison (`BEDaisy.sys`)

Before and after binaries are available at:
[https://github.com/est1mate/est1mate.github.io/tree/main/battleye](https://github.com/est1mate/est1mate.github.io/tree/main/battleye)

| Metric | Before (Original `BEDaisy.sys`) | After (Partially Devirtualized `BEDaisy.sys`) |
|---|---|---|
| **File Size** | `5,148,848` bytes | `5,430,272` bytes (`.devirt` `288 KiB` added, `20,656 B` dead overlay removed) |
| **SHA-256** | `0de4ca95303c938bbe97494a22021cc3...` | `3a7b6b7ddfc0cf1ecd0a7563ad192ff97e9461786c763964cf1cc19d55057d13` |
| **PE OptionalHeader CheckSum** | `0x4ed4cc` (`valid = True`) | `0x52edbb` (`valid = True`) |
| **Static Imports** | `6` (`ntoskrnl.exe` `5`, `FLTMGR.SYS` `1`) | `130` (`ntoskrnl.exe` `121`, `FLTMGR.SYS` `9` in read-only `.idata`) |
| **Writable+Executable (`RWX`) Sections** | `0` | `0` (`[]`) |
| **Binary-Patched `.devirt` Functions** | `0 / 224` | **`84 / 224` (`37.5%` patched; `140 / 224` unpatched in `.be0`/`.text`)** |
| **Virtualized (`VMProtect 3.8+`) Functions** | `87` virtualized (`0` native) | **`46 / 87` (`52.9%`) lifted to native; `41 / 87` (`47.1%`) still virtualized** |
| **Mutated (`.be0` / `.text`) Functions** | `123` mutated | **`36 / 123` (`29.3%`) patched in `.devirt`; `87 / 123` unpatched (`123/123` jmp-folded)** |
| **Obfuscated Instructions (on the 84 patched paths)** | `6,721,725` executed insns | **`2,055` native x86-64 insns (`99.969%` reduction on lifted paths)** |
| **Runtime-Decrypted Strings** | `0` UTF-16LE visible statically | **`143` unique runtime strings (`130` APIs + `13` paths/targets/tags)** |

### 11.2 Why `41` Virtualized Functions Were Left Unpatched

The `41` virtualized functions still in `.be0` were skipped for three reasons:

#### 1. Unmodeled Kernel Struct Offsets (`21` Functions)
*(Note: `0xe3e4` and `0x4b70` from this initial fault list were later fixed and patched; the rest dereference deeper WDM struct pointers not set up in our Unicorn environment.)*

| # | RVA | VM Instance | Stop Status | Faulting RVA | Faulting Instruction | APIs Called Before Fault |
|---:|---|---|---|---|---|---|
| 1 | `0x10d8` | `0x43af94` | `unmapped(0x70)` | `0x44d148` | `mov rbx, qword ptr [rcx + riz]` | `-` |
| 2 | `0x3834` | `0x2f327d` | `unmapped(0x70)` | `0x44d148` | `mov rbx, qword ptr [rcx + riz]` | `ProbeForWrite, KeWaitForSingleObject, KeReleaseMutex` |
| 3 | `0x58d0` | `0x4258a8` | `unmapped(0x0)` | `0x3a431c` | `mov r10d, dword ptr [rax + rsi + 0x9a2f3be]` | `ProbeForRead` |
| 4 | `0x58e0` | `0x2ccb80` | `unmapped(0x0)` | `0x3a431c` | `mov r10d, dword ptr [rax + rsi + 0x9a2f3be]` | `ProbeForRead` |
| 5 | `0xc260` | `0x2ccb80` | `unmapped(0x3c)` | `0x4b9cba` | `mov ecx, dword ptr [rax + rsi*2 - 0x110]` | `-` |
| 6 | `0xcae8` | `0x4a163e` | `unmapped(0x0)` | `0x126cb` | `cmp byte ptr [rdx], 0x4c` | `RtlInitUnicodeString, ZwOpenFile, ZwCreateSection, ZwMapViewOfSection` |
| 7 | `0xf4d0` | `0x37dbff` | `unmapped(0x18)` | `0x48d870` | `mov rcx, qword ptr [rax + r8 - 0xd7da43e]` | `-` |
| 8 | `0xf7a8` | `0x2c91b5` | `unmapped(0x60200000)` | `0x14477` | `movaps xmmword ptr [rcx - 0x10], xmm0` | `-` |
| 9 | `0xfdf8` | `0x330e68` | `unmapped(0x3c3c3c3c3c48b)` | `0x492cf0` | `mov rdx, qword ptr [rbp + rax - 0x193c9c0a]` | `-` |
| 10 | `0x10a40` | `0x4a163e` | `unmapped(0x28)` | `0x46d7f7` | `mov r11, qword ptr [rcx + rdi*4 + 0x1b9ce90]` | `RtlInitUnicodeString, ZwOpenSection, ObReferenceObjectByHandle` |
| 11 | `0x10fa4` | `0x37dbff` | `unmapped(0xc0030000)` | `0x3d720b` | `movzx si, byte ptr [rdi + riz]` | `-` |
| 12 | `0x11734` | `0x37dbff` | `unmapped(0x30)` | `0x30c5db` | `mov dword ptr [rdi + rsi - 0xb20dccd], r10d` | `ZwAllocateVirtualMemory` |
| 13 | `0x121b4` | `0x2ccb80` | `unmapped(0x120023ffc)` | `0x32e08c` | `mov r9d, dword ptr [rbp + rax - 0x55ec78db]` | `-` |
| 14 | `0x12494` | `0x4258a8` | `unmapped(0x15)` | `0x309982` | `mov ecx, dword ptr [rax + r9 - 0x1bb000bc]` | `RtlInitUnicodeString, ZwOpenFile, ZwCreateSection, ZwMapViewOfSection, MmGetSystemRoutineAddress` |
| 15 | `0x12660` | `0x43af94` | `unmapped(0x15)` | `0x309982` | `mov ecx, dword ptr [rax + r9 - 0x1bb000bc]` | `RtlInitUnicodeString, ZwOpenFile, ZwCreateSection, ZwMapViewOfSection, MmGetSystemRoutineAddress` |
| 16 | `0x13034` | `0x4a163e` | `unmapped(0x15)` | `0x309982` | `mov ecx, dword ptr [rax + r9 - 0x1bb000bc]` | `RtlInitUnicodeString, ZwOpenFile, ZwCreateSection, ZwMapViewOfSection, MmGetSystemRoutineAddress` |
| 17 | `0x138f0` | `0x2c91b5` | `unmapped(0xfffffffffffeb)` | `0x4e8541` | `or byte ptr [rax - 0x15], 6` | `RtlInitUnicodeString, ZwOpenSection, ObReferenceObjectByHandle` |
| 18 | `0x4cbad7` | `0x2ccb80` | `unmapped(0x0)` | `0x3a431c` | `mov r10d, dword ptr [rax + rsi + 0x9a2f3be]` | `ProbeForRead` |
| 19 | `0x4d7e32` | `0x4a163e` | `unmapped(0x0)` | `0x126cb` | `cmp byte ptr [rdx], 0x4c` | `RtlInitUnicodeString, ZwOpenFile, ZwCreateSection, ZwMapViewOfSection` |
| 20 | `0x4e74e0` | `0x4a163e` | `unmapped(0x15)` | `0x309982` | `mov ecx, dword ptr [rax + r9 - 0x1bb000bc]` | `RtlInitUnicodeString, ZwOpenFile, ZwCreateSection, ZwMapViewOfSection, MmGetSystemRoutineAddress` |
| 21 | `0x4e8427` | `0x2c91b5` | `unmapped(0xfffffffffffeb)` | `0x4e8541` | `or byte ptr [rax - 0x15], 6` | `RtlInitUnicodeString, ZwOpenSection, ObReferenceObjectByHandle` |

#### 2. Long Loops Over Kernel Lists and Sections (`18` Functions)
*(Note: `0xe3e4` at `1.08M` steps was later lifted; the rest loop over module lists, handle tables, or mapped sections past the trace step budget.)*

| # | RVA | VM Instance | `VIP` | Executed Steps | Unique `VIP`s | Top `VIP` Loop Back-Edges | APIs Called |
|---:|---|---|---:|---:|---:|---|---|
| 1 | `0x502c` | `0x43af94` | `r8` | `1,412,468` | `2596` | `0x2c9d33->0x30a183` (30x), `0x3804fa->0x3b1ea7` (27x) | `ExAllocatePool, MmGetSystemRoutineAddress, ExAllocatePoolWithTag, RtlInitUnicodeString, ZwOpenFile, ZwCreateSection, ZwMapViewOfSection` |
| 2 | `0x6024` | `0x37dbff` | `r9` | `2,000,000` | `1321` | `0x3bea1->0x121749` (31x), `0x3bcfc->0x3bdcd` (28x) | `-` |
| 3 | `0x60e4` | `0x2f327d` | `r9` | `2,000,000` | `771` | `0x36b202->0x3c86b` (45x), `0x3f718d->0x36b202` (42x) | `-` |
| 4 | `0x61bc` | `0x2c91b5` | `rsi` | `2,000,000` | `735` | `0x4201d3->0x20fa24` (13x), `0x4201d3->0x20fa28` (12x) | `-` |
| 5 | `0xd014` | `0x2f327d` | `r9` | `77,996` | `870` | `0x305fdf->0x2ddab5` (2x), `0x2ddab5->0x2d964f` (2x) | `KeWaitForSingleObject, KeReleaseMutex` |
| 6 | `0xe3e4` | `0x37dbff` | `r9` | `1,085,956` | `3609` | `0x2c91e0->0x331830` (24x), `0x331830->0x3e2da` (23x) | `-` |
| 7 | `0xf5fc` | `0x37dbff` | `r9` | `956,128` | `1497` | `0x2d19a6->0x358a18` (60x), `0x3ea9a2->0x49c20f` (59x) | `CmUnRegisterCallback, MmIsAddressValid` |
| 8 | `0xf6dc` | `0x2c91b5` | `rsi` | `2,000,000` | `1273` | `0x193624->0x1c943` (33x), `0x1c943->0x1ca10` (26x) | `MmGetSystemRoutineAddress` |
| 9 | `0xf8d4` | `0x37dbff` | `r9` | `941,376` | `1162` | `0x2d19a6->0x358a18` (60x), `0x3ea9a2->0x49c20f` (59x) | `CmUnRegisterCallback, MmIsAddressValid` |
| 10 | `0xfcfc` | `0x2d1cfa` | `rdi` | `977,504` | `683` | `0x3baa2d->0x303e31` (60x), `0x3d08d1->0x2e7029` (44x) | `MmGetSystemRoutineAddress` |
| 11 | `0x10d24` | `0x43af94` | `r8` | `1,715,584` | `2110` | `0x3804fa->0x3b1ea7` (60x), `0x3b1ea7->0x320340` (59x) | `-` |
| 12 | `0x10dd8` | `0x2c91b5` | `rsi` | `52,816` | `728` | `0x207ac4->0x2079ef` (1x), `0x207926->0x1af847` (1x) | `-` |
| 13 | `0x10ecc` | `0x330e68` | `r9` | `2,000,000` | `3240` | `0x2ddab5->0x2d964f` (40x), `0x49c20f->0x32afa5` (40x) | `-` |
| 14 | `0x11b40` | `0x4a163e` | `rbp` | `1,016,189` | `2205` | `0x3e3ab0->0x319322` (9x), `0x40e2b6->0x347dc1` (8x) | `RtlInitUnicodeString, ZwOpenFile, ObReferenceObjectByHandle, KeStackAttachProcess, ObOpenObjectByPointer, PsGetProcessId, ObfDereferenceObject, ZwClose, MmIsAddressValid, KeUnstackDetachProcess` |
| 15 | `0x4c357c` | `0x2f327d` | `r9` | `32,962` | `755` | `0x30ccb->0x30d98` (1x), `0x30e69->0xaff98` (1x) | `KeWaitForSingleObject, KeReleaseMutex` |
| 16 | `0x4c4ed0` | `0x4a163e` | `rbp` | `36,881` | `318` | `0x8af51->0x8b024` (1x) | `KeReleaseMutex` |
| 17 | `0x4dcebe` | `0x4258a8` | `r11` | `28,227` | `391` | `0x1c7fab->0x1c7ed8` (1x), `0x1c7e08->0xbbe82` (1x) | `KeWaitForSingleObject, KeReleaseMutex` |
| 18 | `0x4e5d70` | `0x2ccb80` | `rsi` | `93,660` | `455` | `0x21d599->0x213bbe` (1x), `0x213bbe->0x36c5b9` (1x) | `-` |

#### 3. Indirect Calls Through Zeroed Runtime Pointers (`6` Functions)
- `0xd014` (VM `0x2f327d`): jumps via `0x1404d8725: pop rax; jmp qword ptr [0x140017e88]` (`[0x17e88] == 0` outside an active session).
- `0x10dd8` (VM `0x2c91b5`): executes `call qword ptr [rsp + 0x50]` with a zeroed callback slot.
- `0x4c357c` (VM `0x2f327d`), `0x4c4ed0` (VM `0x4a163e`), `0x4dcebe` (VM `0x4258a8`), `0x4e5d70` (VM `0x2ccb80`): jump through state pointers that are still zero at boot.

### 11.3 Open Points

1. **Partial coverage and fallback paths:** Only `84 / 224` functions (`46 / 87` virtualized) are patched into `.devirt`, and functions with entry checks jump back into `.be0` when runtime state takes an untraced branch (for instance, `BeDispatchDeviceControl` `0x126e8` only lifts the unopened fast-reject path, leaving active IOCTL handling inside `.be0`).
2. **Target of `.data` pointer `0x140017e88` (`0xd014`):** Referenced at `0x1404d8725`, never written during `DriverEntry` (`800,000` steps) or standalone `250,000`-step runs (`unverified`).
3. **Unreached `.be0` handlers and booted Windows 11 testing:** Handler copies in `.be0` that never ran dynamically were not disassembled (`unverified`), and all comparison runs were done in `Unicorn` rather than inside a booted Windows 11 kernel VM (`unverified`).
