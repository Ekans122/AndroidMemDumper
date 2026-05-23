# Android ARM64 Memory Dump → Ghidra Analysis Guide

Target:
- Android ARM64
- libncgp.so (com.ncsoft.lineagew)
- memdumper64
- Ghidra

---

## Step 1: Get PID

```bat
adb shell pidof com.ncsoft.lineagew
```

Or:

```bat
adb shell ps -A | findstr lineagew
```

Example:

```text
27914
```

---

## Step 2: Check Memory Map

```bat
adb shell su -c "cat /proc/27914/maps | grep libncgp.so"
```

Values to record:

```text
Base = start address of first r-xp entry
End  = end address of last rw-p entry
```

Example output:

```text
6cd42d7000-6cd48bf000 r-xp ...  <- code (multiple r-xp lines)
6cd48c2000-6cd4925000 r--p ...  <- rodata
6cd4928000-6cd492b000 rw-p ...  <- data
```

Record:

```text
Base = 0x6cd42d7000
End  = 0x6cd492b000
```

Multiple r-xp VMAs are normal. The kernel splits them due to repeated mprotect calls during initialization. The underlying data is contiguous.

---

## Step 3: Upload memdumper64

```bat
adb push libs\arm64-v8a\memdumper64 /data/local/tmp/memdumper64
adb shell su -c "chmod 755 /data/local/tmp/memdumper64"
```

Verify:

```bat
adb shell su -c "/data/local/tmp/memdumper64 -h"
```

---

## Step 4: Dump

```bat
adb shell su -c "/data/local/tmp/memdumper64 -i 27914 -l -n libncgp.so -o /sdcard"
```

Expected output:

```text
Base Address of libncgp.so Found At 6cd42d7000
End Address of libncgp.so Found At 6cd492b000
Lib Size: 6635520
Rebuilding Elf(So)
fixed so has write to /sdcard/libncgp.so
Rebuilding Complete
```

Warnings you can ignore:

```text
warning load size [69596088] is bigger than so size [6635520]
  -> PT_LOAD p_memsz is inflated for anti-analysis. Dump is complete.

warning DT_HASH not found, try to detect dynsym size...
  -> DT_HASH was stripped. No effect on dump quality.
```

---

## Step 5: Pull to PC

```bat
adb pull /sdcard/libncgp.so .
```

Check size:

```powershell
(Get-Item .\libncgp.so).Length
```

Expected: `6636686`

---

## Step 6: Verify ELF Header

```powershell
Format-Hex .\libncgp.so | Select-Object -First 2
```

Valid:

```text
00000000  7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00   ELF.....
00000010  03 00 B7 00 01 00 00 00 ...
          ^     ^
          ET_DYN  AArch64
```

Invalid (e_type or e_machine is 0x00):

```text
00000010  00 00 00 00 ...  <- needs Step 7 fix
```

The current libncgp.so header is valid — Step 7 can be skipped.

---

## Step 7: Fix ELF Header (only if invalid)

```powershell
$b = [System.IO.File]::ReadAllBytes(".\libncgp.so")

# ET_DYN
$b[0x10] = 0x03; $b[0x11] = 0x00
# AArch64
$b[0x12] = 0xB7; $b[0x13] = 0x00
# Clear e_entry
for ($i = 0x18; $i -lt 0x20; $i++) { $b[$i] = 0 }

[System.IO.File]::WriteAllBytes(".\libncgp_fixed.so", $b)
```

---

## Step 8: Import into Ghidra

Menu:

```text
File -> Import File
```

File: `libncgp.so`
(Use `libncgp_fixed.so` if Step 7 was performed.)

Settings:

```text
Format   : ELF
Language : AARCH64:LE:64:v8A
Compiler : default
```

Click Options -> Image Base:

```text
6cd42d7000
```

When prompted to Auto Analyze after import -> click **No** (do Step 9 first).

---

## Step 9: Fix Memory Map

Menu:

```text
Window -> Memory Map
```

### Enable Execute on code region

Code range from maps:

```text
Start = 0x6cd42d7000
End   = 0x6cd48bf000
```

Select the segment(s) covering this range and check the Execute (X) column.

If the segment is missing, add it with the "+" button:

```text
Name          : .text
Start Address : 6cd42d7000
Length        : 5e8000
Read          : checked
Write         : unchecked
Execute       : checked
File Bytes    : checked
File Offset   : 0
```

### Target segment layout

| Name    | Start         | Length   | R | W | X |
|---------|---------------|----------|---|---|---|
| .text   | 6cd42d7000    | 5e8000   | Y |   | Y |
| .rodata | 6cd48c2000    | 63000    | Y |   |   |
| .data   | 6cd4928000    | 3000     | Y | Y |   |

---

## Step 10: Auto Analyze

Menu:

```text
Analysis -> Auto Analyze
```

Enable:

```text
[x] ASCII Strings
[x] Data Reference
[x] Reference
[x] Subroutine References
[x] Function Start Search
[x] Function Start Search After Code
[x] Basic Constant Reference Analyzer
```

Disable:

```text
[ ] Stack
[ ] Function ID
[ ] Create Address Tables
[ ] Decompiler Parameter ID
[ ] Decompiler Switch Analysis
```

Click Analyze and wait.

---

## Step 11: Find Functions

Common AArch64 function prologue:

```asm
stp x29, x30, [sp, #-??]!
mov x29, sp
```

Byte pattern:

```text
FD 7B ?? A9  FD 03 00 91
```

Search:

```text
Search -> Memory -> FD 7B BF A9
```

Key bindings:

```text
G   : Go to address
D   : Disassemble
F   : Create function
F4  : Open Decompiler
```

---

## Step 12: Address Conversion

Runtime base: `0x6cd42d7000`

```text
Runtime VA  = Ghidra address  (Image Base is set to runtime base, so they match directly)
RVA         = Ghidra address - 0x6cd42d7000
```

Example:

```text
Frida/logcat address : 0x6cd7b719c0
Ghidra Go-to         : G -> 0x6cd7b719c0
RVA                  : 0x6cd7b719c0 - 0x6cd42d7000 = 0x343a9c0
```

---

## Note A: No strings visible

Cause: OLLVM string obfuscation.
Strings are never stored as plaintext in the binary.
They are assembled at runtime via arithmetic operations.

Capture at runtime with Frida:

```javascript
// frida -U -p 27914 -l strings.js

Interceptor.attach(Module.getExportByName(null, "strcmp"), {
    onEnter(args) {
        try {
            const a = args[0].readUtf8String();
            const b = args[1].readUtf8String();
            if (a && a.length > 3) console.log(`strcmp: "${a}" | "${b}"`);
        } catch (_) {}
    }
});
```

---

## Note B: libncgp.so map structure

```text
Why r-xp is split into 40+ VMAs:
  JNI_OnLoad repeatedly calls mprotect(rwx -> rx) per region during decryption.
  The kernel records each permission change as a separate VMA.
  This is a side effect of anti-tamper; data is contiguous and dump is unaffected.

Two 0x3000 VA gaps:
  6cd48bf000 ~ 6cd48c2000  (between r-xp and r--p)
  6cd4925000 ~ 6cd4928000  (between r--p and rw-p)
  These are ELF page-alignment gaps. No effect on file data.

No anonymous mappings:
  No separate runtime decryption buffer.
  String encryption is OLLVM-style (computed inline, not stored).
```
