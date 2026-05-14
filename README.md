# Blitz Crank

> **Strictly for educational and research purposes.**
> This repository documents the reverse engineering of an Electron desktop application's integrity verification system, the techniques used to analyse a native Node.js addon binary, and the strategies used to patch it. No copyrighted source code or proprietary binaries from the target application are included.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Application Architecture](#2-application-architecture)
3. [The Integrity System — How It Works](#3-the-integrity-system--how-it-works)
4. [Error Taxonomy (E1–E6)](#4-error-taxonomy-e1e6)
5. [Reverse Engineering the Native Module](#5-reverse-engineering-the-native-module)
6. [Patch 1 — Binary Patch of `blitz_core.node`](#6-patch-1--binary-patch-of-blitz_corenode)
7. [Patch 2 — ASAR Extraction, JS Modification, and Repacking](#7-patch-2--asar-extraction-js-modification-and-repacking)
   - [auth.js — Fake Premium User](#authjs--fake-premium-user)
   - [autoUpdater/index.js — Disable Auto-Updates](#autoupdaterindexjs--disable-auto-updates)
   - [crashReporter.js — Disable Telemetry](#crashreporterjs--disable-telemetry)
   - [ota.js — Disable OTA Updater](#otajs--disable-ota-updater)
   - [electronWindowHandlers.js — Network-Level Ad Block](#electronwindowhandlersjs--network-level-ad-block)
   - [createWindow.js — Premium Window Size](#createwindowjs--premium-window-size)
   - [blitz-entry.js — Disable Privacy Sandbox](#blitz-entryjs--disable-privacy-sandbox)
8. [Patch 3 — `.env.production`](#8-patch-3--envproduction)
9. [Patch 4 — `app-update.yml`](#9-patch-4--app-updateyml)
10. [ASAR Repacking — Why `--unpack` Matters](#10-asar-repacking--why---unpack-matters)
11. [Tools Used](#11-tools-used)
12. [Usage](#12-usage)
13. [Restore](#13-restore)
14. [Disclaimer](#14-disclaimer)

---

## 1. Overview

**Blitz** is an Electron desktop application (LoL/Valorant companion) built on:
- An Electron shell (`Blitz.exe`) loading a remote React web app via a `BrowserView`
- A local Node.js ASAR (`app.asar`) containing the main process JavaScript
- A native C++ Node.js addon (`blitz_core.node`) handling game integration, crash reporting, and **integrity verification**

This project documents a complete patch pipeline that:
1. Neutralises the native module's integrity checking loop via a **PE binary patch**
2. Modifies the Electron main-process JavaScript via **ASAR extraction and repacking**
3. Strips telemetry configuration from environment files

---

## 2. Application Architecture

```
C:\Users\<user>\AppData\Local\Programs\Blitz\
├── Blitz.exe                  ← Electron shell (Chromium + Node.js)
├── icudtl.dat                 ← ICU i18n data (verified by blitz_core.node)
└── resources\
    ├── app.asar               ← Main process JS (archived with Electron ASAR)
    ├── app.asar.unpacked\     ← Native addons that cannot live inside ASAR
    │   └── node_modules\
    │       ├── classic-level\ ← LevelDB binding (used for local app DB)
    │       └── lzma-native\   ← LZMA compression (used for update delta patches)
    ├── binaries\
    │   └── blitz_core.node    ← Native C++ addon (812 KB PE/COFF DLL)
    ├── .env.production        ← Environment config (Sentry DSNs, API keys)
    └── app-update.yml         ← electron-updater feed config

C:\Users\<user>\AppData\Roaming\Blitz\
├── blitz-deps\{version}\      ← Runtime copy of binaries\ (copied on startup)
│   └── blitz_core.node        ← The file actually loaded at runtime
├── appdb\                     ← LevelDB database (window state, auth token, etc.)
├── app.log                    ← Main process log
└── crash.log                  ← Native crash handler log
```

**Key architectural detail:** On every startup, `blitz-entry.js` calls `copyDeps()`, which copies the entire `resources/binaries/` directory to `%APPDATA%\Blitz\blitz-deps\{appVersion}\`. This means:
- The *source* of truth for the binary is `resources/binaries/blitz_core.node`
- The *runtime* binary actually loaded is `blitz-deps/{version}/blitz_core.node`
- **Both must be patched** to ensure the patch survives restarts

---

## 3. The Integrity System — How It Works

The native addon `blitz_core.node` is a **Win32 PE DLL** loaded by the Electron main process via Node.js's `require()`. Once initialised, it spawns an internal thread that runs a continuous verification loop inside the function we identified as `FUN_1800161c0`.

The loop performs these checks on a timer:

| Check | Mechanism | Purpose |
|-------|-----------|---------|
| Debugger detection | `IsDebuggerPresent()` + PEB `BeingDebugged` flag + `NtQueryInformationProcess(ProcessDebugPort)` | Detect attached debuggers |
| Remote debugger | `CheckRemoteDebuggerPresent()` | Detect remote debuggers |
| Timing check | Compare `QueryPerformanceCounter` deltas | Detect single-stepping (breakpoints slow execution) |
| CRC32 of `icudtl.dat` | Read entire file, compute CRC32 | Detect tampering with ICU data |
| Path verification | Check process path matches expected install location | Detect execution from wrong directory |
| ASAR integrity | CRC32 / hash of `app.asar` | Detect ASAR modification |

If any check fails, the function writes an error code (E1–E6) to the crash log and triggers process termination.

**Why is `blitz_core.node` the gatekeeper?** Because it's a compiled native binary — unlike the JavaScript in `app.asar`, it cannot be modified by simply unpacking an archive. The JavaScript has no way to override what the native code does once it's loaded.

---

## 4. Error Taxonomy (E1–E6)

These error codes appear verbatim in `crash.log` and were found as literal strings in `blitz_core.node` using Ghidra's string analysis:

| Code | Trigger condition |
|------|-------------------|
| `PRE E1` | Integrity loop not yet initialised (startup guard) |
| `E1 Error` | `IsDebuggerPresent()` returned non-zero |
| `E2 Error` | PEB `NtGlobalFlag` indicates debugger present |
| `E3 Error` | `NtQueryInformationProcess(ProcessDebugPort)` ≠ 0 |
| `E4 Error` | Timing anomaly detected (execution too slow = breakpoint) |
| `E5 Error` | Process path check failed |
| `E6 Error` | **CRC32 mismatch on `icudtl.dat`** (or ASAR hash mismatch) |

The `E6 Error` was the one triggered when `app.asar` was modified — the native module hashes the asar file and compares it to an expected value embedded in the binary. Any byte-level change to the asar, including adding a single trailing null byte, triggers E6.

---

## 5. Reverse Engineering the Native Module

### Toolchain

- **Ghidra 12.1** (NSA's open-source reverse engineering suite)
- Custom headless analysis script (`ExportForAI.java`) to batch-export decompiled C, cross-references, strings, and symbol tables to plain text

### Ghidra Headless Analysis

```batch
analyzeHeadless <project_dir> BlitzProject \
  -import blitz_core.node \
  -postScript ExportForAI.java \
  -processor x86:LE:64:default \
  -cspec windows
```

The `ExportForAI.java` script exported:
- `decompiled_all.c` — All 2,670 decompiled functions
- `strings.txt` — All string literals (where E1–E6 were found)
- `exports.txt` — Exported N-API symbols
- `xrefs.txt` — Cross-reference map

### Finding the Integrity Loop

String search for `"E6 Error"` in `strings.txt` produced the virtual address `0x180095430`. Cross-referencing this address (via Ghidra's xrefs) led to the function `FUN_1800161c0`, which contained all six error strings and the verification logic.

### Key Addresses

| Symbol | Virtual Address | Purpose |
|--------|----------------|---------|
| `FUN_1800161c0` | `0x1800161C0` | Main integrity verification loop |
| `DAT_1800bf8ac` | `0x1800BF8AC` | "Verified" flag byte (1 = passed) |
| `IMAGE_BASE` | `0x180000000` | PE preferred load address |

The decompiled pseudocode (simplified) for `FUN_1800161c0`:

```c
void FUN_1800161c0(void) {
    // Anti-debug checks
    if (IsDebuggerPresent()) { write_crash("E1 Error."); terminate(); }
    if (peb->NtGlobalFlag & 0x70) { write_crash("E2 Error."); terminate(); }
    if (NtQueryInformationProcess(..., ProcessDebugPort, ...) != 0) {
        write_crash("E3 Error."); terminate();
    }
    // Timing check
    QueryPerformanceCounter(&t1);
    // ... some work ...
    QueryPerformanceCounter(&t2);
    if ((t2 - t1) > THRESHOLD) { write_crash("E4 Error."); terminate(); }
    // Path check
    if (!check_process_path()) { write_crash("E5 Error."); terminate(); }
    // CRC32 check on icudtl.dat (and app.asar)
    uint32_t crc = compute_crc32(icudtl_path);
    if (crc != EXPECTED_CRC) { write_crash("E6 Error."); terminate(); }

    DAT_1800bf8ac = 1;  // Set "verified" flag
    // Loop with sleep interval...
}
```

---

## 6. Patch 1 — Binary Patch of `blitz_core.node`

### Goal

Make `FUN_1800161c0` immediately set the "verified" flag and return, without executing any checks.

### Technique: RIP-Relative MOV + RET

We overwrite the first 8 bytes of the function with two x86-64 instructions:

```asm
; Instruction 1: MOV byte ptr [rip + 0xA96E5], 1
; Opcode encoding: C6 /0 /disp32 /imm8
C6 05 E5 96 0A 00 01

; Instruction 2: RET
C3
```

**Why RIP-relative addressing?**

In x86-64 there is no `mov [absolute_address], imm8` encoding that fits in 8 bytes. Instead we use RIP-relative: the CPU computes the target address as `RIP + displacement`, where RIP is the address of the **next** instruction after the current one.

```
Instruction VA:   0x1800161C0
MOV length:       7 bytes
RIP after MOV:    0x1800161C7

Target (DAT_1800bf8ac): 0x1800BF8AC
Displacement:     0x1800BF8AC - 0x1800161C7 = 0x000A96E5 (stored LE: E5 96 0A 00)
```

### PE File Offset Calculation

The virtual address `0x1800161C0` cannot be directly used as a file offset — PE files are mapped differently in memory than on disk. We must walk the **section headers** to convert the RVA (Relative Virtual Address) to a raw file offset:

```
RVA = VA - IMAGE_BASE = 0x1800161C0 - 0x180000000 = 0x161C0

For each section header:
  if (VirtualAddress <= RVA < VirtualAddress + VirtualSize):
    FileOffset = RawDataPointer + (RVA - VirtualAddress)

Result: File offset 0x155C0  (in the .text section)
```

### Patch Bytes

```
Offset 0x155C0:
  Before: 40 55 53 56 57 41 54 41   (function prologue: push rbp; push rbx; ...)
  After:  C6 05 E5 96 0A 00 01 C3   (mov [rip+0xA96E5], 1; ret)
```

### Effect

Every time the Electron process calls `FUN_1800161c0` (via an internal timer), it immediately:
1. Writes `1` to `DAT_1800bf8ac` — the "verified" global flag
2. Returns — skipping all anti-debug, timing, path, and CRC checks

This means we can now freely modify `app.asar` without triggering E6.

---

## 7. Patch 2 — ASAR Extraction, JS Modification, and Repacking

### What is an ASAR?

Electron ASAR (Atom Shell Archive) is a **tar-like archive format** used to package JavaScript source files. The format consists of:

1. A 4-byte magic number
2. A Chromium Pickle-encoded header containing a JSON filesystem tree (with each file's offset, size, and optional SHA-256 integrity hash)
3. Raw concatenated file content following the header

The format is designed for fast random-access reads — Electron patches Node.js's `require()` to transparently read files from inside the ASAR without extracting.

### Why Repacking Was Historically Impossible

Before patching `blitz_core.node`, **any modification to app.asar triggered E6**. This was confirmed by the following experiment table:

| Modification | Result |
|---|---|
| Zero-change re-serialisation (identical bytes) | ✅ Works |
| Add 1 trailing null byte | ❌ E6 Error |
| Update integrity hash only | ❌ E6 Error |
| Change content + update hash | ❌ E6 Error |
| Change content, keep old hash | ❌ E6 Error |

The native module was performing a whole-file or block-level hash check on `app.asar`. Now that the checker is bypassed, repacking works freely.

### ASAR Workflow

```
Original app.asar (backup)
        │
        ▼ npx @electron/asar extract
   extracted/
   └── src/
       ├── auth.js            ← PATCH: fake premium user
       ├── autoUpdater/
       │   └── index.js       ← PATCH: no-op all update functions
       ├── crashReporter.js   ← PATCH: no-op crash/telemetry reporting
       ├── ota.js             ← PATCH: no-op OTA version check
       ├── electronWindowHandlers.js  ← PATCH: cancel ad network requests
       ├── createWindow.js    ← PATCH: premium window dimensions
       └── blitz-entry.js     ← PATCH: disable ads API + auto-start
        │
        ▼ npx @electron/asar pack --unpack "{*.node,*.dll}"
   patched app.asar  +  app.asar.unpacked/
        │
        ▼ copy to resources/
   Installed!
```

---

### auth.js — Fake Premium User

**Original behaviour:** `fetchUser()` reads a JWT from the local LevelDB store, POST's it to `https://auth.blitz.gg/graphql`, and returns the user's profile including their `roles` array. `hasPremiumRole()` then checks if any role is `PRO_SUBSCRIBER`, `FREE_PRO_SUBSCRIBER`, or `CRYPTO_PRO_SUBSCRIBER`.

**Why this matters:** The result of `hasPremiumRole()` is used in `createWindow.js` to determine the minimum window size. Free users get a 1420×850 minimum (sized to fit ad units). Premium users get 940×500.

**Patch:** Replace `fetchUser()` with a function that returns a hardcoded object with `PRO_SUBSCRIBER` role, and make `hasPremiumRole()` always return `true`.

```js
// BEFORE
async function fetchUser() {
  const token = await getToken();
  if (!token?.authToken) return;
  return axios("https://auth.blitz.gg/graphql", { ... })
    .then(r => r?.data?.data?.me);
}

// AFTER
async function fetchUser() {
  return { name: "PremiumUser", roles: [{ code: "PRO_SUBSCRIBER" }] };
}
```

---

### autoUpdater/index.js — Disable Auto-Updates

**Original behaviour:** Uses `electron-updater` to poll the GitHub releases feed at `theblitzapp/blitz-core`, download delta patches (`.exe` files), verify their SHA-256, and apply them by spawning the installer. Updates are applied automatically for "security" releases.

**Patch:** Replace the entire module with stub functions that return resolved Promises. The `app-update.yml` feed URL is also replaced with `localhost:0` as a belt-and-suspenders measure.

---

### crashReporter.js — Disable Telemetry

**Original behaviour:**
1. Calls `Electron.crashReporter.start()` with the Sentry minidump DSN from `.env.production` — this registers a system-level crash handler that uploads minidumps to Sentry on process crash
2. On Windows, calls `blitz_core.node`'s `InitCrashHandler()` to register a native crash dump writer to `%TEMP%\blitz\`

**Patch:** Replace with a no-op `setupCrashHandler()`. The `.env.production` SENTRY_DSN values are also cleared.

---

### ota.js — Disable OTA Updater

**Original behaviour:** A *separate* update mechanism (distinct from `electron-updater`) that polls `utils.iesdev.com` to determine which version of the remote web app to load. Stores the resolved version in LevelDB. Runs on startup and polls every hour.

This is separate from the binary updater — it controls which URL the `BrowserView` loads (`https://probuilds.net/v{version}`).

**Patch:** Return the version from the bundled `package.json` directly, making zero network calls.

**Why this matters:** The original `ota.js` was discovered when the app threw `ENOTFOUND utils.iesdev.com` errors because the app's startup OTA check was failing (network not yet up or domain blocked), causing an unhandled rejection that crashed the window.

---

### electronWindowHandlers.js — Network-Level Ad Block

**Original behaviour:** `interceptRequests()` is called for each `BrowserWindow`/`BrowserView`. It sets up `session.webRequest.onBeforeSendHeaders()` to modify headers for the LCU WebSocket and Blitz CDN. It does **not** block ad networks.

**Patch:** We inject an additional `session.webRequest.onBeforeRequest()` handler that cancels any request whose URL matches a list of known ad networks and telemetry endpoints **before the TCP connection is even opened**.

```js
window.webContents.session.webRequest.onBeforeRequest(
  { urls: AD_BLOCK_PATTERNS },
  (_details, callback) => callback({ cancel: true })
);
```

**Electron URL pattern syntax note:** Patterns follow Chrome extension match pattern syntax. A common mistake is using wildcard TLDs like `*://host.*/*` — these are **invalid** in Electron and throw:
```
TypeError: Invalid url pattern *://adservice.google.*/*: Invalid host wildcard.
```
Only **subdomain wildcards** (`*://*.host.com/*`) are supported.

---

### createWindow.js — Premium Window Size

**Original behaviour:**
```js
const DEFAULT_WIDTH = 1420;
const DEFAULT_HEIGHT = 850;

fetchUser().then((user) => {
  if (user && hasPremiumRole(user.roles)) {
    MIN_WIDTH = 940; MIN_HEIGHT = 500;
    windows.client.setMinimumSize(940, 500);
  } else {
    MIN_WIDTH = DEFAULT_WIDTH; MIN_HEIGHT = DEFAULT_HEIGHT;
    // Force resize if window is smaller than ad-friendly minimum
    windows.client.setMinimumSize(1420, 850);
  }
});
```

**Patch:** Change the constants and replace the `fetchUser()` callback with a static assignment:
```js
const DEFAULT_WIDTH = 940;   // PATCHED
const DEFAULT_HEIGHT = 500;  // PATCHED

// PATCHED: hardcode premium window dimensions
MIN_WIDTH = 940; MIN_HEIGHT = 500;
write("MIN_WIDTH", MIN_WIDTH); write("MIN_HEIGHT", MIN_HEIGHT);
windows.client.setMinimumSize(940, 500);
```

---

### blitz-entry.js — Disable Privacy Sandbox

**Original behaviour:** The app entry point appends `--enable-privacy-sandbox-ads-apis` to Chromium's command-line arguments, enabling the Topics API (a FLoC successor for browser-based ad targeting). It also calls `addAutoStartOnFirstRun()` which registers Blitz as a Windows startup app via the registry.

**Patch:** Comment out both lines.

---

## 8. Patch 3 — `.env.production`

The app loads `resources/.env.production` via `dotenv` at startup. It contains:

```ini
SENTRY_DSN=https://d0d473722f3c496a9d6097abb79c953f@sentry.blitz.gg/2
SENTRY_MINIDUMP_DSN=https://sentry.blitz.gg/api/2/minidump/?sentry_key=...
REACT_APP_LOCIZE_API_KEY=d983c536-1533-4230-be6b-ee764813355f
```

**Patch:** Clear the values (keep the keys so dotenv doesn't fail) to ensure no crash events, error reports, or i18n telemetry are sent even if the `crashReporter.js` patch is somehow bypassed:

```ini
SENTRY_DSN=
SENTRY_MINIDUMP_DSN=
REACT_APP_LOCIZE_API_KEY=
```

---

## 9. Patch 4 — `app-update.yml`

`electron-updater` reads this file to find the update feed:

```yaml
# Original
owner: theblitzapp
repo: blitz-core
provider: github
```

**Patch:** Change to an unreachable generic URL:

```yaml
# Patched
provider: generic
url: http://localhost:0
```

The `autoUpdater/index.js` JS patch already makes the updater a no-op. This config change is belt-and-suspenders — even if the JS is somehow reverted, the updater will fail to resolve `localhost:0` at the network level.

---

## 10. ASAR Repacking — Why `--unpack` Matters

### The `--unpack` Problem

When `@electron/asar pack` is run without `--unpack`, **all files** including native `.node` addons are packed inside the ASAR. However, native addons loaded via `require()` are handled differently from regular JS files:

- JS files: Node.js reads them directly from the ASAR virtual filesystem via a patched `require()`
- Native `.node` files: Node.js loads them with `dlopen()` (Linux) / `LoadLibrary()` (Windows), which requires a **real filesystem path**

If a `.node` file is inside the ASAR, `dlopen` fails with `ERR_DLOPEN_FAILED`.

### The `liblzma.dll` Problem

`lzma-native`'s `electron.napi.node` links against `liblzma.dll` at runtime. Windows resolves DLL dependencies by searching directories in this order:

1. The directory of the loading DLL itself
2. System directories (`System32`, etc.)
3. PATH

If `liblzma.dll` is packed inside the ASAR but `electron.napi.node` is unpacked to `app.asar.unpacked/`, Windows can't find `liblzma.dll` in directory 1 (it's not on disk next to the `.node` file). The crash:

```
Error: The specified module could not be found.
\\?\C:\...\app.asar.unpacked\node_modules\lzma-native\prebuilds\win32-x64\electron.napi.node
```

**Fix:** Use `--unpack "{*.node,*.dll}"` to unpack both `.node` files AND their companion DLLs to disk.

### The `app.asar.unpacked/` Directory

After repacking, the directory structure is:

```
app.asar              ← ASAR archive (JS source only)
app.asar.unpacked/    ← Real files on disk (native modules + DLLs)
└── node_modules/
    ├── classic-level/prebuilds/win32-x64/
    │   └── node.napi.node      ← LevelDB native addon
    └── lzma-native/prebuilds/win32-x64/
        ├── electron.napi.node  ← LZMA native addon
        ├── node.napi.node
        └── liblzma.dll         ← Required companion DLL
```

**Important:** Both `app.asar` and `app.asar.unpacked/` must be installed together. Replacing only `app.asar` without updating the `.unpacked/` directory will cause stale native modules to be loaded.

---

## 11. Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| [Ghidra](https://ghidra-sre.org/) | 12.1 | Disassembly and decompilation of `blitz_core.node` |
| Python | 3.8+ | PE binary patching, ASAR orchestration |
| Node.js + npx | 18+ | Running `@electron/asar` for extraction/repacking |
| [@electron/asar](https://github.com/electron/asar) | latest | Official ASAR packing/unpacking tool |
| PowerShell | 5.1+ | File search, process management, verification |
| `struct` (Python stdlib) | — | PE header parsing for RVA→file offset conversion |

---

## 12. Usage

### Requirements

- Windows 10/11
- [Python 3.8+](https://python.org)
- [Node.js 18+](https://nodejs.org) (for `npx`)
- Blitz desktop app installed at its default path

### Running the Patcher

```powershell
# Clone the repo
git clone https://github.com/ameen/blitz-crank
cd blitz-crank

# Apply all patches
python tools\patch.py
```

The script will:
1. Backup all original files to `_backup/`
2. Patch `blitz_core.node` in-place (8 bytes)
3. Extract `app.asar` from the backup, apply JS patches, repack with `--unpack "{*.node,*.dll}"`
4. Install patched `app.asar` + `app.asar.unpacked/`
5. Clear Sentry DSNs from `.env.production`
6. Disable the update feed in `app-update.yml`

---

## 13. Restore

```powershell
python tools\patch.py --restore
```

Restores all files from the `_backup/` directory created during the first run.

---

## 14. Disclaimer

This project is provided **strictly for educational and research purposes**. It documents:
- x86-64 binary analysis and patching techniques
- PE file format internals (section headers, RVA-to-offset conversion)
- RIP-relative addressing in x86-64
- Electron application internals (ASAR format, native addon loading, webRequest API)
- Node.js native addon (`node-api`) architecture

No Blitz source code, binaries, or proprietary assets are included in this repository. The patch script modifies locally installed files and does not distribute any Blitz IP.

Use of these techniques against software you do not own, or in violation of its Terms of Service, may be unlawful. The authors accept no responsibility for misuse.
