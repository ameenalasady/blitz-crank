"""
Blitz Crank — Patch Engine
============================
For educational purposes only. Demonstrates PE binary patching, ASAR
extraction, and JavaScript source modification on an Electron application.

To add or change a patch: edit  tools/patches.py
To change a patch file:   edit  tools/patches/<name>.js

Usage:
  python patch.py           # apply all patches
  python patch.py --restore # restore originals from backup

Requirements: Python 3.8+, Node.js 18+ (for npx / @electron/asar)
"""

import sys
import os
import re
import struct
import shutil
import subprocess

# ── Target paths ──────────────────────────────────────────────────────────────
_USER = os.environ.get("USERNAME", "User")
BLITZ_DIR   = rf"C:\Users\{_USER}\AppData\Local\Programs\Blitz"
RES_DIR     = os.path.join(BLITZ_DIR, "resources")
ASAR_PATH   = os.path.join(RES_DIR, "app.asar")
BINARIES    = os.path.join(RES_DIR, "binaries")
ENV_FILE    = os.path.join(RES_DIR, ".env.production")
UPDATE_YML  = os.path.join(RES_DIR, "app-update.yml")
CORE_NODE   = os.path.join(BINARIES, "blitz_core.node")

TOOLS_DIR   = os.path.dirname(os.path.abspath(__file__))
WORK_DIR    = os.path.join(TOOLS_DIR, "_patch_work")
EXTRACT_DIR = os.path.join(WORK_DIR, "app")
REPACK_ASAR = os.path.join(WORK_DIR, "app.asar")
BACKUP_DIR  = os.path.join(TOOLS_DIR, "_backup")

RESTORE = "--restore" in sys.argv


# ══════════════════════════════════════════════════════════════════════════════
# Console helpers
# ══════════════════════════════════════════════════════════════════════════════

def log(msg):  print(f"  {msg}")
def step(msg): print(f"\n[*] {msg}")
def ok(msg):   print(f"  [OK] {msg}")
def warn(msg): print(f"  [!]  {msg}")
def die(msg):  print(f"\n[ERROR] {msg}"); sys.exit(1)


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def _write(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def run(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"Command failed: {cmd}\n{r.stderr}\n{r.stdout}")
    return r


# ══════════════════════════════════════════════════════════════════════════════
# Process management
# ══════════════════════════════════════════════════════════════════════════════

def kill_blitz():
    """Terminate all Blitz processes before touching locked native files.

    app.asar.unpacked contains .node files (classic-level, lzma-native) that
    Windows keeps open while Blitz is running. shutil.rmtree() will fail with
    PermissionError (WinError 5) if any handles are open.
    """
    procs = ["Blitz.exe", "BlitzUpdater.exe", "BlitzHelper.exe"]
    killed = []
    for p in procs:
        r = subprocess.run(f'taskkill /F /IM "{p}" /T',
                           shell=True, capture_output=True, text=True)
        if r.returncode == 0:
            killed.append(p)
    if killed:
        import time
        log(f"Killed: {', '.join(killed)} — waiting for handles to release...")
        time.sleep(2)
    else:
        log("No running Blitz processes found")


# ══════════════════════════════════════════════════════════════════════════════
# Backup / restore
# ══════════════════════════════════════════════════════════════════════════════

def backup(src):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    dst = os.path.join(BACKUP_DIR, os.path.basename(src))
    if not os.path.exists(dst):
        shutil.copy2(src, dst)
        ok(f"Backed up {os.path.basename(src)}")
    else:
        log(f"Backup already exists for {os.path.basename(src)}")

def restore_file(name, dst):
    src = os.path.join(BACKUP_DIR, name)
    if not os.path.exists(src):
        warn(f"No backup for {name}"); return
    shutil.copy2(src, dst)
    ok(f"Restored {name}")

def do_restore():
    step("Restoring originals from backup...")
    kill_blitz()
    restore_file("blitz_core.node", CORE_NODE)
    restore_file("app.asar",        ASAR_PATH)
    restore_file(".env.production",  ENV_FILE)
    restore_file("app-update.yml",   UPDATE_YML)
    unpacked_bak = os.path.join(BACKUP_DIR, "app.asar.unpacked")
    unpacked_tgt = ASAR_PATH + ".unpacked"
    if os.path.exists(unpacked_bak):
        if os.path.exists(unpacked_tgt):
            shutil.rmtree(unpacked_tgt)
        shutil.copytree(unpacked_bak, unpacked_tgt)
        ok("Restored app.asar.unpacked/")
    ok("Restore complete.")


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 1 — blitz_core.node (PE binary patch)
# ══════════════════════════════════════════════════════════════════════════════
#
# Target:  FUN_1800161c0  (the main integrity verification loop)
# Method:  Overwrite the 8-byte function prologue with:
#
#   C6 05 E5 96 0A 00 01   MOV byte ptr [RIP + 0xA96E5], 1
#   C3                     RET
#
# RIP-relative calculation:
#   Instruction VA = 0x1800161C0
#   RIP after 7-byte MOV = 0x1800161C7
#   Target (DAT_1800bf8ac, "verified" flag) = 0x1800BF8AC
#   Displacement = 0x1800BF8AC - 0x1800161C7 = 0x000A96E5  (LE: E5 96 0A 00)
#
# Effect: the function immediately sets verified=1 and returns, bypassing
#         all E1-E6 checks (anti-debug, timing, path, CRC32 of icudtl.dat
#         and app.asar). This is what allows app.asar to be freely modified.
# ─────────────────────────────────────────────────────────────────────────────

IMAGE_BASE  = 0x180000000
TARGET_RVA  = 0x161C0        # FUN_1800161c0 relative to IMAGE_BASE
VERIFIED_VA = 0x1800BF8AC    # DAT_1800bf8ac — the "verified" flag byte

PATCH_BYTES = bytes([
    0xC6, 0x05,              # MOV byte ptr [RIP + disp32], imm8
    0xE5, 0x96, 0x0A, 0x00, # disp32 = 0x000A96E5 (little-endian)
    0x01,                    # imm8   = 1
    0xC3,                    # RET
])


def _rva_to_file_offset(f, rva):
    """Walk PE section headers to convert RVA → raw file offset."""
    f.seek(0x3C)
    pe = struct.unpack("<I", f.read(4))[0]
    f.seek(pe + 4 + 2)
    nsec = struct.unpack("<H", f.read(2))[0]
    f.seek(pe + 4 + 16)
    optsz = struct.unpack("<H", f.read(2))[0]
    sec_base = pe + 4 + 20 + optsz
    for i in range(nsec):
        f.seek(sec_base + i * 40 + 8)
        vsize = struct.unpack("<I", f.read(4))[0]
        vaddr = struct.unpack("<I", f.read(4))[0]
        _     = struct.unpack("<I", f.read(4))[0]
        rptr  = struct.unpack("<I", f.read(4))[0]
        if vaddr <= rva < vaddr + vsize:
            return rptr + (rva - vaddr)
    return None


def patch_core_node():
    step("PATCH 1 — blitz_core.node (PE binary patch)")
    backup(CORE_NODE)
    with open(CORE_NODE, "r+b") as f:
        assert f.read(2) == b"MZ", "Not a PE binary!"
        offset = _rva_to_file_offset(f, TARGET_RVA)
        if offset is None:
            die("Could not resolve RVA to file offset")
        f.seek(offset)
        orig = f.read(len(PATCH_BYTES))
        log(f"File offset:    0x{offset:X}")
        log(f"Original bytes: {orig.hex(' ')}")
        log(f"Patch bytes:    {PATCH_BYTES.hex(' ')}")
        if orig == PATCH_BYTES:
            ok("Already patched — skipping"); return
        f.seek(offset)
        f.write(PATCH_BYTES)
        f.seek(offset)
        assert f.read(len(PATCH_BYTES)) == PATCH_BYTES
    ok("Integrity checker bypassed (E1-E6, anti-debug, CRC32)")


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 2 — app.asar (generic JS patch engine driven by patches.py)
# ══════════════════════════════════════════════════════════════════════════════

def _apply_one(patch, src_dir):
    """Apply a single patch dict to the extracted ASAR src/ tree."""
    op       = patch["op"]
    rel      = patch["file"].replace("/", os.sep)
    target   = os.path.join(src_dir, rel)
    patch_id = patch.get("id", rel)

    if not os.path.exists(target):
        warn(f"{patch_id}: target file not found ({rel}) — skipping")
        return

    # ── rewrite: replace entire file with content from patches/<name>.js ──
    if op == "rewrite":
        src_path = os.path.join(TOOLS_DIR, patch["src"].replace("/", os.sep))
        content  = _read(src_path)
        _write(target, content)
        ok(f"{rel} — {patch['desc']}")

    # ── inject: insert snippet before a marker (with idempotency guard) ──
    elif op == "inject":
        code  = _read(target)
        guard = patch.get("guard")
        if guard and guard in code:
            ok(f"{rel} — already patched (guard found)"); return
        src_path = os.path.join(TOOLS_DIR, patch["src"].replace("/", os.sep))
        snippet  = _read(src_path)
        marker   = patch["marker"]
        if marker not in code:
            warn(f"{patch_id}: injection marker not found — skipping"); return
        _write(target, code.replace(marker, snippet + "\n" + marker))
        ok(f"{rel} — {patch['desc']}")

    # ── replace: single str.replace ──
    elif op == "replace":
        code = _read(target)
        new  = code.replace(patch["find"], patch["replace"])
        if new == code:
            warn(f"{patch_id}: pattern not found — '{patch['find'][:60]}'")
        else:
            ok(f"{rel} — {patch['desc']}")
        _write(target, new)

    # ── replace_many: ordered sequence of replace / regex ops ──
    elif op == "replace_many":
        code = _read(target)
        any_changed = False
        for sub in patch["ops"]:
            sub_op = sub.get("op", "replace")
            if sub_op == "regex":
                flags   = sub.get("flags", 0)
                new, n  = re.subn(sub["pattern"], sub["replace"], code, flags=flags)
                if n == 0:
                    warn(f"{patch_id}: regex sub-op not found — skipping sub-op")
                else:
                    any_changed = True
                code = new
            else:  # plain replace
                new = code.replace(sub["find"], sub["replace"])
                if new == code:
                    warn(f"{patch_id}: sub-op find not found — '{sub['find'][:60]}'")
                else:
                    any_changed = True
                code = new
        _write(target, code)
        if any_changed:
            ok(f"{rel} — {patch['desc']}")

    else:
        warn(f"{patch_id}: unknown op '{op}' — skipping")


def patch_asar():
    step("PATCH 2 — app.asar (ASAR extract → JS patch → repack)")
    backup(ASAR_PATH)

    # Back up the unpacked native module directory
    unpacked_src = ASAR_PATH + ".unpacked"
    unpacked_bak = os.path.join(BACKUP_DIR, "app.asar.unpacked")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    if os.path.exists(unpacked_src) and not os.path.exists(unpacked_bak):
        shutil.copytree(unpacked_src, unpacked_bak)
        ok("Backed up app.asar.unpacked/")

    if os.path.exists(WORK_DIR):
        shutil.rmtree(WORK_DIR)
    os.makedirs(WORK_DIR, exist_ok=True)

    if run("npx --yes @electron/asar --version", check=False).returncode != 0:
        die("@electron/asar not available — install Node.js and try again")
    ok("@electron/asar available")

    # Always extract from the ORIGINAL backup — prevents cumulative re-patching.
    # If you extract from the already-patched installed ASAR you will inject
    # the same blocks twice, causing SyntaxErrors at runtime.
    orig_asar = os.path.join(BACKUP_DIR, "app.asar")
    if not os.path.exists(orig_asar):
        die(f"Original ASAR backup not found at {orig_asar}")
    log(f"Extracting original ASAR → {EXTRACT_DIR}")
    run(f'npx @electron/asar extract "{orig_asar}" "{EXTRACT_DIR}"')
    ok("Original ASAR extracted")

    # Load the patch registry and apply every entry
    from patches import PATCHES
    src_dir = os.path.join(EXTRACT_DIR, "src")
    for patch in PATCHES:
        _apply_one(patch, src_dir)

    # Repack — two reasons for --unpack "{*.node,*.dll}":
    #   1. Native .node addons require a real filesystem path for dlopen/LoadLibrary
    #   2. Companion DLLs (e.g. liblzma.dll) must sit beside their .node file so
    #      Windows DLL search order can find them (directory-of-loading-DLL first)
    log("Repacking with --unpack '{*.node,*.dll}'")
    run(f'npx @electron/asar pack "{EXTRACT_DIR}" "{REPACK_ASAR}" --unpack "{{*.node,*.dll}}"')
    ok("ASAR repacked")

    # Kill Blitz before installing — classic-level's node.napi.node is held
    # open by the running process; rmtree will fail with WinError 5 if it is.
    kill_blitz()

    shutil.copy2(REPACK_ASAR, ASAR_PATH)
    ok(f"Installed → {ASAR_PATH}")

    repack_unpacked  = REPACK_ASAR + ".unpacked"
    install_unpacked = ASAR_PATH   + ".unpacked"
    if os.path.exists(repack_unpacked):
        if os.path.exists(install_unpacked):
            shutil.rmtree(install_unpacked)
        shutil.copytree(repack_unpacked, install_unpacked)
        ok(f"Installed app.asar.unpacked/ → {install_unpacked}")
    else:
        warn("No .unpacked dir generated — native modules may fail to load!")


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 3 — .env.production (clear telemetry DSNs)
# ══════════════════════════════════════════════════════════════════════════════
#
# The app loads this file with dotenv at startup. Clearing the Sentry DSN
# values prevents crash events and minidumps from being sent even if the
# crashReporter.js patch is bypassed. Keys are kept so dotenv doesn't fail.
# ─────────────────────────────────────────────────────────────────────────────

ENV_KEYS_TO_CLEAR = {"SENTRY_DSN", "SENTRY_MINIDUMP_DSN", "REACT_APP_LOCIZE_API_KEY"}

def patch_env():
    step("PATCH 3 — .env.production (clear telemetry DSNs)")
    backup(ENV_FILE)
    lines = _read(ENV_FILE).splitlines(keepends=True)
    out   = []
    for line in lines:
        key = line.split("=")[0]
        if key in ENV_KEYS_TO_CLEAR:
            out.append(f"{key}=\n")
            log(f"Cleared: {key}")
        else:
            out.append(line)
    _write(ENV_FILE, "".join(out))
    ok("Sentry DSNs and Locize API key cleared")


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 4 — app-update.yml (disable update feed)
# ══════════════════════════════════════════════════════════════════════════════
#
# electron-updater reads this file to find the update feed URL. Pointing it
# at localhost:0 ensures the updater fails at the network level even if the
# autoUpdater/index.js patch is somehow reverted. Belt-and-suspenders.
# ─────────────────────────────────────────────────────────────────────────────

def patch_update_yml():
    step("PATCH 4 — app-update.yml (disable update feed)")
    backup(UPDATE_YML)
    _write(UPDATE_YML, "# PATCHED: update feed disabled\nprovider: generic\nurl: http://localhost:0\n")
    ok("Update feed pointed to localhost:0 (unreachable)")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if RESTORE:
        do_restore(); return

    print("\n" + "=" * 60)
    print("  Blitz Crank — Educational Patch Installer")
    print("=" * 60)

    if not os.path.exists(BLITZ_DIR):
        die(f"Blitz not found at {BLITZ_DIR}\nInstall Blitz first.")

    patch_core_node()
    patch_asar()
    patch_env()
    patch_update_yml()

    # Count JS patches applied
    from patches import PATCHES
    print("\n" + "=" * 60)
    print("  Done! All patches applied.")
    print()
    print("  [1] blitz_core.node — integrity checker bypassed (E1-E6)")
    print(f"  [2] app.asar        — {len(PATCHES)} JS patches applied")
    for p in PATCHES:
        print(f"        {p['file']:<38} {p['desc'][:45]}")
    print("  [3] .env.production — Sentry DSNs + Locize key cleared")
    print("  [4] app-update.yml  — update feed disabled")
    print()
    print(f"  Backups: {BACKUP_DIR}")
    print("  Restore: python patch.py --restore")
    print("=" * 60)


if __name__ == "__main__":
    main()
