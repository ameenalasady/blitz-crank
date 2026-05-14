"""
Blitz Crank — Educational Patch Installer
==========================================
For educational purposes only. Demonstrates:
  - PE binary patching (RIP-relative MOV + RET)
  - Electron ASAR extraction, JS source modification, and repacking
  - Native addon (.node) dependency handling
  - Environment config stripping

Usage:
  python patch.py           # Apply all patches
  python patch.py --restore # Restore original files from backup

Requirements:
  - Python 3.8+
  - Node.js + npx (for @electron/asar)
  - Blitz installed at the default path

See README.md and docs/ for a full explanation of every step.
"""

import sys
import os
import struct
import shutil
import subprocess
import re

# ── Target paths ───────────────────────────────────────────────────
BLITZ_DIR   = r"C:\Users\{}\AppData\Local\Programs\Blitz".format(os.environ.get("USERNAME", "User"))
RES_DIR     = os.path.join(BLITZ_DIR, "resources")
ASAR_PATH   = os.path.join(RES_DIR, "app.asar")
BINARIES    = os.path.join(RES_DIR, "binaries")
ENV_FILE    = os.path.join(RES_DIR, ".env.production")
UPDATE_YML  = os.path.join(RES_DIR, "app-update.yml")
CORE_NODE   = os.path.join(BINARIES, "blitz_core.node")

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
WORK_DIR    = os.path.join(SCRIPT_DIR, "_patch_work")
EXTRACT_DIR = os.path.join(WORK_DIR, "app")
REPACK_ASAR = os.path.join(WORK_DIR, "app.asar")
BACKUP_DIR  = os.path.join(SCRIPT_DIR, "_backup")

RESTORE = "--restore" in sys.argv


def kill_blitz():
    """Terminate all running Blitz processes.

    app.asar.unpacked contains native .node files (classic-level, lzma-native)
    that Windows locks while Blitz is running. shutil.rmtree() will fail with
    PermissionError (WinError 5) if any of those handles are open.
    We kill the process first to release the locks.
    """
    BLITZ_PROCS = ["Blitz.exe", "BlitzUpdater.exe", "BlitzHelper.exe"]
    killed = []
    for proc_name in BLITZ_PROCS:
        result = subprocess.run(
            f'taskkill /F /IM "{proc_name}" /T',
            shell=True, capture_output=True, text=True
        )
        if result.returncode == 0:
            killed.append(proc_name)
    if killed:
        log(f"Killed: {', '.join(killed)} — waiting for handles to release...")
        import time; time.sleep(2)
    else:
        log("No running Blitz processes found")


# ══════════════════════════════════════════════════════════════════
# Utility helpers
# ══════════════════════════════════════════════════════════════════

def log(msg):  print(f"  {msg}")
def step(msg): print(f"\n[*] {msg}")
def ok(msg):   print(f"  [OK] {msg}")
def warn(msg): print(f"  [!]  {msg}")
def die(msg):  print(f"\n[ERROR] {msg}"); sys.exit(1)


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
        warn(f"No backup found for {name}")
        return
    shutil.copy2(src, dst)
    ok(f"Restored {name}")


def run(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        die(f"Command failed: {cmd}\n{result.stderr}\n{result.stdout}")
    return result


# ══════════════════════════════════════════════════════════════════
# RESTORE
# ══════════════════════════════════════════════════════════════════

def do_restore():
    """Restore all original files from backup."""
    step("Restoring originals from backup...")
    kill_blitz()
    restore_file("blitz_core.node", CORE_NODE)
    restore_file("app.asar", ASAR_PATH)
    restore_file(".env.production", ENV_FILE)
    restore_file("app-update.yml", UPDATE_YML)
    unpacked_bak = os.path.join(BACKUP_DIR, "app.asar.unpacked")
    unpacked_tgt = ASAR_PATH + ".unpacked"
    if os.path.exists(unpacked_bak):
        if os.path.exists(unpacked_tgt):
            shutil.rmtree(unpacked_tgt)
        shutil.copytree(unpacked_bak, unpacked_tgt)
        ok("Restored app.asar.unpacked/")
    ok("Restore complete.")


# ══════════════════════════════════════════════════════════════════
# PATCH 1 — blitz_core.node (binary PE patch)
# ══════════════════════════════════════════════════════════════════
#
# Target:  FUN_1800161c0  (the main integrity verification loop)
# Method:  Replace the 8-byte function prologue with:
#
#   C6 05 E5 96 0A 00 01   mov byte ptr [rip + 0xA96E5], 1
#   C3                     ret
#
# RIP-relative calculation:
#   Instruction VA = 0x1800161C0
#   RIP after 7-byte MOV = 0x1800161C7
#   Target (DAT_1800bf8ac, the "verified" flag) = 0x1800BF8AC
#   Displacement = 0x1800BF8AC - 0x1800161C7 = 0x000A96E5
#
# Effect: On every call, the function immediately sets verified=1 and
#         returns, bypassing all E1-E6 checks, anti-debug detection,
#         and CRC32 verification of icudtl.dat and app.asar.
# ─────────────────────────────────────────────────────────────────

IMAGE_BASE  = 0x180000000
TARGET_RVA  = 0x161C0        # FUN_1800161c0 - IMAGE_BASE
VERIFIED_VA = 0x1800BF8AC    # DAT_1800bf8ac (the "verified" flag byte)

PATCH_BYTES = bytes([
    0xC6, 0x05,              # MOV byte ptr [rip + disp32], imm8
    0xE5, 0x96, 0x0A, 0x00, # disp32 = 0x000A96E5 (LE) → targets DAT_1800bf8ac
    0x01,                    # imm8  = 1
    0xC3,                    # RET
])


def _rva_to_file_offset(f, rva):
    """Walk PE section headers to convert RVA → raw file offset."""
    f.seek(0x3C)
    pe = struct.unpack('<I', f.read(4))[0]
    f.seek(pe + 4 + 2)
    nsec = struct.unpack('<H', f.read(2))[0]
    f.seek(pe + 4 + 16)
    optsz = struct.unpack('<H', f.read(2))[0]
    sec_base = pe + 4 + 20 + optsz
    for i in range(nsec):
        f.seek(sec_base + i * 40 + 8)
        vsize = struct.unpack('<I', f.read(4))[0]
        vaddr = struct.unpack('<I', f.read(4))[0]
        _     = struct.unpack('<I', f.read(4))[0]  # raw size
        rptr  = struct.unpack('<I', f.read(4))[0]
        if vaddr <= rva < vaddr + vsize:
            return rptr + (rva - vaddr)
    return None


def patch_core_node():
    step("PATCH 1 — blitz_core.node (PE binary patch)")
    backup(CORE_NODE)

    with open(CORE_NODE, 'r+b') as f:
        assert f.read(2) == b'MZ', "Not a PE binary!"
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


# ══════════════════════════════════════════════════════════════════
# PATCH 2 — app.asar (JS source patches)
# ══════════════════════════════════════════════════════════════════

def _write(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def patch_auth(src):
    """
    auth.js — fetchUser() / hasPremiumRole()
    ─────────────────────────────────────────
    Originally fetchUser() makes a GraphQL POST to auth.blitz.gg,
    decodes the JWT from the local LevelDB store, and returns the
    user object including their `roles` array.

    hasPremiumRole() then checks whether any role code is one of:
      PRO_SUBSCRIBER | FREE_PRO_SUBSCRIBER | CRYPTO_PRO_SUBSCRIBER

    This result gates the minimum window size in createWindow.js.

    Patch: Return a fake user object with PRO_SUBSCRIBER role
           directly — no network call, no auth token needed.
    """
    _write(os.path.join(src, "auth.js"), r"""const { write, get } = require("./db");
const log = require("npmlog");

const tokenListeners = [];
function addTokenListener(cb) { tokenListeners.push(cb); }

async function getToken() {
  const r = await get("authToken");
  if (!r) return null;
  if (/^[0-9a-z]+:[0-9a-z]+$/i.test(r)) return null;
  return JSON.parse(r);
}

async function saveToken(data) {
  const str = data ? JSON.stringify(data) : "";
  for (const cb of tokenListeners) { try { cb(data || null); } catch(e){} }
  return write("authToken", str);
}

// EDUCATIONAL PATCH: Return fake premium user — no auth server call
async function fetchUser() {
  return { name: "PremiumUser", roles: [{ code: "PRO_SUBSCRIBER" }] };
}

// EDUCATIONAL PATCH: Always report premium status
function hasPremiumRole(_roles) { return true; }

module.exports = { saveToken, getToken, fetchUser, hasPremiumRole, addTokenListener };
""")
    ok("auth.js — fetchUser() returns PRO_SUBSCRIBER, hasPremiumRole() always true")


def patch_autoupdater(src):
    """
    autoUpdater/index.js
    ─────────────────────
    The original uses electron-updater to poll a GitHub releases feed
    (app-update.yml), download delta patches or full installers, and
    apply them via spawnSync. It also sends an APP_INSTALL telemetry
    event to science.v2.iesdev.com on first run.

    Patch: Replace the entire module with no-ops so the app never
           checks for or applies updates. app-update.yml is also
           rewritten to point at localhost:0 as a belt-and-suspenders
           measure.
    """
    _write(os.path.join(src, "autoUpdater", "index.js"), r"""// EDUCATIONAL PATCH: auto-updater disabled
const log = require("npmlog");
function init() { log.info("[Updater] PATCHED: disabled."); }
function checkForUpdates() { return Promise.resolve(); }
async function bootApp() { return Promise.resolve(); }
function closeUpdaterWindow() { return Promise.resolve(); }
module.exports = { init, checkForUpdates, bootApp, closeUpdaterWindow };
""")
    ok("autoUpdater/index.js — all update functions no-op'd")


def patch_crash_reporter(src):
    """
    crashReporter.js
    ─────────────────
    Originally calls Electron's built-in crashReporter.start() with
    the Sentry minidump DSN loaded from .env.production, then on
    Windows also calls the native blitz_core.node InitCrashHandler()
    to register a low-level crash dump writer to %TEMP%/blitz/.

    Patch: Replace with a no-op. .env.production is also cleared of
           SENTRY_DSN and SENTRY_MINIDUMP_DSN as belt-and-suspenders.
    """
    _write(os.path.join(src, "crashReporter.js"), r"""// EDUCATIONAL PATCH: crash reporting / telemetry disabled
const log = require("npmlog");
async function setupCrashHandler() { log.info("[CrashReporter] PATCHED: disabled."); }
module.exports = { setupCrashHandler };
""")
    ok("crashReporter.js — Sentry / minidump reporting disabled")


def patch_ota(src):
    """
    ota.js (Over-The-Air updater)
    ──────────────────────────────
    A separate, secondary update mechanism that polls
    utils.iesdev.com to determine which web-app version to load.
    Unlike electron-updater (which updates the binary), OTA updates
    the URL used to load the remote React app inside the BrowserView.
    It stores the resolved version in LevelDB and uses it to build
    the probuilds.net/v{version} URL on next launch.

    Patch: Return the bundled package.json version synchronously
           so the app boots without any network call.
    """
    ota_path = os.path.join(src, "ota.js")
    if not os.path.exists(ota_path):
        warn("ota.js not found — skipping")
        return
    _write(ota_path, r"""// EDUCATIONAL PATCH: OTA updater disabled
const log = require("npmlog");
const ota = {
  checkForUpdates: async () => {},
  pollForUpdates:  () => {},
  getVersion:      async () => require("../package.json").version,
};
module.exports = ota;
""")
    ok("ota.js — OTA update polling disabled")


def patch_window_handlers(src):
    """
    electronWindowHandlers.js — ad/telemetry network blocking
    ──────────────────────────────────────────────────────────
    interceptRequests() already manipulates request headers for the
    LCU WebSocket and Blitz CDN. We inject an additional
    session.webRequest.onBeforeRequest() handler that cancels any
    request whose URL matches a known ad network or telemetry domain
    before it even leaves the process.

    This is the Electron equivalent of a hosts-file block but scoped
    to the app's own network session, so it works independently of
    system-level DNS blockers (Pi-hole, etc.).

    Note: Electron's webRequest URL patterns follow Chrome extension
    match pattern syntax. Wildcard TLDs (*://host.*/) are NOT valid —
    only subdomain wildcards (*://*.host.com/) are supported.
    """
    path = os.path.join(src, "electronWindowHandlers.js")
    with open(path, 'r', encoding='utf-8') as f:
        code = f.read()

    if "AD_BLOCK_PATTERNS" in code:
        ok("electronWindowHandlers.js — ad-block already present"); return

    block = r"""

  // EDUCATIONAL PATCH: cancel ad/telemetry requests at the session layer
  const AD_BLOCK_PATTERNS = [
    "*://googleads.g.doubleclick.net/*",
    "*://securepubads.g.doubleclick.net/*",
    "*://pagead2.googlesyndication.com/*",
    "*://tpc.googlesyndication.com/*",
    "*://adservice.google.com/*",
    "*://stats.g.doubleclick.net/*",
    "*://www.googletagmanager.com/gtag/*",
    "*://www.googletagservices.com/*",
    "*://ads.pubmatic.com/*",
    "*://simage2.pubmatic.com/*",
    "*://ib.adnxs.com/*",
    "*://acdn.adnxs.com/*",
    "*://amazon-adsystem.com/*",
    "*://s.amazon-adsystem.com/*",
    "*://openx.net/*",
    "*://*.openx.net/*",
    "*://prebid.adnxs.com/*",
    "*://rubiconproject.com/*",
    "*://*.rubiconproject.com/*",
    "*://fastlane.rubiconproject.com/*",
    "*://pixel.adsafeprotected.com/*",
    "*://dt.adsafeprotected.com/*",
    "*://cdn.siftscience.com/*",
    "*://amplitude.com/*",
    "*://*.amplitude.com/*",
    "*://api2.amplitude.com/*",
    "*://region1.analytics.google.com/*",
    "*://analytics.google.com/*",
    "*://www.google-analytics.com/*",
    "*://ssl.google-analytics.com/*",
    "*://science.v2.iesdev.com/*",
    "*://sentry.blitz.gg/*",
    "*://sentry.io/*",
    "*://*.sentry.io/*",
    "*://locize.io/*",
    "*://*.locize.io/*",
    "*://locize.com/*",
  ];
  window.webContents.session.webRequest.onBeforeRequest(
    { urls: AD_BLOCK_PATTERNS },
    (_details, callback) => callback({ cancel: true })
  );
"""
    marker = "  // Some CORS workarounds :)"
    if marker in code:
        code = code.replace(marker, block + "\n" + marker)
    else:
        warn("Could not find insertion point — ad blocking may be incomplete")

    _write(path, code)
    ok("electronWindowHandlers.js — ad/telemetry requests blocked at session layer")


def patch_create_window(src):
    """
    createWindow.js — force premium window size
    ─────────────────────────────────────────────
    Originally the app sets DEFAULT_WIDTH=1420, DEFAULT_HEIGHT=850
    (sized to fit ads). After window creation it calls fetchUser()
    asynchronously: if the user has a premium role, the minimum size
    is reduced to 940×500; otherwise it stays at the larger ad-friendly
    dimensions and any existing window smaller than that is forced to
    resize.

    Patch:
      1. Rewrite DEFAULT_WIDTH/HEIGHT constants to 940/500 so the
         initial window is created at premium dimensions.
      2. Replace the fetchUser().then() callback body with a static
         assignment of the premium dimensions so the async handler
         also sets premium sizing regardless of the real role.
    """
    path = os.path.join(src, "createWindow.js")
    with open(path, 'r', encoding='utf-8') as f:
        code = f.read()

    code = code.replace("const DEFAULT_WIDTH = 1420;",
                        "const DEFAULT_WIDTH = 940; // PATCHED: premium size")
    code = code.replace("const DEFAULT_HEIGHT = 850;",
                        "const DEFAULT_HEIGHT = 500; // PATCHED: premium size")

    # Replace the fetchUser().then((user) => { ... }); block
    rx = re.compile(
        r'fetchUser\(\)\.then\(\(user\) =>.*?windows\.client\.setMinimumSize\(MIN_WIDTH, MIN_HEIGHT\);\s*\}\s*\}\);',
        re.DOTALL
    )
    replacement = (
        "// PATCHED: hardcode premium window dimensions\n"
        "  MIN_WIDTH = 940; MIN_HEIGHT = 500;\n"
        '  write("MIN_WIDTH", MIN_WIDTH); write("MIN_HEIGHT", MIN_HEIGHT);\n'
        "  windows.client.setMinimumSize(MIN_WIDTH, MIN_HEIGHT);"
    )
    new_code, n = rx.subn(replacement, code)
    if n == 0:
        warn("createWindow.js: fetchUser block not found — constants patch still applied")
        new_code = code
    else:
        ok("createWindow.js — fetchUser() size gate replaced with premium dims")

    _write(path, new_code)


def patch_blitz_entry(src):
    """
    blitz-entry.js — disable Chromium ads API & auto-start
    ────────────────────────────────────────────────────────
    The entry point appends a Chromium command-line switch
    --enable-privacy-sandbox-ads-apis which enables the Topics API,
    a browser-based ad targeting mechanism.

    It also calls addAutoStartOnFirstRun() which registers Blitz as a
    Windows startup application on first launch via the registry.

    Patch: Comment out both.
    """
    path = os.path.join(src, "blitz-entry.js")
    with open(path, 'r', encoding='utf-8') as f:
        code = f.read()

    code = code.replace(
        'app.commandLine.appendSwitch("enable-privacy-sandbox-ads-apis");',
        '// PATCHED: Topics API / Privacy Sandbox ads disabled\n'
        '// app.commandLine.appendSwitch("enable-privacy-sandbox-ads-apis");'
    )
    code = code.replace(
        "addAutoStartOnFirstRun();",
        "// PATCHED: auto-start registration disabled\n  // addAutoStartOnFirstRun();"
    )
    _write(path, code)
    ok("blitz-entry.js — Topics API and auto-start registration disabled")


def patch_asar():
    step("PATCH 2 — app.asar (ASAR extract → JS patch → repack)")
    backup(ASAR_PATH)

    # Back up original unpacked dir
    unpacked_src = ASAR_PATH + ".unpacked"
    unpacked_bak = os.path.join(BACKUP_DIR, "app.asar.unpacked")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    if os.path.exists(unpacked_src) and not os.path.exists(unpacked_bak):
        shutil.copytree(unpacked_src, unpacked_bak)
        ok("Backed up app.asar.unpacked/")

    if os.path.exists(WORK_DIR):
        shutil.rmtree(WORK_DIR)
    os.makedirs(WORK_DIR, exist_ok=True)

    r = run("npx --yes @electron/asar --version", check=False)
    if r.returncode != 0:
        die("@electron/asar not available — install Node.js and try again")
    ok(f"@electron/asar available")

    # Always extract from the ORIGINAL backup — prevents cumulative re-patching
    orig_asar = os.path.join(BACKUP_DIR, "app.asar")
    if not os.path.exists(orig_asar):
        die(f"Original ASAR backup not found at {orig_asar}")
    log(f"Extracting original ASAR → {EXTRACT_DIR}")
    run(f'npx @electron/asar extract "{orig_asar}" "{EXTRACT_DIR}"')
    ok("Original ASAR extracted")

    src = os.path.join(EXTRACT_DIR, "src")
    patch_auth(src)
    patch_autoupdater(src)
    patch_crash_reporter(src)
    patch_ota(src)
    patch_window_handlers(src)
    patch_create_window(src)
    patch_blitz_entry(src)

    # Repack with --unpack "{*.node,*.dll}"
    # *.node — native addons must be real filesystem paths (dlopen requirement)
    # *.dll  — companion DLLs like liblzma.dll must sit next to their .node file
    #          so Windows LoadLibrary() can find them via DLL search order
    log("Repacking with --unpack '{*.node,*.dll}'")
    run(f'npx @electron/asar pack "{EXTRACT_DIR}" "{REPACK_ASAR}" --unpack "{{*.node,*.dll}}"')
    ok("ASAR repacked")

    # Kill Blitz before installing — native .node files in app.asar.unpacked
    # are locked by the running process; rmtree will fail with WinError 5 otherwise.
    kill_blitz()

    shutil.copy2(REPACK_ASAR, ASAR_PATH)
    ok(f"Installed → {ASAR_PATH}")

    repack_unpacked = REPACK_ASAR + ".unpacked"
    install_unpacked = ASAR_PATH + ".unpacked"
    if os.path.exists(repack_unpacked):
        if os.path.exists(install_unpacked):
            shutil.rmtree(install_unpacked)
        shutil.copytree(repack_unpacked, install_unpacked)
        ok(f"Installed app.asar.unpacked/ → {install_unpacked}")
    else:
        warn("No .unpacked dir generated — native modules may fail to load!")


# ══════════════════════════════════════════════════════════════════
# PATCH 3 — .env.production
# ══════════════════════════════════════════════════════════════════
#
# The app loads this file with dotenv at startup. It contains DSNs
# (Data Source Names) for Sentry crash reporting and the Locize
# localisation API key. Clearing these prevents the app from
# sending crash/error events even if the crashReporter patch is
# somehow bypassed, and stops i18n key telemetry.
# ─────────────────────────────────────────────────────────────────

def patch_env():
    step("PATCH 3 — .env.production (clear telemetry DSNs)")
    backup(ENV_FILE)
    with open(ENV_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    out = []
    CLEAR = {"SENTRY_DSN", "SENTRY_MINIDUMP_DSN", "REACT_APP_LOCIZE_API_KEY"}
    for line in lines:
        key = line.split("=")[0]
        if key in CLEAR:
            out.append(f"{key}=\n")
            log(f"Cleared: {key}")
        else:
            out.append(line)
    with open(ENV_FILE, 'w', encoding='utf-8') as f:
        f.writelines(out)
    ok("Sentry DSNs and Locize API key cleared")


# ══════════════════════════════════════════════════════════════════
# PATCH 4 — app-update.yml
# ══════════════════════════════════════════════════════════════════
#
# electron-updater reads this file to determine the update feed URL.
# The original points to theblitzapp/blitz-core on GitHub. Replacing
# the provider with "generic" and the URL with localhost:0 ensures
# the updater can never resolve a valid feed even if the JS patch is
# somehow reverted. Belt-and-suspenders.
# ─────────────────────────────────────────────────────────────────

def patch_update_yml():
    step("PATCH 4 — app-update.yml (disable update feed)")
    backup(UPDATE_YML)
    with open(UPDATE_YML, 'w', encoding='utf-8') as f:
        f.write("# PATCHED: update feed disabled\nprovider: generic\nurl: http://localhost:0\n")
    ok("Update feed pointed to localhost:0 (unreachable)")


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

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

    print("\n" + "=" * 60)
    print("  Done! All patches applied.")
    print()
    print("  [1] blitz_core.node — integrity checker bypassed")
    print("  [2] app.asar        — 6 JS patches applied")
    print("  [3] .env.production — Sentry DSNs cleared")
    print("  [4] app-update.yml  — update feed disabled")
    print()
    print(f"  Backups: {BACKUP_DIR}")
    print("  Restore: python patch.py --restore")
    print("=" * 60)


if __name__ == "__main__":
    main()
