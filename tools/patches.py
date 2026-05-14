"""
Blitz Crank — Patch Registry
=============================
This is the ONLY file you need to edit to add, remove, or modify JS patches.

Each entry in PATCHES is a dict describing one atomic operation. The engine
in patch.py reads this list and applies each patch generically.

Operation types
---------------
  rewrite      — replace the entire target file with the content of a .js
                 file from the patches/ directory
  inject       — insert a snippet from a .js file immediately before a marker
                 string in the target file (idempotent via a guard string)
  replace      — single str.replace(find, replace) on the target file
  replace_many — ordered list of replace/regex sub-operations on one file

All "file" paths are relative to the extracted ASAR src/ directory.
All "src"  paths are relative to the tools/ directory (i.e. patches/<name>.js).
"""

import re  # only for flag constants — no logic here

PATCHES = [

    # ══════════════════════════════════════════════════════════════════════════
    # Full file rewrites
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id":   "auth",
        "desc": "fetchUser() returns hardcoded PRO_SUBSCRIBER; hasPremiumRole() always true",
        "file": "auth.js",
        "op":   "rewrite",
        "src":  "patches/auth.js",
    },
    {
        "id":   "autoUpdater",
        "desc": "All electron-updater functions replaced with no-ops",
        "file": "autoUpdater/index.js",
        "op":   "rewrite",
        "src":  "patches/autoUpdater.js",
    },
    {
        "id":   "crashReporter",
        "desc": "Sentry crash reporter and native minidump handler disabled",
        "file": "crashReporter.js",
        "op":   "rewrite",
        "src":  "patches/crashReporter.js",
    },
    {
        "id":   "ota",
        "desc": "OTA version check returns bundled package.json version; no network call",
        "file": "ota.js",
        "op":   "rewrite",
        "src":  "patches/ota.js",
    },
    {
        "id":   "domain",
        "desc": "Geo fingerprinting + A/B domain routing replaced with static probuilds.net",
        "file": "util/domain.js",
        "op":   "rewrite",
        "src":  "patches/domain.js",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Code injection
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id":    "adblock",
        "desc":  "Cancel 30+ ad/telemetry domains at the Electron session layer",
        "file":  "electronWindowHandlers.js",
        "op":    "inject",
        # Injected immediately before this line in the original source.
        # If you need to target a different version of the app, update this marker.
        "marker": "  // Some CORS workarounds :)",
        "src":   "patches/ad_block.js",
        # Idempotency guard: if this string is already in the file, skip.
        "guard": "AD_BLOCK_PATTERNS",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Multi-operation patches (applied in order to the same file)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id":   "createWindow",
        "desc": "Force 940×500 premium dimensions — all 3 MIN_WIDTH/HEIGHT gates",
        "file": "createWindow.js",
        "op":   "replace_many",
        "ops":  [
            # Gate 1: module-level constants
            {
                "find":    "const DEFAULT_WIDTH = 1420;",
                "replace": "const DEFAULT_WIDTH = 940; // PATCHED: premium size",
            },
            {
                "find":    "const DEFAULT_HEIGHT = 850;",
                "replace": "const DEFAULT_HEIGHT = 500; // PATCHED: premium size",
            },
            # Gate 2: LevelDB reads in createWindow() that restore stale free-user
            # values on every subsequent launch (root cause of intermittent failures)
            {
                "find":    '  MIN_WIDTH = (await get("MIN_WIDTH")) || MIN_WIDTH;',
                "replace": '  MIN_WIDTH = 940; // PATCHED: ignore stale DB value',
            },
            {
                "find":    '  MIN_HEIGHT = (await get("MIN_HEIGHT")) || MIN_HEIGHT;',
                "replace": '  MIN_HEIGHT = 500; // PATCHED: ignore stale DB value',
            },
            # Gate 3: fetchUser().then() block that runs post-creation and
            # writes the free-user MIN values back to LevelDB for next launch
            {
                "op":      "regex",
                "pattern": (
                    r'fetchUser\(\)\.then\(\(user\) =>'
                    r'.*?windows\.client\.setMinimumSize\(MIN_WIDTH, MIN_HEIGHT\);'
                    r'\s*\}\s*\}\);'
                ),
                "flags":   re.DOTALL,
                "replace": (
                    "// PATCHED: hardcode premium window dimensions\n"
                    "  MIN_WIDTH = 940; MIN_HEIGHT = 500;\n"
                    '  write("MIN_WIDTH", MIN_WIDTH); write("MIN_HEIGHT", MIN_HEIGHT);\n'
                    "  windows.client.setMinimumSize(MIN_WIDTH, MIN_HEIGHT);"
                ),
            },
        ],
    },
    {
        "id":   "blitz_entry",
        "desc": "Disable Topics API, auto-start registration, and machineID file write",
        "file": "blitz-entry.js",
        "op":   "replace_many",
        "ops":  [
            # Topics API (Chromium Privacy Sandbox / FLoC successor)
            {
                "find": 'app.commandLine.appendSwitch("enable-privacy-sandbox-ads-apis");',
                "replace": (
                    "// PATCHED: Topics API / Privacy Sandbox ads disabled\n"
                    '// app.commandLine.appendSwitch("enable-privacy-sandbox-ads-apis");'
                ),
            },
            # Automatic Windows startup registration
            {
                "find":    "addAutoStartOnFirstRun();",
                "replace": "// PATCHED: auto-start registration disabled\n  // addAutoStartOnFirstRun();",
            },
            # Hardware fingerprint written to %APPDATA%/.machineId on every launch
            {
                "find": (
                    "async function writeMachineID() {\n"
                    "  try {\n"
                    "    const machineId = getMachineID();\n"
                    '    const machineIDFile = path.join(app.getPath("appData"), ".machineId");\n'
                    "    await fse.writeFile(machineIDFile, machineId);\n"
                    "  } catch (err) {\n"
                    '    log.error("Error: ", err);\n'
                    "  }\n"
                    "}"
                ),
                "replace": (
                    "// PATCHED: hardware fingerprint file write disabled\n"
                    "async function writeMachineID() {\n"
                    "  // no-op: .machineId not written to disk\n"
                    "}"
                ),
            },
        ],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Single-replacement patches
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id":   "pinApp",
        "desc": "Prevent PinManager.exe from silently pinning Blitz to the taskbar",
        "file": "pinApp/index.js",
        "op":   "replace",
        # Replace only the module.exports — the rest of the file (savePinState,
        # createShortcut, etc.) is left intact so nothing else breaks.
        "find": (
            "module.exports = {\n"
            "  init,\n"
            "  savePinState,\n"
            "};"
        ),
        "replace": (
            "// PATCHED: init() replaced with no-op — PinManager.exe not spawned\n"
            "async function _init_noop() {}\n"
            "module.exports = {\n"
            "  init: _init_noop,\n"
            "  savePinState,\n"
            "};"
        ),
    },
]
