// EDUCATIONAL PATCH — crashReporter.js
// Originally calls Electron's crashReporter.start() with the Sentry minidump
// DSN from .env.production, registering a system-level crash handler that
// uploads minidumps to Sentry. Also calls blitz_core.node's InitCrashHandler()
// to register a native dump writer to %TEMP%/blitz/.
// Replaced with a no-op. .env.production DSNs are also cleared separately.

const log = require("npmlog");
async function setupCrashHandler() {
  log.info("[CrashReporter] PATCHED: disabled.");
}
module.exports = { setupCrashHandler };
