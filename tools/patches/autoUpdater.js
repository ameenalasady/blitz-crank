// EDUCATIONAL PATCH — autoUpdater/index.js
// electron-updater normally polls the GitHub releases feed defined in
// app-update.yml, downloads delta patches, verifies SHA-256 checksums,
// and applies them by spawning the installer binary. Replaced with stubs.

const log = require("npmlog");
function init()               { log.info("[Updater] PATCHED: disabled."); }
function checkForUpdates()    { return Promise.resolve(); }
async function bootApp()      { return Promise.resolve(); }
function closeUpdaterWindow() { return Promise.resolve(); }
module.exports = { init, checkForUpdates, bootApp, closeUpdaterWindow };
