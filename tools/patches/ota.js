// EDUCATIONAL PATCH — ota.js
// A secondary update mechanism (distinct from electron-updater) that polls
// utils.iesdev.com to determine which version of the remote web app to load
// inside the BrowserView. Stores the resolved version in LevelDB and uses it
// to build the probuilds.net/v{version} URL on next launch.
// Replaced: return the bundled package.json version with zero network calls.

const log = require("npmlog");
const ota = {
  checkForUpdates: async () => {},
  pollForUpdates:  () => {},
  getVersion:      async () => require("../package.json").version,
};
module.exports = ota;
