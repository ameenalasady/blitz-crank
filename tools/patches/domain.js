// EDUCATIONAL PATCH — util/domain.js
// Original: fetches cloudflare.com/cdn-cgi/trace to geolocate, then routes
// traffic using CRC32(machineID) % 100 as an A/B bucket across 5 domains.
// Patch: always return "probuilds.net" — no network call, no fingerprinting.

const log = require("npmlog");
const MAIN_DOMAIN = { hostname: "probuilds.net" };

async function getDomain(_version) {
  return MAIN_DOMAIN.hostname;
}

module.exports = { getDomain, MAIN_DOMAIN };
