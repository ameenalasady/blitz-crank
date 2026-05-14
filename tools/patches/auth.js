// EDUCATIONAL PATCH — auth.js
// fetchUser() returns a hardcoded PRO_SUBSCRIBER user object instead of
// making a GraphQL POST to auth.blitz.gg. hasPremiumRole() always returns
// true. The token read/write API is preserved so the app can still log in
// and out without errors.

const { write, get } = require("./db");
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

// PATCHED: no auth server call — hardcoded premium role
async function fetchUser() {
  return { name: "PremiumUser", roles: [{ code: "PRO_SUBSCRIBER" }] };
}

// PATCHED: always premium
function hasPremiumRole(_roles) { return true; }

module.exports = { saveToken, getToken, fetchUser, hasPremiumRole, addTokenListener };
