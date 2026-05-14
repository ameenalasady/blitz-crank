
  // EDUCATIONAL PATCH: cancel ad/telemetry requests at the session layer
  // Operates at the Electron webRequest level — runs before a TCP connection
  // is opened. Note: patterns use Chrome extension match syntax. Wildcard TLDs
  // (*://host.*/) are invalid — only subdomain wildcards (*://*.host.com/) work.
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
