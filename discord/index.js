/**
 * UPDATED CLOUDFLARE WORKER SCRIPT FOR DISCORD OBSERVER
 * 
 * Key modifications made:
 * 1. Added CORS headers ("Access-Control-Allow-Origin: *", etc.) to all /api responses
 *    so any external static web app can fetch Discord user & server data without browser CORS blocking.
 * 2. Added HTTP OPTIONS preflight handling returning 204 No Content with CORS headers.
 * 3. Added /api/batch endpoint to support resolving multiple IDs simultaneously in a single HTTP request.
 * 4. Preserved all existing Discord lookup functionality, snowflake decoding, invite resolvers, and HTML viewer.
 */

const DISCORD_API = "https://discord.com/api/v10";
const DISCORD_EPOCH = 1420070400000n;

const requestBuckets = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 60; // Increased limit for multi-card viewers

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, Authorization, X-Requested-With",
  "Access-Control-Max-Age": "86400"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      ...corsHeaders
    }
  });
}

function decodeSnowflake(id) {
  const value = BigInt(id);
  const timestamp = Number((value >> 22n) + DISCORD_EPOCH);
  return {
    id,
    timestamp,
    iso: new Date(timestamp).toISOString(),
    worker: Number((value >> 17n) & 31n),
    process: Number((value >> 12n) & 31n),
    increment: Number(value & 4095n)
  };
}

function validSnowflake(value) {
  return typeof value === "string" && /^\d{17,20}$/.test(value) && BigInt(value) > 0n && BigInt(value) <= 18446744073709551615n;
}

function parseTarget(input) {
  let raw = String(input || "").trim();
  if (!raw || raw.length > 500) return { error: "Enter a Discord ID, profile link, message link, or invite." };

  const messageMatch = raw.match(/^https?:\/\/(?:canary\.|ptb\.)?(?:discord\.com|discordapp\.com)\/channels\/(?:@me|(\d{17,20}))\/(\d{17,20})\/(\d{17,20})(?:[?#].*)?$/i);
  if (messageMatch) {
    return {
      type: "message",
      guildId: messageMatch[1] || null,
      channelId: messageMatch[2],
      id: messageMatch[3]
    };
  }

  const channelMatch = raw.match(/^https?:\/\/(?:canary\.|ptb\.)?(?:discord\.com|discordapp\.com)\/channels\/(?:@me|(\d{17,20}))\/(\d{17,20})(?:[?#].*)?$/i);
  if (channelMatch) {
    return {
      type: "channel",
      guildId: channelMatch[1] || null,
      id: channelMatch[2]
    };
  }

  const userMatch = raw.match(/^https?:\/\/(?:canary\.|ptb\.)?(?:discord\.com|discordapp\.com)\/users\/(\d{17,20})(?:[?#].*)?$/i);
  if (userMatch) {
    return {
      type: "user",
      id: userMatch[1]
    };
  }

  const inviteUrlMatch = raw.match(/^(?:https?:\/\/)?(?:www\.)?(?:discord\.gg\/|discord(?:app)?\.com\/invite\/)([a-z0-9_-]{2,32})(?:[?#].*)?$/i);
  if (inviteUrlMatch) {
    return { type: "invite", code: inviteUrlMatch[1] };
  }

  const inviteMatch = raw.match(/^(?:https?:\/\/(?:www\.)?(?:discord\.gg|discord\.com\/invite|discordapp\.com\/invite)\/)?([a-z0-9_-]{2,32})$/i);
  if (inviteMatch && !/^\d{17,20}$/.test(raw)) {
    const candidate = inviteMatch[1];
    if (!/^(?:https?:|<@|<#)/i.test(raw) && !/^\d+$/.test(candidate)) {
      return { type: "invite", code: candidate };
    }
  }

  const emojiMatch = raw.match(/^<(a)?:([a-zA-Z0-9_]{2,32}):(\d{17,20})>$/);
  if (emojiMatch) {
    return {
      type: "emoji",
      animated: Boolean(emojiMatch[1]),
      name: emojiMatch[2],
      id: emojiMatch[3]
    };
  }

  const rolePair = raw.match(/^(\d{17,20})\/(\d{17,20})$/);
  if (rolePair) return { type: "role", guildId: rolePair[1], id: rolePair[2] };

  const mention = raw.match(/^<(@!?|#|@&)(\d{17,20})>$/);
  if (mention) {
    if (mention[1] === "#") return { type: "channel", id: mention[2] };
    if (mention[1] === "@&") return { type: "role-context-missing", id: mention[2] };
    return { type: "user", id: mention[2] };
  }

  if (validSnowflake(raw)) return { type: "auto", id: raw };
  return { error: "That is not a valid Discord ID, supported link, or mention." };
}

async function discordGet(path, token) {
  let response;
  try {
    response = await fetch(DISCORD_API + path, {
      method: "GET",
      headers: {
        "Authorization": "Bot " + token,
        "Accept": "application/json",
        "User-Agent": "Discord-ID-Viewer (Cloudflare Worker)"
      },
      signal: AbortSignal.timeout(9000)
    });
  } catch (error) {
    return { ok: false, status: 0, error: "Discord API connection failed or timed out." };
  }

  const text = await response.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); }
    catch { data = { message: text.slice(0, 300) }; }
  }
  return { ok: response.ok, status: response.status, data, retryAfter: response.headers.get("Retry-After") };
}

function rateAllowed(request) {
  const key = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = Date.now();
  const bucket = requestBuckets.get(key);

  if (!bucket || now - bucket.started >= RATE_WINDOW_MS) {
    requestBuckets.set(key, { started: now, count: 1 });
    if (requestBuckets.size > 2000) {
      for (const [ip, value] of requestBuckets) {
        if (now - value.started >= RATE_WINDOW_MS) requestBuckets.delete(ip);
      }
    }
    return true;
  }

  if (bucket.count >= RATE_LIMIT) return false;
  bucket.count += 1;
  return true;
}

function safeUser(user) {
  const fields = [
    "id", "username", "global_name", "discriminator", "avatar", "banner",
    "accent_color", "public_flags", "flags", "bot", "system",
    "avatar_decoration_data", "collectibles", "primary_guild", "premium_type"
  ];
  const clean = {};
  for (const key of fields) {
    if (Object.prototype.hasOwnProperty.call(user || {}, key)) clean[key] = user[key];
  }
  return clean;
}

async function lookup(input, token) {
  const target = parseTarget(input);
  if (target.error) return { status: 400, body: { ok: false, error: target.error } };

  const snowflakeId = target.id || target.channelId || null;
  const snowflake = snowflakeId && validSnowflake(snowflakeId) ? decodeSnowflake(snowflakeId) : null;

  if (target.type === "emoji") {
    const ext = target.animated ? "gif" : "png";
    return {
      status: 200,
      body: {
        ok: true,
        kind: "emoji",
        data: {
          id: target.id,
          name: target.name,
          animated: target.animated,
          url: `https://cdn.discordapp.com/emojis/${target.id}.${ext}?size=256`
        },
        snowflake
      }
    };
  }

  if (!token) {
    return {
      status: 200,
      body: {
        ok: true,
        kind: "snowflake",
        targetType: target.type,
        snowflake,
        error: "Add the DISCORD_BOT_TOKEN Worker secret to enable live Discord lookups."
      }
    };
  }

  if (target.type === "role-context-missing") {
    return {
      status: 200,
      body: {
        ok: true,
        kind: "snowflake",
        targetType: "role",
        snowflake,
        error: "A role lookup also needs its server ID. Enter GUILD_ID/ROLE_ID."
      }
    };
  }

  if (target.type === "invite") {
    const result = await discordGet("/invites/" + encodeURIComponent(target.code) + "?with_counts=true&with_expiration=true", token);
    if (result.ok) return { status: 200, body: { ok: true, kind: "invite", data: result.data } };
    return apiFailure(result, "Could not resolve this invite.");
  }

  if (target.type === "message") {
    const channel = await discordGet("/channels/" + target.channelId, token);
    if (!channel.ok) return apiFailure(channel, "The bot cannot access this channel (verify permissions).");
    const message = await discordGet("/channels/" + target.channelId + "/messages/" + target.id, token);
    if (!message.ok) return apiFailure(message, "The bot cannot read this message (verify bot is in the server with Read Message History).");
    return {
      status: 200,
      body: {
        ok: true,
        kind: "message",
        data: message.data,
        channel: channel.data,
        guildId: target.guildId,
        snowflake: decodeSnowflake(target.id)
      }
    };
  }

  if (target.type === "channel") {
    const channel = await discordGet("/channels/" + target.id, token);
    if (channel.ok) return { status: 200, body: { ok: true, kind: "channel", data: channel.data, snowflake } };
    return apiFailure(channel, "The bot cannot access this channel (ensure bot is in the server with View Channel permission).", snowflake);
  }

  if (target.type === "role") {
    const roles = await discordGet("/guilds/" + target.guildId + "/roles", token);
    if (!roles.ok) return apiFailure(roles, "The bot cannot read roles in that server (ensure bot is a member).");
    const role = Array.isArray(roles.data) ? roles.data.find(item => item.id === target.id) : null;
    if (!role) return { status: 404, body: { ok: false, error: "Role not found in that server.", snowflake } };
    const guild = await discordGet("/guilds/" + target.guildId + "?with_counts=true", token);
    return {
      status: 200,
      body: { ok: true, kind: "role", data: role, guild: guild.ok ? guild.data : null, snowflake: decodeSnowflake(target.id) }
    };
  }

  if (target.type === "user") {
    const user = await discordGet("/users/" + target.id, token);
    if (user.ok) return { status: 200, body: { ok: true, kind: "user", data: safeUser(user.data), snowflake } };
    return apiFailure(user, "Could not retrieve this user.", snowflake);
  }

  const user = await discordGet("/users/" + target.id, token);
  if (user.ok) return { status: 200, body: { ok: true, kind: "user", data: safeUser(user.data), snowflake } };
  if (user.status === 401 || user.status === 429 || user.status === 0) return apiFailure(user, "Discord API lookup failed.", snowflake);

  const guild = await discordGet("/guilds/" + target.id + "?with_counts=true", token);
  if (guild.ok) return { status: 200, body: { ok: true, kind: "guild", data: guild.data, snowflake } };
  if (guild.status === 401 || guild.status === 429 || guild.status === 0) return apiFailure(guild, "Discord API lookup failed.", snowflake);

  const channel = await discordGet("/channels/" + target.id, token);
  if (channel.ok) return { status: 200, body: { ok: true, kind: "channel", data: channel.data, snowflake } };
  if (channel.status === 401 || channel.status === 429 || channel.status === 0) return apiFailure(channel, "Discord API lookup failed.", snowflake);

  return {
    status: 404,
    body: {
      ok: false,
      error: "No accessible user, server, or channel matched this ID.",
      snowflake,
      api: { user: user.status, guild: guild.status, channel: channel.status }
    }
  };
}

function apiFailure(result, fallback, snowflake = null) {
  if (result.status === 401) {
    return { status: 502, body: { ok: false, error: "The configured bot token was rejected. Check DISCORD_BOT_TOKEN.", snowflake } };
  }
  if (result.status === 429) {
    return { status: 429, body: { ok: false, error: "Discord rate limit reached. Try again shortly.", retryAfter: result.retryAfter, snowflake } };
  }
  if (result.status === 0) {
    return { status: 502, body: { ok: false, error: result.error || fallback, snowflake } };
  }
  if (result.status === 403) {
    return { status: 403, body: { ok: false, error: "The bot does not have permission to view this Discord resource.", snowflake } };
  }
  return { status: result.status || 502, body: { ok: false, error: fallback, snowflake } };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. CORS Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    if (url.pathname === "/favicon.ico") return new Response(null, { status: 204 });

    // 2. Batch lookup endpoint
    if (url.pathname === "/api/batch") {
      if (request.method !== "GET") return json({ ok: false, error: "Method not allowed." }, 405);
      if (!rateAllowed(request)) return json({ ok: false, error: "Too many lookups. Try again in a minute." }, 429);

      const rawIds = url.searchParams.get("ids") || "";
      const ids = rawIds.split(/[\s,]+/).map(s => s.trim()).filter(Boolean).slice(0, 12);
      const results = await Promise.all(ids.map(id => lookup(id, env.DISCORD_BOT_TOKEN || "")));
      return json({ ok: true, results: results.map(r => r.body) });
    }

    // 3. Single lookup endpoint
    if (url.pathname === "/api/lookup") {
      if (request.method !== "GET") return json({ ok: false, error: "Method not allowed." }, 405);
      if (!rateAllowed(request)) return json({ ok: false, error: "Too many lookups. Try again in a minute." }, 429);
      
      let query = url.searchParams.get("q") || url.searchParams.get("id") || "";
      if (!query && url.search && url.search.length > 1) {
        const raw = url.search.slice(1).trim();
        if (!raw.includes("=")) {
          query = decodeURIComponent(raw);
        } else {
          const firstKey = url.searchParams.keys().next().value;
          if (firstKey && !url.searchParams.get(firstKey)) query = decodeURIComponent(firstKey);
        }
      }

      const result = await lookup(query, env.DISCORD_BOT_TOKEN || "");
      return json(result.body, result.status);
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed", { status: 405, headers: { "Allow": "GET, HEAD, OPTIONS" } });
    }

    // Return status info for index or root request
    return json({
      ok: true,
      service: "Discord Observer Cloudflare Worker",
      endpoints: ["/api/lookup?q={id}", "/api/batch?ids={id1,id2}"],
      cors: "enabled"
    });
  }
};
