const DISCORD_API = "https://discord.com/api/v10";
const DISCORD_EPOCH = 1420070400000n;

// Best-effort per-isolate throttle. Add a Cloudflare WAF rate-limit rule for
// durable, global protection on a public deployment.
const requestBuckets = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 30;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer"
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

  // Discord message links: channels/guildId/@me/channelId/messageId
  const messageMatch = raw.match(/^https?:\/\/(?:canary\.|ptb\.)?(?:discord\.com|discordapp\.com)\/channels\/(?:@me|(\d{17,20}))\/(\d{17,20})\/(\d{17,20})(?:[?#].*)?$/i);
  if (messageMatch) {
    return {
      type: "message",
      guildId: messageMatch[1] || null,
      channelId: messageMatch[2],
      id: messageMatch[3]
    };
  }

  // Discord channel links: channels/guildId/@me/channelId
  const channelMatch = raw.match(/^https?:\/\/(?:canary\.|ptb\.)?(?:discord\.com|discordapp\.com)\/channels\/(?:@me|(\d{17,20}))\/(\d{17,20})(?:[?#].*)?$/i);
  if (channelMatch) {
    return {
      type: "channel",
      guildId: channelMatch[1] || null,
      id: channelMatch[2]
    };
  }

  // Discord user profile links: discord.com/users/USER_ID
  const userMatch = raw.match(/^https?:\/\/(?:canary\.|ptb\.)?(?:discord\.com|discordapp\.com)\/users\/(\d{17,20})(?:[?#].*)?$/i);
  if (userMatch) {
    return {
      type: "user",
      id: userMatch[1]
    };
  }

  // Invite links with graceful auto-removal of discord.gg, https://discord.gg, discord.com/invite
  const inviteUrlMatch = raw.match(/^(?:https?:\/\/)?(?:www\.)?(?:discord\.gg\/|discord(?:app)?\.com\/invite\/)([a-z0-9_-]{2,32})(?:[?#].*)?$/i);
  if (inviteUrlMatch) {
    return { type: "invite", code: inviteUrlMatch[1] };
  }

  // Raw invite code candidate
  const inviteMatch = raw.match(/^(?:https?:\/\/(?:www\.)?(?:discord\.gg|discord\.com\/invite|discordapp\.com\/invite)\/)?([a-z0-9_-]{2,32})$/i);
  if (inviteMatch && !/^\d{17,20}$/.test(raw)) {
    const candidate = inviteMatch[1];
    if (!/^(?:https?:|<@|<#)/i.test(raw) && !/^\d+$/.test(candidate)) {
      return { type: "invite", code: candidate };
    }
  }

  // Custom emoji format: <:name:id> or <a:name:id>
  const emojiMatch = raw.match(/^<(a)?:([a-zA-Z0-9_]{2,32}):(\d{17,20})>$/);
  if (emojiMatch) {
    return {
      type: "emoji",
      animated: Boolean(emojiMatch[1]),
      name: emojiMatch[2],
      id: emojiMatch[3]
    };
  }

  // Role context format: GUILD_ID/ROLE_ID
  const rolePair = raw.match(/^(\d{17,20})\/(\d{17,20})$/);
  if (rolePair) return { type: "role", guildId: rolePair[1], id: rolePair[2] };

  // Discord mentions
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
    if (requestBuckets.size > 1500) {
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

  // A raw snowflake does not identify its resource class. User resolution is
  // deliberately first because user profiles are the primary public lookup target.
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
      error: "No accessible user, server, or channel matched this ID. If this is a server or channel, ensure the bot is a member with access. A message ID alone is not enough; paste its full Discord message link.",
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

const PAGE = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#1e1f22">
<title>Discord ID</title>
<style>
:root{color-scheme:dark;--bg:#1e1f22;--panel:#111214;--panel2:#2b2d31;--text:#f2f3f5;--muted:#b5bac1;--subtle:#949ba4;--blurple:#5865f2;--line:#3f4147;--green:#23a559;--red:#ed4245}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font-family:Inter,"gg sans","Noto Sans",Arial,sans-serif}
body{min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:clamp(22px,7vh,72px) 16px 48px;background:radial-gradient(ellipse at 50% -15%,#343747 0,transparent 54%),var(--bg)}
.lookup{width:min(100%,480px);display:flex;gap:8px;align-items:center;position:relative;z-index:2;transition:width .45s cubic-bezier(.2,.8,.2,1),transform .45s}
.lookup input{min-width:0;flex:1;height:48px;border:1px solid #3d4048;border-radius:12px;background:#2b2d31;color:#f2f3f5;padding:0 16px;font-size:15px;outline:0;box-shadow:0 5px 20px #0002;transition:border-color .2s,box-shadow .2s}
.lookup input:focus{border-color:var(--blurple);box-shadow:0 0 0 3px #5865f233,0 5px 20px #0002}
.lookup input::placeholder{color:#9298a2}
.lookup button{width:48px;height:48px;flex:0 0 48px;border:0;border-radius:12px;background:var(--blurple);color:white;font-size:23px;cursor:pointer;box-shadow:0 5px 18px #5865f244;transition:transform .18s,background .18s}
.lookup button:hover{background:#4752c4;transform:translateY(-1px)}
.lookup button:disabled{opacity:.55;cursor:wait;transform:none}
.status{width:min(100%,520px);min-height:18px;text-align:center;margin:10px 0 0;color:#aeb4bf;font-size:12px;line-height:1.45;overflow-wrap:anywhere}
.result{width:min(100%,340px);margin:22px auto 0;display:none;opacity:0;transform:translateY(16px) scale(.97);transform-origin:top center;transition:width .52s cubic-bezier(.2,.8,.2,1),border-radius .52s,transform .45s,opacity .35s;will-change:transform,width}
.result.visible{display:block;opacity:1;transform:translateY(0) scale(1);animation:materialize .48s cubic-bezier(.2,.85,.2,1) both}
@keyframes materialize{0%{clip-path:inset(10% 9% 10% 9% round 42px);filter:blur(5px)}100%{clip-path:inset(0 0 0 0 round 12px);filter:blur(0)}}
.result[data-type="user"]{width:min(100%,340px);border-radius:12px;background:#111214;overflow:hidden;box-shadow:0 18px 55px #0006}
.result[data-type="guild"]{width:min(100%,430px);border-radius:18px;background:#232428;overflow:hidden;box-shadow:0 18px 55px #0006}
.result[data-type="channel"]{width:min(100%,390px);border-radius:16px;background:#232428;overflow:hidden;box-shadow:0 18px 55px #0006}
.result[data-type="message"]{width:min(100%,520px);border-radius:18px;background:#232428;overflow:hidden;box-shadow:0 18px 55px #0006}
.result[data-type="role"],.result[data-type="invite"],.result[data-type="snowflake"],.result[data-type="emoji"]{width:min(100%,390px);border-radius:16px;background:#232428;overflow:hidden;box-shadow:0 18px 55px #0006}
.banner{height:120px;background:#5865f2 center/cover no-repeat;position:relative}
.banner a.banner-link{display:block;width:100%;height:100%;cursor:pointer;transition:background .18s;outline:none}
.banner a.banner-link:hover{background:rgba(255,255,255,.08)}
.banner-fallback-badge{position:absolute;top:10px;right:12px;display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:6px;background:rgba(0,0,0,.55);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);color:#f2f3f5;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:11px;font-weight:750;letter-spacing:.5px;border:1px solid rgba(255,255,255,.16);box-shadow:0 2px 6px rgba(0,0,0,.3);cursor:pointer;user-select:none;transition:background .18s,transform .15s,border-color .18s;z-index:1;outline:0}
.banner-fallback-badge:hover{background:rgba(0,0,0,.75);border-color:rgba(255,255,255,.3);transform:translateY(-1px)}
.banner-fallback-dot{width:9px;height:9px;border-radius:50%;border:1px solid rgba(255,255,255,.4);flex-shrink:0}
.avatar-wrap{position:absolute;left:16px;top:76px;width:80px;height:80px;border-radius:50%;padding:6px;background:#111214;z-index:2}
.avatar-link{display:block;width:100%;height:100%;border-radius:50%;position:relative;text-decoration:none;cursor:pointer;outline:none}
.avatar-wrap img.avatar{display:block;width:100%;height:100%;border-radius:50%;object-fit:cover;background:#36393f;transition:transform .18s,filter .18s}
.avatar-link:hover img.avatar{transform:scale(1.04);filter:brightness(1.1)}
.avatar-wrap img.decoration{position:absolute;inset:-6px;width:calc(100% + 12px);height:calc(100% + 12px);object-fit:contain;pointer-events:none;z-index:2}
.user-body{padding:48px 16px 18px;background:#111214}
.user-name-row{display:flex;align-items:center;gap:7px;flex-wrap:wrap;min-height:26px}
.user-name{font-size:20px;line-height:1.2;font-weight:750;letter-spacing:-.25px;overflow-wrap:anywhere}
.username{font-size:14px;color:#b5bac1;margin-top:3px;overflow-wrap:anywhere}
.guild-tag{display:inline-flex;align-items:center;gap:4px;padding:3px 7px;border-radius:5px;background:#292b30;color:#dbdee1;font-size:12px;font-weight:750;letter-spacing:.25px}
.guild-tag img{width:15px;height:15px;object-fit:contain}
.bot-mark,.premium-mark{font-size:10px;font-weight:800;line-height:16px;padding:0 5px;border-radius:4px;background:#5865f2;color:white;letter-spacing:.15px}
.section{border-top:1px solid #2b2d31;margin-top:16px;padding-top:13px}
.section:first-child{border-top:0;margin-top:0;padding-top:0}
.section-title{font-size:11px;line-height:1.2;color:#b5bac1;font-weight:800;letter-spacing:.55px;text-transform:uppercase;margin:0 0 9px}
.field{margin:0 0 11px;min-width:0}
.field:last-child{margin-bottom:0}
.field-label{font-size:11px;line-height:1.25;color:#9298a2;font-weight:750;text-transform:uppercase;letter-spacing:.35px}
.field-value{font-size:13px;line-height:1.45;color:#e3e5e8;margin-top:3px;overflow-wrap:anywhere;white-space:pre-wrap}
.field-value.muted{color:#9298a2}
.copy{appearance:none;border:0;padding:0;margin:0 0 0 5px;background:transparent;color:#9298a2;font:inherit;font-size:11px;cursor:pointer;vertical-align:1px}
.copy:hover{color:white}
.pills{display:flex;flex-wrap:wrap;gap:5px}
.pill{display:inline-flex;align-items:center;gap:5px;padding:4px 7px;border-radius:5px;background:#2b2d31;color:#e3e5e8;font-size:11px;font-weight:650;max-width:100%;overflow-wrap:anywhere}
.pill img{width:14px;height:14px;object-fit:contain}
.asset-row{display:flex;align-items:center;gap:10px;margin-top:9px;min-width:0;flex-wrap:wrap}
.asset-action-link{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:#00a8fc;text-decoration:none;font-weight:650;padding:6px 11px;background:#2b2d31;border-radius:6px;transition:background .18s,color .18s;margin-top:4px}
.asset-action-link:hover{background:#35373c;color:#fff}
.nameplate-card{position:relative;width:100%;border-radius:12px;overflow:hidden;background-position:center;background-size:cover;background-repeat:no-repeat;border:1px solid rgba(255,255,255,.14);box-shadow:0 4px 16px rgba(0,0,0,.35);margin-top:10px}
.nameplate-card::before{content:"";position:absolute;inset:0;background:linear-gradient(90deg,rgba(0,0,0,.45) 0%,rgba(0,0,0,.15) 100%);pointer-events:none}
.nameplate-inner{position:relative;z-index:1;display:flex;align-items:center;gap:12px;padding:10px 14px;min-height:56px}
.nameplate-avatar-wrap{position:relative;width:38px;height:38px;flex:0 0 38px;display:flex;align-items:center;justify-content:center;text-decoration:none;cursor:pointer;border-radius:50%}
.nameplate-avatar{width:32px;height:32px;border-radius:50%;object-fit:cover;display:block;background:#111214;transition:transform .18s,filter .18s}
.nameplate-avatar-wrap:hover .nameplate-avatar{transform:scale(1.06);filter:brightness(1.1)}
.nameplate-decoration{position:absolute;inset:0;width:100%;height:100%;object-fit:contain;pointer-events:none;z-index:2}
.nameplate-info{min-width:0;flex:1;display:flex;flex-direction:column;justify-content:center}
.nameplate-name-row{display:flex;align-items:center;gap:6px;flex-wrap:nowrap;overflow:hidden}
.nameplate-display-name{font-weight:750;font-size:14px;line-height:1.25;color:#fff;text-shadow:0 1px 3px rgba(0,0,0,.85);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nameplate-tag{display:inline-flex;align-items:center;gap:3px;padding:1px 5px;border-radius:4px;background:rgba(0,0,0,.55);backdrop-filter:blur(4px);color:#e3e5e8;font-size:11px;font-weight:750;border:1px solid rgba(255,255,255,.15);flex-shrink:0}
.nameplate-tag img{width:12px;height:12px;object-fit:contain}
.nameplate-handle{font-size:11px;line-height:1.2;color:rgba(255,255,255,.75);text-shadow:0 1px 2px rgba(0,0,0,.85);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.inviter-nameplate{display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:12px;background:#2b2d31;border:1px solid #3f4147;text-decoration:none;color:inherit;cursor:pointer;margin-top:6px;transition:background .18s,border-color .18s,transform .15s,box-shadow .18s;box-shadow:0 4px 12px rgba(0,0,0,.2)}
.inviter-nameplate:hover{background:#34373d;border-color:var(--blurple);transform:translateY(-1px);box-shadow:0 6px 18px rgba(0,0,0,.35)}
.inviter-arrow{margin-left:auto;font-size:15px;color:#9298a2;transition:color .18s,transform .18s;flex-shrink:0;padding-right:2px}
.inviter-nameplate:hover .inviter-arrow{color:#ffffff;transform:translate(2px,-2px)}
.entity-head{position:relative;min-height:118px;padding:23px 20px 18px;background:#36393f center/cover no-repeat}
.entity-head::before{content:"";position:absolute;inset:0;background:linear-gradient(90deg,#0009,#0002)}
.entity-head-link{position:absolute;inset:0;display:block;cursor:pointer;z-index:0;transition:background .18s}
.entity-head-link:hover{background:rgba(255,255,255,.06)}
.entity-icon-link{position:relative;z-index:1;display:inline-block;border-radius:18px}
.entity-icon-link:hover img{filter:brightness(1.08)}
.entity-title{position:relative;z-index:1;font-size:22px;font-weight:800;line-height:1.2;overflow-wrap:anywhere;text-shadow:0 2px 8px #0008}
.entity-subtitle{position:relative;z-index:1;font-size:12px;color:#e4e5e7;margin-top:7px;overflow-wrap:anywhere}
.entity-icon{position:relative;z-index:1;width:66px;height:66px;object-fit:cover;border-radius:18px;border:4px solid #232428;background:#2b2d31;margin-bottom:10px}
.entity-body{padding:17px 19px 19px}
.entity-body .section{border-color:#383a40}
.message-head{padding:16px 18px;border-bottom:1px solid #383a40;display:flex;gap:12px;align-items:center}
.message-author-avatar-link{display:block;width:42px;height:42px;border-radius:50%;flex:0 0 42px;cursor:pointer}
.message-author-avatar-link img{width:100%;height:100%;border-radius:50%;object-fit:cover;background:#36393f;transition:filter .18s}
.message-author-avatar-link:hover img{filter:brightness(1.1)}
.message-author{font-weight:750;font-size:14px;overflow-wrap:anywhere}
.message-time{font-size:11px;color:#9298a2;margin-top:3px}
.message-content{padding:18px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:14px;line-height:1.55;min-height:56px}
.attachments{padding:0 18px 18px;display:grid;gap:8px}
.attachments a{color:#00a8fc;font-size:12px;overflow-wrap:anywhere;text-decoration:none}
.attachments a:hover{text-decoration:underline}
.attachments img{display:block;max-width:100%;max-height:280px;object-fit:contain;border-radius:8px;margin-top:5px}
.embed-box{margin-top:10px;padding:12px 14px;border-radius:6px;background:#2b2d31;border-left:4px solid var(--embed-color,#5865f2)}
.embed-title{font-size:14px;font-weight:700;color:#fff;margin-bottom:6px}
.embed-desc{font-size:13px;line-height:1.45;color:#dbdee1;white-space:pre-wrap;overflow-wrap:anywhere}
.embed-img{display:block;max-width:100%;max-height:220px;border-radius:6px;margin-top:8px;object-fit:contain}
.reactions{display:flex;flex-wrap:wrap;gap:6px}
.reaction-pill{display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border-radius:6px;background:#2b2d31;font-size:12px;font-weight:600;color:#dbdee1}
.emoji-preview{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:28px 16px 20px;background:#18191c}
.emoji-preview img{width:96px;height:96px;object-fit:contain}
.emoji-name{font-size:18px;font-weight:750;margin-top:12px;color:#f2f3f5}
.error-card{padding:18px 19px;color:#f2f3f5;font-size:13px;line-height:1.5;overflow-wrap:anywhere}
.error-card .field-label{color:#ed7779}
.snowflake-card{padding:18px 19px}
.snowflake-value{font-size:13px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;color:#e4e5e7}
.accent-line{height:3px;width:100%;background:var(--accent,#5865f2)}
@media(max-width:480px){body{padding:28px 12px 32px}.lookup{gap:6px}.lookup input,.lookup button{height:46px}.result{margin-top:17px}.entity-head{min-height:108px;padding:18px}.entity-title{font-size:20px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}
</style>
</head>
<body>
<form class="lookup" id="lookupForm" autocomplete="off">
  <input id="query" type="text" inputmode="text" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="Discord ID, profile, message or invite link" aria-label="Discord ID or link">
  <button id="submit" type="submit" aria-label="Look up" title="Look up">⌕</button>
</form>
<div id="status" class="status" role="status" aria-live="polite"></div>
<main id="result" class="result" aria-live="polite"></main>
<script>
(function(){
  'use strict';
  var form=document.getElementById('lookupForm');
  var input=document.getElementById('query');
  var button=document.getElementById('submit');
  var status=document.getElementById('status');
  var result=document.getElementById('result');

  var FLAGS=[
    [1,'Discord Staff'],[2,'Partnered Server Owner'],[4,'HypeSquad Events'],[8,'Bug Hunter Level 1'],
    [64,'HypeSquad Bravery'],[128,'HypeSquad Brilliance'],[256,'HypeSquad Balance'],
    [512,'Early Supporter'],[1024,'Team User'],[16384,'Bug Hunter Level 2'],
    [65536,'Verified Bot'],[131072,'Early Verified Bot Developer'],
    [262144,'Certified Moderator Alumni'],[524288,'HTTP Interactions'],
    [1048576,'Spammer'],[4194304,'Active Developer']
  ];
  var CHANNEL_TYPES={
    0:'Text Channel',1:'Direct Message',2:'Voice Channel',3:'Group DM',4:'Category',
    5:'Announcement Channel',10:'Announcement Thread',11:'Public Thread',12:'Private Thread',
    13:'Stage Channel',14:'Directory',15:'Forum Channel',16:'Media Channel'
  };
  var NAMEPLATE_PALETTES={
    crimson:'#6b1219',berry:'#6e1b4f',sky:'#184e7a',teal:'#135154',forest:'#1a502e',
    bubble_gum:'#7c2a63',violet:'#471f76',cobalt:'#172d73',clover:'#265219',lemon:'#6f5313',
    white:'#4f545c',none:'#232428'
  };

  function stripInvitePrefix(str){
    if(!str)return '';
    var s=String(str).trim();
    if(/discord(?:app)?\.com\/(?:channels|users)/i.test(s))return s;
    var m=s.match(/^(?:https?:\/\/)?(?:www\.)?(?:discord\.gg\/|discord(?:app)?\.com\/invite\/)([a-zA-Z0-9_-]+)(?:[?#].*)?$/i);
    if(m)return m[1];
    if(/^(?:https?:\/\/)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com\/invite)\/?$/i.test(s))return '';
    return s;
  }

  function node(tag,cls,text){var n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined&&text!==null)n.textContent=String(text);return n;}
  function setStatus(text,isError){status.textContent=text||'';status.style.color=isError?'#ed7779':'#aeb4bf';}
  function hideResult(){result.className='result';result.removeAttribute('data-type');result.replaceChildren();}
  function showResult(kind){result.replaceChildren();result.setAttribute('data-type',kind);result.className='result visible';}

  function addField(parent,label,value,options){
    if(value===undefined||value===null||value==='')return null;
    var wrap=node('div','field');wrap.appendChild(node('div','field-label',label));
    var val=node('div','field-value'+(options&&options.muted?' muted':''));val.textContent=String(value);wrap.appendChild(val);
    if(options&&options.copy){var copy=node('button','copy','copy');copy.type='button';copy.title='Copy';copy.addEventListener('click',function(){copyText(String(options.copy));});val.appendChild(copy);}
    parent.appendChild(wrap);return wrap;
  }
  function addSection(parent,title){var s=node('section','section');if(title)s.appendChild(node('h3','section-title',title));parent.appendChild(s);return s;}
  function addPills(parent,items){if(!items||!items.length)return;var wrap=node('div','pills');items.forEach(function(item){if(typeof item==='string')wrap.appendChild(node('span','pill',item));else{var p=node('span','pill');if(item.image){var img=node('img');img.src=item.image;img.alt='';img.loading='lazy';p.appendChild(img);}p.appendChild(document.createTextNode(item.text));wrap.appendChild(p);}});parent.appendChild(wrap);}
  function copyText(value){if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(value).then(function(){setStatus('Copied: '+value);}).catch(function(){setStatus('Copy unavailable',true);});}else{var t=document.createElement('textarea');t.value=value;document.body.appendChild(t);t.select();try{document.execCommand('copy');setStatus('Copied: '+value);}catch(e){setStatus('Copy unavailable',true);}t.remove();}}
  function imageURL(path){return 'https://cdn.discordapp.com/'+path;}

  function avatarURL(user,size){
    var s=size?'?size='+size:'?size=256';
    if(user.avatar)return imageURL('avatars/'+user.id+'/'+user.avatar+'.'+(user.avatar.indexOf('a_')===0?'gif':'png')+s);
    var index=0;
    if(user.discriminator&&user.discriminator!=='0')index=Number(user.discriminator)%5;
    else{try{index=Number((BigInt(user.id)>>22n)%6n);}catch(e){index=0;}}
    return imageURL('embed/avatars/'+index+'.png');
  }
  function bannerURL(id,hash,size){var s=size?'?size='+size:'?size=1024';return hash?imageURL('banners/'+id+'/'+hash+'.'+(hash.indexOf('a_')===0?'gif':'png')+s):'';}
  function fmtDate(iso){var d=new Date(iso);if(isNaN(d.getTime()))return '';return new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'medium'}).format(d);}

  function userCard(payload){
    var u=payload.data||{};
    showResult('user');

    var banner=node('div','banner');
    var bUrl=bannerURL(u.id,u.banner,4096);
    var hexColor=Number.isInteger(u.accent_color)?'#'+u.accent_color.toString(16).padStart(6,'0'):'#5865f2';

    if(bUrl){
      banner.style.backgroundImage='url("'+bUrl+'")';
      var a=node('a','banner-link');
      a.href=bUrl;
      a.target='_blank';
      a.rel='noopener noreferrer';
      a.setAttribute('aria-label','Open profile banner in new tab');
      a.title='Open banner in new tab';
      banner.appendChild(a);
    } else {
      banner.style.backgroundColor=hexColor;
      var fallbackBadge=node('button','banner-fallback-badge');
      fallbackBadge.type='button';
      fallbackBadge.title='Accent color (click to copy)';
      fallbackBadge.setAttribute('aria-label','Copy accent color hex code');
      var dot=node('span','banner-fallback-dot');
      dot.style.backgroundColor=hexColor;
      fallbackBadge.appendChild(dot);
      fallbackBadge.appendChild(document.createTextNode(hexColor.toUpperCase()));
      fallbackBadge.addEventListener('click',function(e){
        e.stopPropagation();
        copyText(hexColor.toUpperCase());
      });
      banner.appendChild(fallbackBadge);
    }
    result.appendChild(banner);

    var fullAvatar=avatarURL(u,4096);
    var avatarWrap=node('div','avatar-wrap');
    var avatarLink=node('a','avatar-link');
    avatarLink.href=fullAvatar;
    avatarLink.target='_blank';
    avatarLink.rel='noopener noreferrer';
    avatarLink.setAttribute('aria-label','Open avatar in new tab');
    avatarLink.title='Open avatar in new tab';

    var avatar=node('img','avatar');
    avatar.src=avatarURL(u,256);
    avatar.alt='';
    avatar.loading='lazy';
    avatarLink.appendChild(avatar);

    if(u.avatar_decoration_data&&u.avatar_decoration_data.asset){
      var deco=node('img','decoration');
      deco.src=imageURL('avatar-decoration-presets/'+u.avatar_decoration_data.asset+'.png?size=256');
      deco.alt='';
      avatarLink.appendChild(deco);
    }
    avatarWrap.appendChild(avatarLink);
    result.appendChild(avatarWrap);

    var body=node('div','user-body');
    result.appendChild(body);

    var nameRow=node('div','user-name-row');
    nameRow.appendChild(node('div','user-name',u.global_name||u.username||'Unknown User'));
    if(u.bot)nameRow.appendChild(node('span','bot-mark','BOT'));

    var primary=u.primary_guild;
    if(primary&&primary.tag&&primary.identity_enabled!==false){
      var tag=node('span','guild-tag');
      if(primary.badge&&primary.identity_guild_id){
        var badge=node('img');
        badge.src=imageURL('guild-tag-badges/'+primary.identity_guild_id+'/'+primary.badge+'.png?size=32');
        badge.alt='';
        tag.appendChild(badge);
      }
      tag.appendChild(document.createTextNode(primary.tag));
      nameRow.appendChild(tag);
    }
    body.appendChild(nameRow);

    var username=node('div','username','@'+(u.username||'unknown'));
    if(u.discriminator&&u.discriminator!=='0')username.textContent+=' #'+u.discriminator;
    body.appendChild(username);

    var created=payload.snowflake?fmtDate(payload.snowflake.iso):'';
    var identity=addSection(body,'User');
    addField(identity,'Account created',created);
    addField(identity,'User ID',u.id,{copy:u.id});

    var premium={0:'None',1:'Nitro Classic',2:'Nitro',3:'Nitro Basic'};
    if(u.premium_type!==undefined&&u.premium_type!==null)addField(identity,'Nitro',premium[u.premium_type]||('Type '+u.premium_type));
    if(u.system)addField(identity,'Account type','System account');
    if(primary&&primary.tag&&primary.identity_enabled!==false)addField(identity,'Primary server tag',primary.tag);
    if(u.accent_color!==undefined&&u.accent_color!==null)addField(identity,'Accent color','#'+Number(u.accent_color).toString(16).padStart(6,'0'),{copy:'#'+Number(u.accent_color).toString(16).padStart(6,'0')});

    var badges=[];
    var bits=BigInt(u.public_flags||0);
    FLAGS.forEach(function(flag){if((bits&BigInt(flag[0]))!==0n)badges.push(flag[1]);});
    if(badges.length){
      var badgeSection=addSection(body,'Badges');
      addPills(badgeSection,badges);
    }

    if(u.avatar_decoration_data&&u.avatar_decoration_data.asset){
      var decoSection=addSection(body,'Avatar decoration');
      var decoUrl=imageURL('avatar-decoration-presets/'+u.avatar_decoration_data.asset+'.png?size=256');
      var decoRow=node('div','asset-row');
      var di=node('img');
      di.src=decoUrl;
      di.alt='Avatar decoration';
      di.style.width='64px';
      di.style.height='64px';
      decoRow.appendChild(di);
      var dLink=node('a','asset-action-link','Open Decoration Asset');
      dLink.href=decoUrl;
      dLink.target='_blank';
      dLink.rel='noopener noreferrer';
      decoRow.appendChild(dLink);
      decoSection.appendChild(decoRow);
      if(u.avatar_decoration_data.sku_id)addField(decoSection,'SKU ID',u.avatar_decoration_data.sku_id,{copy:u.avatar_decoration_data.sku_id});
    }

    if(u.collectibles&&u.collectibles.nameplate&&u.collectibles.nameplate.asset){
      var np=u.collectibles.nameplate;
      var npSection=addSection(body,'Nameplate');
      var npAsset=np.asset.replace(/^\/+|\/+$/g,'');
      var npAssetUrl=imageURL('assets/collectibles/'+npAsset+'/img.png');
      var paletteBg=NAMEPLATE_PALETTES[String(np.palette||'').toLowerCase()]||'#232428';

      var npCard=node('div','nameplate-card');
      npCard.style.backgroundColor=paletteBg;
      npCard.style.backgroundImage='url("'+npAssetUrl+'")';

      var npInner=node('div','nameplate-inner');

      var npAvWrap=node('a','nameplate-avatar-wrap');
      npAvWrap.href=fullAvatar;
      npAvWrap.target='_blank';
      npAvWrap.rel='noopener noreferrer';
      npAvWrap.title='Open avatar in new tab';
      npAvWrap.setAttribute('aria-label','Open avatar in new tab');

      var npAv=node('img','nameplate-avatar');
      npAv.src=avatarURL(u,128);
      npAv.alt='';
      npAv.loading='lazy';
      npAvWrap.appendChild(npAv);

      if(u.avatar_decoration_data&&u.avatar_decoration_data.asset){
        var npDeco=node('img','nameplate-decoration');
        npDeco.src=imageURL('avatar-decoration-presets/'+u.avatar_decoration_data.asset+'.png?size=128');
        npDeco.alt='';
        npAvWrap.appendChild(npDeco);
      }
      npInner.appendChild(npAvWrap);

      var npInfo=node('div','nameplate-info');
      var npNameRow=node('div','nameplate-name-row');
      npNameRow.appendChild(node('span','nameplate-display-name',u.global_name||u.username||'Unknown'));

      if(primary&&primary.tag&&primary.identity_enabled!==false){
        var npTag=node('span','nameplate-tag');
        if(primary.badge&&primary.identity_guild_id){
          var npBadge=node('img');
          npBadge.src=imageURL('guild-tag-badges/'+primary.identity_guild_id+'/'+primary.badge+'.png?size=32');
          npBadge.alt='';
          npTag.appendChild(npBadge);
        }
        npTag.appendChild(document.createTextNode(primary.tag));
        npNameRow.appendChild(npTag);
      }
      npInfo.appendChild(npNameRow);
      npInfo.appendChild(node('div','nameplate-handle','@'+(u.username||'unknown')));
      npInner.appendChild(npInfo);
      npCard.appendChild(npInner);
      npSection.appendChild(npCard);

      if(np.palette)addField(npSection,'Palette',np.palette);
      if(np.sku_id)addField(npSection,'SKU ID',np.sku_id,{copy:np.sku_id});
      var npActionRow=node('div','asset-row');
      var npLink=node('a','asset-action-link','Open Nameplate Asset');
      npLink.href=npAssetUrl;
      npLink.target='_blank';
      npLink.rel='noopener noreferrer';
      npActionRow.appendChild(npLink);
      npSection.appendChild(npActionRow);
    }

    if(payload.snowflake){
      var technical=addSection(body,'Snowflake');
      addField(technical,'Timestamp',payload.snowflake.iso);
      addField(technical,'Worker ID',payload.snowflake.worker);
      addField(technical,'Process ID',payload.snowflake.process);
      addField(technical,'Increment',payload.snowflake.increment);
    }
  }

  function entityShell(kind,title,subtitle,icon,banner,iconLink,bannerLink){
    showResult(kind);
    var head=node('div','entity-head');
    if(banner){
      head.style.backgroundImage='url("'+banner+'")';
      if(bannerLink){
        var bLink=node('a','entity-head-link');
        bLink.href=bannerLink;
        bLink.target='_blank';
        bLink.rel='noopener noreferrer';
        bLink.title='Open banner in new tab';
        head.appendChild(bLink);
      }
    }
    if(icon){
      var iconWrap=iconLink?node('a','entity-icon-link'):null;
      var img=node('img','entity-icon');
      img.src=icon;
      img.alt='';
      if(iconWrap){
        iconWrap.href=iconLink;
        iconWrap.target='_blank';
        iconWrap.rel='noopener noreferrer';
        iconWrap.title='Open icon in new tab';
        iconWrap.appendChild(img);
        head.appendChild(iconWrap);
      } else {
        head.appendChild(img);
      }
    }
    head.appendChild(node('div','entity-title',title||'Unknown'));
    if(subtitle)head.appendChild(node('div','entity-subtitle',subtitle));
    result.appendChild(head);
    var body=node('div','entity-body');
    result.appendChild(body);
    return body;
  }

  function guildCard(payload){
    var g=payload.data||{};
    var icon=g.icon?imageURL('icons/'+g.id+'/'+g.icon+'.'+(g.icon.indexOf('a_')===0?'gif':'png')+'?size=1024'):'';
    var banner=g.banner?imageURL('banners/'+g.id+'/'+g.banner+'.'+(g.banner.indexOf('a_')===0?'gif':'png')+'?size=2048'):'';
    var body=entityShell('guild',g.name,'Server',icon,banner,icon,banner);
    var s=addSection(body,'Server');
    addField(s,'Created',payload.snowflake?fmtDate(payload.snowflake.iso):'');
    addField(s,'Server ID',g.id,{copy:g.id});
    addField(s,'Owner ID',g.owner_id,{copy:g.owner_id});
    if(g.vanity_url_code)addField(s,'Vanity invite','discord.gg/'+g.vanity_url_code,{copy:'https://discord.gg/'+g.vanity_url_code});
    addField(s,'Description',g.description);
    addField(s,'Preferred locale',g.preferred_locale);
    var VERIFICATION_LEVELS={0:'None',1:'Low (Verified email)',2:'Medium (Registered > 5m)',3:'High (Member > 10m)',4:'Very High (Verified phone)'};
    if(g.verification_level!==undefined)addField(s,'Verification level',VERIFICATION_LEVELS[g.verification_level]||g.verification_level);
    var BOOST_TIERS={0:'None',1:'Tier 1',2:'Tier 2',3:'Tier 3'};
    if(g.premium_tier!==undefined)addField(s,'Boost level',BOOST_TIERS[g.premium_tier]||('Tier '+g.premium_tier));
    if(g.premium_subscription_count!==undefined&&g.premium_subscription_count!==null)addField(s,'Server boosts',g.premium_subscription_count);
    addField(s,'Approx. members',g.approximate_member_count);
    addField(s,'Approx. online',g.approximate_presence_count);
    if(Array.isArray(g.features)&&g.features.length){
      var fs=addSection(body,'Features');
      addPills(fs,g.features.slice(0,24));
    }
    if(payload.snowflake){
      var technical=addSection(body,'Snowflake');
      addField(technical,'Timestamp',payload.snowflake.iso);
      addField(technical,'Worker ID',payload.snowflake.worker);
      addField(technical,'Process ID',payload.snowflake.process);
      addField(technical,'Increment',payload.snowflake.increment);
    }
  }

  function channelCard(payload){
    var c=payload.data||{};
    var typeName=CHANNEL_TYPES[c.type]||('Channel type '+c.type);
    var body=entityShell('channel',c.name||'Direct message',typeName,null,'');
    var s=addSection(body,'Channel');
    addField(s,'Created',payload.snowflake?fmtDate(payload.snowflake.iso):'');
    addField(s,'Channel ID',c.id,{copy:c.id});
    addField(s,'Channel type',typeName);
    if(c.guild_id)addField(s,'Server ID',c.guild_id,{copy:c.guild_id});
    if(c.parent_id)addField(s,'Category / Parent ID',c.parent_id,{copy:c.parent_id});
    addField(s,'Topic',c.topic);
    if(c.rate_limit_per_user!==undefined&&c.rate_limit_per_user!==null)addField(s,'Slowmode',c.rate_limit_per_user>0?(c.rate_limit_per_user+'s'):'Disabled');
    if(c.bitrate)addField(s,'Bitrate',Math.round(c.bitrate/1000)+' kbps');
    if(c.user_limit)addField(s,'User limit',c.user_limit>0?c.user_limit:'No limit');
    if(c.position!==undefined&&c.position!==null)addField(s,'Position',c.position);
    addField(s,'NSFW',typeof c.nsfw==='boolean'?(c.nsfw?'Yes':'No'):null);
    if(payload.snowflake){
      var technical=addSection(body,'Snowflake');
      addField(technical,'Timestamp',payload.snowflake.iso);
    }
  }

  function messageCard(payload){
    var m=payload.data||{};
    var author=m.author||{};
    var authorAvatar=avatarURL(author,4096);
    var head=node('div','message-head');

    var avLink=node('a','message-author-avatar-link');
    avLink.href=authorAvatar;
    avLink.target='_blank';
    avLink.rel='noopener noreferrer';
    avLink.title='Open avatar in new tab';
    var av=node('img');
    av.src=avatarURL(author,128);
    av.alt='';
    avLink.appendChild(av);
    head.appendChild(avLink);

    var info=node('div');
    info.appendChild(node('div','message-author',(author.global_name||author.username||'Unknown user')+(author.bot?' · BOT':'')));
    info.appendChild(node('div','message-time',fmtDate(m.timestamp||payload.snowflake&&payload.snowflake.iso)));
    head.appendChild(info);

    result.replaceChildren();
    result.setAttribute('data-type','message');
    result.className='result visible';
    result.appendChild(head);

    var content=node('div','message-content',m.content||'');
    if(!m.content)content.classList.add('muted');
    result.appendChild(content);

    if(Array.isArray(m.attachments)&&m.attachments.length){
      var at=node('div','attachments');
      m.attachments.forEach(function(file){
        var link=node('a');
        link.href=file.url;
        link.target='_blank';
        link.rel='noopener noreferrer';
        link.textContent=file.filename||file.url;
        at.appendChild(link);
        if(file.content_type&&file.content_type.indexOf('image/')===0){
          var im=node('img');
          im.src=file.proxy_url||file.url;
          im.alt=file.filename||'Message attachment';
          im.loading='lazy';
          at.appendChild(im);
        }
      });
      result.appendChild(at);
    }

    if(Array.isArray(m.embeds)&&m.embeds.length){
      var embedsWrap=node('div','embeds-container');
      embedsWrap.style.padding='0 18px 14px';
      m.embeds.forEach(function(em){
        var eb=node('div','embed-box');
        if(Number.isInteger(em.color)){
          eb.style.setProperty('--embed-color','#'+em.color.toString(16).padStart(6,'0'));
        }
        if(em.title)eb.appendChild(node('div','embed-title',em.title));
        if(em.description)eb.appendChild(node('div','embed-desc',em.description));
        if(em.image&&em.image.url){
          var eimg=node('img','embed-img');
          eimg.src=em.image.proxy_url||em.image.url;
          eimg.alt='';
          eb.appendChild(eimg);
        }
        embedsWrap.appendChild(eb);
      });
      result.appendChild(embedsWrap);
    }

    if(Array.isArray(m.reactions)&&m.reactions.length){
      var rxWrap=node('div','reactions');
      rxWrap.style.padding='0 18px 14px';
      m.reactions.forEach(function(r){
        var rPill=node('span','reaction-pill');
        var emojiName=r.emoji?(r.emoji.name||''):'';
        rPill.textContent=emojiName+' '+(r.count||1);
        rxWrap.appendChild(rPill);
      });
      result.appendChild(rxWrap);
    }

    var body=node('div','entity-body');
    result.appendChild(body);
    var s=addSection(body,'Message');
    addField(s,'Message ID',m.id,{copy:m.id});
    addField(s,'Channel ID',m.channel_id,{copy:m.channel_id});
    var gid=payload.channel&&payload.channel.guild_id||payload.guildId;
    if(gid)addField(s,'Server ID',gid,{copy:gid});
    addField(s,'Created',fmtDate(m.timestamp));
    if(m.edited_timestamp)addField(s,'Edited',fmtDate(m.edited_timestamp));
    if(m.pinned)addField(s,'Pinned','Yes');
    addField(s,'Author ID',author.id,{copy:author.id});
    if(payload.snowflake){
      var technical=addSection(body,'Snowflake');
      addField(technical,'Timestamp',payload.snowflake.iso);
    }
  }

  function roleCard(payload){
    var r=payload.data||{};
    var color=Number(r.color||0).toString(16).padStart(6,'0');
    var roleIconUrl=r.icon?imageURL('role-icons/'+r.id+'/'+r.icon+'.png?size=128'):'';
    var body=entityShell('role',r.name,'Role',roleIconUrl,'',roleIconUrl,'');
    var line=node('div','accent-line');
    line.style.setProperty('--accent','#'+color);
    body.insertBefore(line,body.firstChild);
    var s=addSection(body,'Role');
    addField(s,'Role ID',r.id,{copy:r.id});
    addField(s,'Server',payload.guild&&payload.guild.name);
    addField(s,'Server ID',payload.guild&&payload.guild.id,{copy:payload.guild&&payload.guild.id});
    addField(s,'Created',payload.snowflake?fmtDate(payload.snowflake.iso):'');
    addField(s,'Color','#'+color,{copy:'#'+color});
    if(r.position!==undefined)addField(s,'Position',r.position);
    addField(s,'Hoisted',typeof r.hoist==='boolean'?(r.hoist?'Yes':'No'):null);
    addField(s,'Mentionable',typeof r.mentionable==='boolean'?(r.mentionable?'Yes':'No'):null);
    addField(s,'Permissions bitfield',r.permissions,{copy:r.permissions});
    if(payload.snowflake){
      var technical=addSection(body,'Snowflake');
      addField(technical,'Timestamp',payload.snowflake.iso);
    }
  }

  function inviteCard(payload){
    var i=payload.data||{};
    var g=i.guild||{};
    var iconUrl=g.icon?imageURL('icons/'+g.id+'/'+g.icon+'.png?size=256'):'';
    var bannerUrl=g.banner?imageURL('banners/'+g.id+'/'+g.banner+'.png?size=1024'):'';
    var body=entityShell('invite',g.name||i.code,'Discord invite',iconUrl,bannerUrl,iconUrl,bannerUrl);
    var s=addSection(body,'Invite');
    addField(s,'Invite code',i.code||'',{copy:i.code});
    if(g.id)addField(s,'Server ID',g.id,{copy:g.id});
    addField(s,'Description',g.description);
    addField(s,'Approx. members',i.approximate_member_count);
    addField(s,'Approx. online',i.approximate_presence_count);
    addField(s,'Uses',i.uses);
    addField(s,'Expires',i.expires_at?fmtDate(i.expires_at):'Never');
    if(i.channel)addField(s,'Target channel',i.channel.name+' ('+(CHANNEL_TYPES[i.channel.type]||'Channel')+')');

    if(i.inviter){
      var invSection=addSection(body,'Invited by');
      var inv=i.inviter;
      var invName=inv.global_name||inv.username||'Unknown User';

      var npLink=node('a','inviter-nameplate');
      npLink.href='/?'+encodeURIComponent(inv.id);
      npLink.target='_blank';
      npLink.rel='noopener noreferrer';
      npLink.title='Open lookup for '+invName+' in a new tab';
      npLink.setAttribute('aria-label','Open lookup for '+invName+' in a new tab');

      var avWrap=node('div','nameplate-avatar-wrap');
      var av=node('img','nameplate-avatar');
      av.src=avatarURL(inv,128);
      av.alt='';
      av.loading='lazy';
      avWrap.appendChild(av);

      if(inv.avatar_decoration_data&&inv.avatar_decoration_data.asset){
        var deco=node('img','nameplate-decoration');
        deco.src=imageURL('avatar-decoration-presets/'+inv.avatar_decoration_data.asset+'.png?size=128');
        deco.alt='';
        avWrap.appendChild(deco);
      }
      npLink.appendChild(avWrap);

      var info=node('div','nameplate-info');
      var nameRow=node('div','nameplate-name-row');
      nameRow.appendChild(node('span','nameplate-display-name',invName));
      if(inv.bot)nameRow.appendChild(node('span','bot-mark','BOT'));
      info.appendChild(nameRow);

      var handleStr='@'+(inv.username||'unknown');
      if(inv.discriminator&&inv.discriminator!=='0')handleStr+=' #'+inv.discriminator;
      var handle=node('div','nameplate-handle');
      handle.appendChild(document.createTextNode(handleStr));
      info.appendChild(handle);

      npLink.appendChild(info);

      var arrow=node('span','inviter-arrow','↗');
      npLink.appendChild(arrow);

      invSection.appendChild(npLink);
      addField(invSection,'User ID',inv.id,{copy:inv.id});
    }
  }

  function emojiCard(payload){
    showResult('emoji');
    var em=payload.data||{};
    var box=node('div','emoji-preview');
    var img=node('img');
    img.src=em.url;
    img.alt=em.name||'Emoji';
    box.appendChild(img);
    box.appendChild(node('div','emoji-name',':'+(em.name||'emoji')+':'));
    result.appendChild(box);

    var body=node('div','entity-body');
    result.appendChild(body);
    var s=addSection(body,'Custom Emoji');
    addField(s,'Emoji ID',em.id,{copy:em.id});
    addField(s,'Name',em.name);
    addField(s,'Animated',em.animated?'Yes':'No');
    if(payload.snowflake){
      var technical=addSection(body,'Snowflake');
      addField(technical,'Created',fmtDate(payload.snowflake.iso));
      addField(technical,'Timestamp',payload.snowflake.iso);
    }
    var row=node('div','asset-row');
    var aLink=node('a','asset-action-link','Open Full Emoji Image');
    aLink.href=em.url;
    aLink.target='_blank';
    aLink.rel='noopener noreferrer';
    row.appendChild(aLink);
    body.appendChild(row);
  }

  function snowflakeCard(payload){
    showResult('snowflake');
    var box=node('div','snowflake-card');
    result.appendChild(box);
    box.appendChild(node('div','section-title','Discord snowflake'));
    box.appendChild(node('div','snowflake-value',payload.snowflake?payload.snowflake.id:'—'));
    if(payload.snowflake){
      addField(box,'Created',fmtDate(payload.snowflake.iso));
      addField(box,'Timestamp (UTC)',payload.snowflake.iso);
    }
    if(payload.error)addField(box,'Lookup',payload.error);
  }

  function errorCard(data){
    hideResult();
    showResult('snowflake');
    var box=node('div','error-card');
    result.appendChild(box);
    box.appendChild(node('div','field-label','Lookup unavailable'));
    box.appendChild(node('div','field-value',data.error||'Lookup failed.'));
    if(data.snowflake){
      addField(box,'ID',data.snowflake.id,{copy:data.snowflake.id});
      addField(box,'Created',fmtDate(data.snowflake.iso));
    }
  }

  function render(data){
    if(!data||!data.ok){errorCard(data||{});return;}
    if(data.kind==='user')userCard(data);
    else if(data.kind==='guild')guildCard(data);
    else if(data.kind==='channel')channelCard(data);
    else if(data.kind==='message')messageCard(data);
    else if(data.kind==='role')roleCard(data);
    else if(data.kind==='invite')inviteCard(data);
    else if(data.kind==='emoji')emojiCard(data);
    else snowflakeCard(data);
  }

  input.addEventListener('paste',function(e){
    var pasted=(e.clipboardData||window.clipboardData)&&(e.clipboardData||window.clipboardData).getData('text');
    if(pasted){
      var stripped=stripInvitePrefix(pasted);
      if(stripped!==pasted.trim()){
        e.preventDefault();
        input.value=stripped;
        return;
      }
    }
    setTimeout(function(){
      input.value=stripInvitePrefix(input.value);
    },0);
  });

  input.addEventListener('input',function(){
    var stripped=stripInvitePrefix(input.value);
    if(stripped!==input.value){
      input.value=stripped;
    }
  });

  form.addEventListener('submit',function(event){
    event.preventDefault();
    var q=stripInvitePrefix(input.value.trim());
    if(!q)return;
    input.value=q;
    button.disabled=true;
    setStatus('');
    hideResult();

    if(window.history&&window.history.replaceState){
      var targetSearch='?'+encodeURIComponent(q);
      if(location.search!==targetSearch){
        window.history.replaceState(null,'',location.pathname+targetSearch);
      }
    }

    fetch('/api/lookup?q='+encodeURIComponent(q),{method:'GET',headers:{'Accept':'application/json'},credentials:'same-origin'})
      .then(function(response){return response.json().then(function(body){return {status:response.status,body:body};});})
      .then(function(resultData){
        render(resultData.body);
        if(resultData.body&&resultData.body.ok)setStatus('');
        else setStatus(resultData.body&&resultData.body.error||'Lookup failed.',true);
      })
      .catch(function(){
        errorCard({error:'The lookup request failed. Check your connection and try again.'});
        setStatus('Lookup failed.',true);
      })
      .finally(function(){button.disabled=false;});
  });

  // Support /?USER_ID or /?invite_code as well as /?q=... and /?id=...
  var params=new URLSearchParams(location.search);
  var initial=params.get('id')||params.get('q');
  if(!initial&&location.search&&location.search.length>1){
    var rawSearch=location.search.slice(1).trim();
    if(rawSearch){
      if(rawSearch.indexOf('=')===-1){
        initial=decodeURIComponent(rawSearch);
      } else {
        var firstKey=params.keys().next().value;
        if(firstKey&&!params.get(firstKey)){
          initial=decodeURIComponent(firstKey);
        }
      }
    }
  }

  if(initial){
    input.value=stripInvitePrefix(initial);
    form.requestSubmit();
  }
})();
</script>
</body>
</html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/favicon.ico") return new Response(null, { status: 204 });

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
      return new Response("Method not allowed", { status: 405, headers: { "Allow": "GET, HEAD" } });
    }

    return new Response(request.method === "HEAD" ? null : PAGE, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": "default-src 'self'; img-src 'self' data: https://cdn.discordapp.com https://media.discordapp.net; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
      }
    });
  }
};
