const AppType = Object.freeze({
  UNKNOWN: "UNKNOWN",
  HTTP: "HTTP",
  HTTPS: "HTTPS",
  DNS: "DNS",
  TLS: "TLS",
  QUIC: "QUIC",
  GOOGLE: "GOOGLE",
  FACEBOOK: "FACEBOOK",
  YOUTUBE: "YOUTUBE",
  TWITTER: "TWITTER",
  INSTAGRAM: "INSTAGRAM",
  NETFLIX: "NETFLIX",
  AMAZON: "AMAZON",
  MICROSOFT: "MICROSOFT",
  APPLE: "APPLE",
  WHATSAPP: "WHATSAPP",
  TELEGRAM: "TELEGRAM",
  TIKTOK: "TIKTOK",
  SPOTIFY: "SPOTIFY",
  ZOOM: "ZOOM",
  DISCORD: "DISCORD",
  GITHUB: "GITHUB",
  CLOUDFLARE: "CLOUDFLARE"
});

const GENERIC_APP_TYPES = new Set([
  AppType.UNKNOWN,
  AppType.HTTP,
  AppType.HTTPS,
  AppType.DNS,
  AppType.TLS,
  AppType.QUIC
]);

function appTypeToString(type) {
  const table = {
    [AppType.UNKNOWN]: "Unknown",
    [AppType.HTTP]: "HTTP",
    [AppType.HTTPS]: "HTTPS",
    [AppType.DNS]: "DNS",
    [AppType.TLS]: "TLS",
    [AppType.QUIC]: "QUIC",
    [AppType.GOOGLE]: "Google",
    [AppType.FACEBOOK]: "Facebook",
    [AppType.YOUTUBE]: "YouTube",
    [AppType.TWITTER]: "Twitter/X",
    [AppType.INSTAGRAM]: "Instagram",
    [AppType.NETFLIX]: "Netflix",
    [AppType.AMAZON]: "Amazon",
    [AppType.MICROSOFT]: "Microsoft",
    [AppType.APPLE]: "Apple",
    [AppType.WHATSAPP]: "WhatsApp",
    [AppType.TELEGRAM]: "Telegram",
    [AppType.TIKTOK]: "TikTok",
    [AppType.SPOTIFY]: "Spotify",
    [AppType.ZOOM]: "Zoom",
    [AppType.DISCORD]: "Discord",
    [AppType.GITHUB]: "GitHub",
    [AppType.CLOUDFLARE]: "Cloudflare"
  };
  return table[type] ?? "Unknown";
}

function ipToInt(ip) {
  const parts = ip.split(".").map((x) => Number.parseInt(x, 10) || 0);
  return ((parts[0] & 0xff) | ((parts[1] & 0xff) << 8) | ((parts[2] & 0xff) << 16) | ((parts[3] & 0xff) << 24)) >>> 0;
}

function intToIp(ip) {
  return `${ip & 0xff}.${(ip >>> 8) & 0xff}.${(ip >>> 16) & 0xff}.${(ip >>> 24) & 0xff}`;
}

function tupleToString(tuple) {
  return `${intToIp(tuple.src_ip)}:${tuple.src_port} -> ${intToIp(tuple.dst_ip)}:${tuple.dst_port} (${tuple.protocol === 6 ? "TCP" : tuple.protocol === 17 ? "UDP" : "?"})`;
}

function reverseTuple(tuple) {
  return {
    src_ip: tuple.dst_ip,
    dst_ip: tuple.src_ip,
    src_port: tuple.dst_port,
    dst_port: tuple.src_port,
    protocol: tuple.protocol
  };
}

function fiveTupleHash(tuple) {
  let hash = 0;
  const fields = [tuple.src_ip, tuple.dst_ip, tuple.src_port, tuple.dst_port, tuple.protocol];
  for (const field of fields) {
    hash ^= (Number(field) + 0x9e3779b9 + ((hash << 6) >>> 0) + (hash >>> 2)) >>> 0;
  }
  return hash >>> 0;
}

function sniToAppType(sni) {
  if (!sni) return AppType.UNKNOWN;
  const value = sni.toLowerCase();

  if (value.includes("youtube") || value.includes("youtubei") || value.includes("googlevideo") || value.includes("ytimg") || value.includes("ytstatic") || value.includes("youtu.be") || value.includes("yt3.ggpht")) return AppType.YOUTUBE;
  if (value.includes("google") || value.includes("gstatic") || value.includes("googleapis") || value.includes("ggpht") || value.includes("gvt1")) return AppType.GOOGLE;
  if (value.includes("instagram") || value.includes("cdninstagram")) return AppType.INSTAGRAM;
  if (value.includes("whatsapp") || value.includes("wa.me")) return AppType.WHATSAPP;
  if (value.includes("facebook") || value.includes("fbcdn") || value.includes("fb.com") || value.includes("fbsbx") || value.includes("meta.com")) return AppType.FACEBOOK;
  if (value.includes("twitter") || value.includes("twimg") || value.includes("x.com") || value.includes("t.co")) return AppType.TWITTER;
  if (value.includes("netflix") || value.includes("nflxvideo") || value.includes("nflximg")) return AppType.NETFLIX;
  if (value.includes("amazon") || value.includes("amazonaws") || value.includes("cloudfront") || value.includes("aws")) return AppType.AMAZON;
  if (value.includes("microsoft") || value.includes("msn.com") || value.includes("office") || value.includes("azure") || value.includes("live.com") || value.includes("outlook") || value.includes("bing")) return AppType.MICROSOFT;
  if (value.includes("apple") || value.includes("icloud") || value.includes("mzstatic") || value.includes("itunes")) return AppType.APPLE;
  if (value.includes("telegram") || value.includes("t.me")) return AppType.TELEGRAM;
  if (value.includes("tiktok") || value.includes("tiktokcdn") || value.includes("musical.ly") || value.includes("bytedance")) return AppType.TIKTOK;
  if (value.includes("spotify") || value.includes("scdn.co")) return AppType.SPOTIFY;
  if (value.includes("zoom")) return AppType.ZOOM;
  if (value.includes("discord") || value.includes("discordapp")) return AppType.DISCORD;
  if (value.includes("github") || value.includes("githubusercontent")) return AppType.GITHUB;
  if (value.includes("cloudflare") || value.includes("cf-")) return AppType.CLOUDFLARE;

  return AppType.HTTPS;
}

function isGenericAppType(type) {
  return GENERIC_APP_TYPES.has(type ?? AppType.UNKNOWN);
}

module.exports = {
  AppType,
  isGenericAppType,
  appTypeToString,
  sniToAppType,
  ipToInt,
  intToIp,
  tupleToString,
  reverseTuple,
  fiveTupleHash
};
