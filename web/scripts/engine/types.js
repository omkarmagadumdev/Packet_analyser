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

function normalizeHostname(value) {
  if (!value) return "";
  return value
    .toLowerCase()
    .replace(/\.+$/, "")
    .replace(/^\[|\]$/g, "")
    .trim();
}

function matchesDomain(host, domain) {
  const normalizedHost = normalizeHostname(host);
  const normalizedDomain = normalizeHostname(domain);
  if (!normalizedHost || !normalizedDomain) return false;
  return normalizedHost === normalizedDomain || normalizedHost.endsWith(`.${normalizedDomain}`);
}

function matchesAnyDomain(host, domains) {
  return domains.some((domain) => matchesDomain(host, domain));
}

function matchesAnyFragment(host, fragments) {
  const normalizedHost = normalizeHostname(host);
  if (!normalizedHost) return false;
  return fragments.some((fragment) => normalizedHost.includes(fragment.toLowerCase()));
}

function sniToAppType(sni) {
  if (!sni) return AppType.UNKNOWN;
  const value = normalizeHostname(sni);

  if (
    matchesAnyDomain(value, ["youtube.com", "youtubei.googleapis.com", "googlevideo.com", "ytimg.com", "ytstatic.com", "youtu.be", "yt3.ggpht.com"]) ||
    matchesAnyFragment(value, ["youtube", "youtubei", "googlevideo", "ytimg", "ytstatic", "yt3.ggpht"])
  ) return AppType.YOUTUBE;
  if (
    matchesAnyDomain(value, ["google.com", "gstatic.com", "googleapis.com", "ggpht.com", "gvt1.com"]) ||
    matchesAnyFragment(value, ["googleapis", "gstatic", "ggpht", "gvt1"])
  ) return AppType.GOOGLE;
  if (matchesAnyDomain(value, ["instagram.com", "cdninstagram.com"]) || matchesAnyFragment(value, ["instagram", "cdninstagram"])) return AppType.INSTAGRAM;
  if (matchesAnyDomain(value, ["whatsapp.com", "wa.me"]) || matchesAnyFragment(value, ["whatsapp"])) return AppType.WHATSAPP;
  if (matchesAnyDomain(value, ["facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "meta.com"]) || matchesAnyFragment(value, ["facebook", "fbcdn", "fbsbx"])) return AppType.FACEBOOK;
  if (matchesAnyDomain(value, ["twitter.com", "twimg.com", "x.com", "t.co"]) || matchesAnyFragment(value, ["twitter", "twimg"])) return AppType.TWITTER;
  if (matchesAnyDomain(value, ["netflix.com", "nflxvideo.net", "nflximg.net"]) || matchesAnyFragment(value, ["netflix", "nflxvideo", "nflximg"])) return AppType.NETFLIX;
  if (
    matchesAnyDomain(value, ["amazon.com", "amazonaws.com", "cloudfront.net"]) ||
    matchesAnyFragment(value, ["amazon", "amazonaws", "cloudfront"])
  ) return AppType.AMAZON;
  if (
    matchesAnyDomain(value, ["microsoft.com", "msn.com", "office.com", "azure.com", "live.com", "outlook.com", "bing.com"]) ||
    matchesAnyFragment(value, ["microsoft", "office", "azure", "outlook"])
  ) return AppType.MICROSOFT;
  if (matchesAnyDomain(value, ["apple.com", "icloud.com", "mzstatic.com", "itunes.apple.com"]) || matchesAnyFragment(value, ["apple", "icloud", "mzstatic", "itunes"])) return AppType.APPLE;
  if (matchesAnyDomain(value, ["telegram.org", "t.me"]) || matchesAnyFragment(value, ["telegram"])) return AppType.TELEGRAM;
  if (matchesAnyDomain(value, ["tiktok.com", "tiktokcdn.com", "musical.ly", "bytedance.com"]) || matchesAnyFragment(value, ["tiktok", "tiktokcdn", "bytedance"])) return AppType.TIKTOK;
  if (matchesAnyDomain(value, ["spotify.com", "scdn.co"]) || matchesAnyFragment(value, ["spotify"])) return AppType.SPOTIFY;
  if (matchesAnyDomain(value, ["zoom.us"]) || matchesAnyFragment(value, ["zoom"])) return AppType.ZOOM;
  if (matchesAnyDomain(value, ["discord.com", "discordapp.com"]) || matchesAnyFragment(value, ["discord", "discordapp"])) return AppType.DISCORD;
  if (matchesAnyDomain(value, ["github.com", "githubusercontent.com"]) || matchesAnyFragment(value, ["github", "githubusercontent"])) return AppType.GITHUB;
  if (matchesAnyDomain(value, ["cloudflare.com"]) || matchesAnyFragment(value, ["cloudflare"])) return AppType.CLOUDFLARE;

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
