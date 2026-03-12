const fs = require("fs");
const { AppType, appTypeToString, ipToInt, intToIp } = require("./types");

function domainMatchesPattern(domain, pattern) {
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1).toLowerCase();
    const normalizedDomain = domain.toLowerCase();
    if (normalizedDomain.endsWith(suffix)) return true;
    if (normalizedDomain === pattern.slice(2).toLowerCase()) return true;
  }
  return false;
}

class RuleManager {
  constructor() {
    this.blockedIPs = new Set();
    this.blockedApps = new Set();
    this.blockedDomains = new Set();
    this.domainPatterns = [];
    this.blockedPorts = new Set();
  }

  blockIP(ip) {
    const value = typeof ip === "number" ? ip >>> 0 : ipToInt(ip);
    this.blockedIPs.add(value);
  }

  unblockIP(ip) {
    const value = typeof ip === "number" ? ip >>> 0 : ipToInt(ip);
    this.blockedIPs.delete(value);
  }

  isIPBlocked(ip) {
    return this.blockedIPs.has(ip >>> 0);
  }

  getBlockedIPs() {
    return [...this.blockedIPs].map((ip) => intToIp(ip));
  }

  blockApp(app) {
    this.blockedApps.add(app);
  }

  unblockApp(app) {
    this.blockedApps.delete(app);
  }

  isAppBlocked(app) {
    return this.blockedApps.has(app);
  }

  getBlockedApps() {
    return [...this.blockedApps];
  }

  blockDomain(domain) {
    if (domain.includes("*")) this.domainPatterns.push(domain);
    else this.blockedDomains.add(domain);
  }

  unblockDomain(domain) {
    if (domain.includes("*")) {
      this.domainPatterns = this.domainPatterns.filter((pattern) => pattern !== domain);
    } else {
      this.blockedDomains.delete(domain);
    }
  }

  isDomainBlocked(domain) {
    const lower = domain.toLowerCase();
    if ([...this.blockedDomains].some((blocked) => lower === blocked.toLowerCase() || lower.includes(blocked.toLowerCase()))) return true;
    return this.domainPatterns.some((pattern) => domainMatchesPattern(lower, pattern.toLowerCase()));
  }

  getBlockedDomains() {
    return [...this.blockedDomains, ...this.domainPatterns];
  }

  blockPort(port) {
    this.blockedPorts.add(port & 0xffff);
  }

  unblockPort(port) {
    this.blockedPorts.delete(port & 0xffff);
  }

  isPortBlocked(port) {
    return this.blockedPorts.has(port & 0xffff);
  }

  shouldBlock(srcIP, dstPort, app, domain) {
    if (this.isIPBlocked(srcIP)) {
      return { type: "IP", detail: intToIp(srcIP) };
    }
    if (this.isPortBlocked(dstPort)) {
      return { type: "PORT", detail: String(dstPort) };
    }
    if (this.isAppBlocked(app)) {
      return { type: "APP", detail: appTypeToString(app) };
    }
    if (domain && this.isDomainBlocked(domain)) {
      return { type: "DOMAIN", detail: domain };
    }
    return null;
  }

  saveRules(filename) {
    const lines = [];
    lines.push("[BLOCKED_IPS]");
    for (const ip of this.getBlockedIPs()) lines.push(ip);
    lines.push("", "[BLOCKED_APPS]");
    for (const app of this.getBlockedApps()) lines.push(appTypeToString(app));
    lines.push("", "[BLOCKED_DOMAINS]");
    for (const domain of this.getBlockedDomains()) lines.push(domain);
    lines.push("", "[BLOCKED_PORTS]");
    for (const port of this.blockedPorts) lines.push(String(port));
    fs.writeFileSync(filename, `${lines.join("\n")}\n`, "utf8");
    return true;
  }

  loadRules(filename) {
    if (!fs.existsSync(filename)) return false;
    const content = fs.readFileSync(filename, "utf8");
    let section = "";

    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) continue;
      if (line.startsWith("[")) {
        section = line;
        continue;
      }

      if (section === "[BLOCKED_IPS]") {
        this.blockIP(line);
      } else if (section === "[BLOCKED_APPS]") {
        const found = Object.values(AppType).find((app) => appTypeToString(app) === line);
        if (found) this.blockApp(found);
      } else if (section === "[BLOCKED_DOMAINS]") {
        this.blockDomain(line);
      } else if (section === "[BLOCKED_PORTS]") {
        this.blockPort(Number.parseInt(line, 10));
      }
    }
    return true;
  }

  clearAll() {
    this.blockedIPs.clear();
    this.blockedApps.clear();
    this.blockedDomains.clear();
    this.domainPatterns = [];
    this.blockedPorts.clear();
  }

  getStats() {
    return {
      blocked_ips: this.blockedIPs.size,
      blocked_apps: this.blockedApps.size,
      blocked_domains: this.blockedDomains.size + this.domainPatterns.length,
      blocked_ports: this.blockedPorts.size
    };
  }

  toJSON() {
    return {
      blockedIPs: [...this.blockedIPs],
      blockedApps: [...this.blockedApps],
      blockedDomains: [...this.blockedDomains],
      domainPatterns: [...this.domainPatterns],
      blockedPorts: [...this.blockedPorts]
    };
  }

  static fromJSON(state) {
    const manager = new RuleManager();
    if (!state) return manager;

    manager.blockedIPs = new Set(state.blockedIPs ?? []);
    manager.blockedApps = new Set(state.blockedApps ?? []);
    manager.blockedDomains = new Set(state.blockedDomains ?? []);
    manager.domainPatterns = [...(state.domainPatterns ?? [])];
    manager.blockedPorts = new Set(state.blockedPorts ?? []);
    return manager;
  }
}

module.exports = { RuleManager };
