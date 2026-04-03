const { AppType, isGenericAppType, appTypeToString, reverseTuple, tupleToString } = require("./types");

const ConnectionState = Object.freeze({
  NEW: "NEW",
  ESTABLISHED: "ESTABLISHED",
  CLASSIFIED: "CLASSIFIED",
  BLOCKED: "BLOCKED",
  CLOSED: "CLOSED"
});

const PacketAction = Object.freeze({
  FORWARD: "FORWARD",
  DROP: "DROP",
  INSPECT: "INSPECT",
  LOG_ONLY: "LOG_ONLY"
});

function tupleKey(tuple) {
  return `${tuple.src_ip}|${tuple.dst_ip}|${tuple.src_port}|${tuple.dst_port}|${tuple.protocol}`;
}

class ConnectionTracker {
  constructor(fpId, maxConnections = 100000) {
    this.fpId = fpId;
    this.maxConnections = maxConnections;
    this.connections = new Map();
    this.totalSeen = 0;
    this.classifiedCount = 0;
    this.blockedCount = 0;
  }

  getOrCreateConnection(tuple) {
    const key = tupleKey(tuple);
    if (this.connections.has(key)) return this.connections.get(key);
    const reverse = tupleKey(reverseTuple(tuple));
    if (this.connections.has(reverse)) return this.connections.get(reverse);
    if (this.connections.size >= this.maxConnections) this.evictOldest();

    const now = Date.now();
    const conn = {
      tuple,
      state: ConnectionState.NEW,
      app_type: AppType.UNKNOWN,
      sni: "",
      packets_in: 0,
      packets_out: 0,
      bytes_in: 0,
      bytes_out: 0,
      first_seen: now,
      last_seen: now,
      action: PacketAction.FORWARD,
      syn_seen: false,
      syn_ack_seen: false,
      fin_seen: false
    };

    this.connections.set(key, conn);
    this.totalSeen += 1;
    return conn;
  }

  getConnection(tuple) {
    const key = tupleKey(tuple);
    if (this.connections.has(key)) return this.connections.get(key);
    const reverse = tupleKey(reverseTuple(tuple));
    return this.connections.get(reverse) ?? null;
  }

  updateConnection(conn, packetSize, isOutbound) {
    if (!conn) return;
    conn.last_seen = Date.now();
    if (isOutbound) {
      conn.packets_out += 1;
      conn.bytes_out += packetSize;
    } else {
      conn.packets_in += 1;
      conn.bytes_in += packetSize;
    }
  }

  classifyConnection(conn, app, sni) {
    if (!conn) return;
    const nextApp = app ?? conn.app_type;
    const nextSni = sni || conn.sni;

    if (conn.state !== ConnectionState.CLASSIFIED) {
      conn.app_type = nextApp;
      conn.sni = nextSni;
      conn.state = ConnectionState.CLASSIFIED;
      this.classifiedCount += 1;
      return;
    }

    const currentApp = conn.app_type ?? AppType.UNKNOWN;
    const shouldUpgradeApp =
      currentApp === AppType.UNKNOWN ||
      (isGenericAppType(currentApp) && nextApp !== AppType.UNKNOWN && !isGenericAppType(nextApp));

    if (shouldUpgradeApp) {
      conn.app_type = nextApp;
    }

    if (!conn.sni && nextSni) {
      conn.sni = nextSni;
    }
  }

  blockConnection(conn) {
    if (!conn) return;
    conn.state = ConnectionState.BLOCKED;
    conn.action = PacketAction.DROP;
    this.blockedCount += 1;
  }

  closeConnection(tuple) {
    const conn = this.connections.get(tupleKey(tuple));
    if (conn) conn.state = ConnectionState.CLOSED;
  }

  cleanupStale(timeoutSec = 300) {
    const now = Date.now();
    let removed = 0;
    for (const [key, conn] of this.connections.entries()) {
      const ageMs = now - conn.last_seen;
      if (ageMs > timeoutSec * 1000 || conn.state === ConnectionState.CLOSED) {
        this.connections.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  getAllConnections() {
    return [...this.connections.values()];
  }

  getActiveCount() {
    return this.connections.size;
  }

  getStats() {
    return {
      active_connections: this.connections.size,
      total_connections_seen: this.totalSeen,
      classified_connections: this.classifiedCount,
      blocked_connections: this.blockedCount
    };
  }

  clear() {
    this.connections.clear();
  }

  forEach(callback) {
    for (const conn of this.connections.values()) callback(conn);
  }

  evictOldest() {
    let oldestKey = null;
    let oldestTs = Number.MAX_SAFE_INTEGER;
    for (const [key, conn] of this.connections.entries()) {
      if (conn.last_seen < oldestTs) {
        oldestTs = conn.last_seen;
        oldestKey = key;
      }
    }
    if (oldestKey !== null) this.connections.delete(oldestKey);
  }
}

class GlobalConnectionTable {
  constructor(numFPs) {
    this.trackers = new Array(numFPs).fill(null);
  }

  registerTracker(fpId, tracker) {
    if (fpId >= 0 && fpId < this.trackers.length) {
      this.trackers[fpId] = tracker;
    }
  }

  getGlobalStats() {
    const appDistribution = new Map();
    const domainCounts = new Map();
    let totalActiveConnections = 0;
    let totalConnectionsSeen = 0;

    for (const tracker of this.trackers) {
      if (!tracker) continue;
      const stats = tracker.getStats();
      totalActiveConnections += stats.active_connections;
      totalConnectionsSeen += stats.total_connections_seen;

      tracker.forEach((conn) => {
        appDistribution.set(conn.app_type, (appDistribution.get(conn.app_type) ?? 0) + 1);
        if (conn.sni) {
          domainCounts.set(conn.sni, (domainCounts.get(conn.sni) ?? 0) + 1);
        }
      });
    }

    const topDomains = [...domainCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20);

    return {
      total_active_connections: totalActiveConnections,
      total_connections_seen: totalConnectionsSeen,
      app_distribution: appDistribution,
      top_domains: topDomains
    };
  }

  generateReport() {
    const stats = this.getGlobalStats();
    const lines = [];
    lines.push("\n=== CONNECTION STATISTICS REPORT ===");
    lines.push(`Active Connections: ${stats.total_active_connections}`);
    lines.push(`Total Connections Seen: ${stats.total_connections_seen}`);
    lines.push("\nApplication Breakdown:");

    const appEntries = [...stats.app_distribution.entries()].sort((a, b) => b[1] - a[1]);
    const total = appEntries.reduce((sum, [, count]) => sum + count, 0);
    for (const [app, count] of appEntries) {
      const pct = total > 0 ? ((count * 100) / total).toFixed(1) : "0.0";
      lines.push(`- ${appTypeToString(app)}: ${count} (${pct}%)`);
    }

    if (stats.top_domains.length > 0) {
      lines.push("\nTop Domains:");
      for (const [domain, count] of stats.top_domains) {
        lines.push(`- ${domain}: ${count}`);
      }
    }

    return `${lines.join("\n")}\n`;
  }
}

module.exports = {
  ConnectionTracker,
  GlobalConnectionTable,
  ConnectionState,
  PacketAction,
  tupleKey
};
