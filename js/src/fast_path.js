const { AppType, isGenericAppType, sniToAppType, appTypeToString } = require("./types");
const { ConnectionTracker, ConnectionState, PacketAction } = require("./connection_tracker");
const { extractSNI, extractHTTPHost, extractDNSQuery, extractQUICSNI } = require("./sni_extractor");

class FastPathProcessor {
  constructor(fpId, ruleManager, outputCallback) {
    this.fpId = fpId;
    this.ruleManager = ruleManager;
    this.outputCallback = outputCallback;
    this.connTracker = new ConnectionTracker(fpId);

    this.packetsProcessed = 0;
    this.packetsForwarded = 0;
    this.packetsDropped = 0;
    this.sniExtractions = 0;
    this.classificationHits = 0;
    this.packetAppCounts = new Map();
    this.detectedDomains = new Map();
    this.dropReasonCounts = new Map();
    this.dropSamples = [];
  }

  process(job) {
    this.packetsProcessed += 1;
    const result = this.processPacket(job);
    const action = result.action;
    if (this.outputCallback) this.outputCallback(job, action, result.blockReason);

    if (action === PacketAction.DROP) {
      this.packetsDropped += 1;
      this.recordDropReason(result.blockReason);
    } else {
      this.packetsForwarded += 1;
    }

    return action;
  }

  processPacket(job) {
    const conn = this.connTracker.getOrCreateConnection(job.tuple);
    this.connTracker.updateConnection(conn, job.data.length, this.isOutboundPacket(conn, job.tuple));

    if (job.tuple.protocol === 6) this.updateTCPState(conn, job.tcp_flags);
    if (conn.state === ConnectionState.BLOCKED) {
      this.recordPacketClassification(conn);
      return { action: PacketAction.DROP, blockReason: conn.block_reason ?? null };
    }

    if (this.shouldInspectConnection(conn) && job.payload_length > 0) {
      this.inspectPayload(job, conn);
    }

    const result = this.checkRules(job, conn);
    this.recordPacketClassification(conn);
    return result;
  }

  recordPacketClassification(conn) {
    const appType = conn?.app_type ?? AppType.UNKNOWN;
    this.packetAppCounts.set(appType, (this.packetAppCounts.get(appType) ?? 0) + 1);

    if (conn?.sni && !this.detectedDomains.has(conn.sni)) {
      this.detectedDomains.set(conn.sni, conn.app_type ?? AppType.UNKNOWN);
    }
  }

  inspectPayload(job, conn) {
    if (job.payload_length === 0 || job.payload_offset >= job.data.length) return;
    const payload = job.data.subarray(job.payload_offset);

    if (this.tryExtractSNI(job, conn, payload)) return;
    if (this.tryExtractQUICSNI(job, conn, payload)) return;
    if (this.tryExtractHTTPHost(job, conn, payload)) return;

    if (job.tuple.dst_port === 53 || job.tuple.src_port === 53) {
      const domain = extractDNSQuery(payload);
      if (domain) {
        const app = sniToAppType(domain);
        this.connTracker.classifyConnection(conn, app === AppType.HTTPS ? AppType.DNS : app, domain);
        if (app !== AppType.UNKNOWN && app !== AppType.DNS && app !== AppType.HTTPS) this.classificationHits += 1;
        return;
      }
    }

    if (job.tuple.dst_port === 80) this.connTracker.classifyConnection(conn, AppType.HTTP, "");
    else if (job.tuple.protocol === 17 && (job.tuple.dst_port === 443 || job.tuple.src_port === 443)) this.connTracker.classifyConnection(conn, AppType.QUIC, "");
    else if (job.tuple.dst_port === 443 || job.tuple.src_port === 443) this.connTracker.classifyConnection(conn, AppType.HTTPS, "");
  }

  tryExtractSNI(job, conn, payload) {
    if ((job.tuple.dst_port !== 443 && job.tuple.src_port !== 443) || job.payload_length < 50) return false;
    const sni = extractSNI(payload);
    if (!sni) return false;

    this.sniExtractions += 1;
    const app = sniToAppType(sni);
    this.connTracker.classifyConnection(conn, app, sni);
    if (app !== AppType.UNKNOWN && app !== AppType.HTTPS) this.classificationHits += 1;
    return true;
  }

  tryExtractQUICSNI(job, conn, payload) {
    if (job.tuple.protocol !== 17) return false;
    if (job.tuple.dst_port !== 443 && job.tuple.src_port !== 443) return false;

    const sni = extractQUICSNI(payload);
    if (!sni) return false;

    this.sniExtractions += 1;
    const app = sniToAppType(sni);
    this.connTracker.classifyConnection(conn, app, sni);
    if (app !== AppType.UNKNOWN && app !== AppType.QUIC && app !== AppType.HTTPS) this.classificationHits += 1;
    return true;
  }

  tryExtractHTTPHost(job, conn, payload) {
    if (job.tuple.dst_port !== 80) return false;
    const host = extractHTTPHost(payload);
    if (!host) return false;

    const app = sniToAppType(host);
    this.connTracker.classifyConnection(conn, app, host);
    if (app !== AppType.UNKNOWN && app !== AppType.HTTP) this.classificationHits += 1;
    return true;
  }

  checkRules(job, conn) {
    if (!this.ruleManager) return { action: PacketAction.FORWARD, blockReason: null };
    const isDnsPacket = job.tuple.dst_port === 53 || job.tuple.src_port === 53;
    const appForRules = isDnsPacket ? AppType.DNS : conn.app_type;
    const domainForRules = isDnsPacket ? "" : conn.sni;
    const blockReason = this.ruleManager.shouldBlock(job.tuple.src_ip, job.tuple.dst_port, appForRules, domainForRules);
    if (!blockReason) return { action: PacketAction.FORWARD, blockReason: null };

    conn.block_reason = blockReason;
    this.connTracker.blockConnection(conn);
    return { action: PacketAction.DROP, blockReason };
  }

  isOutboundPacket(conn, tuple) {
    if (!conn?.tuple) return true;
    return conn.tuple.src_ip === tuple.src_ip &&
      conn.tuple.dst_ip === tuple.dst_ip &&
      conn.tuple.src_port === tuple.src_port &&
      conn.tuple.dst_port === tuple.dst_port &&
      conn.tuple.protocol === tuple.protocol;
  }

  recordDropReason(blockReason) {
    if (!blockReason?.type) return;
    this.dropReasonCounts.set(blockReason.type, (this.dropReasonCounts.get(blockReason.type) ?? 0) + 1);

    if (this.dropSamples.length < 10) {
      this.dropSamples.push({
        type: blockReason.type,
        detail: blockReason.detail ?? ""
      });
    }
  }

  shouldInspectConnection(conn) {
    if (!conn) return false;
    if (conn.state === ConnectionState.BLOCKED || conn.state === ConnectionState.CLOSED) return false;
    return conn.state !== ConnectionState.CLASSIFIED || isGenericAppType(conn.app_type) || !conn.sni;
  }

  updateTCPState(conn, flags) {
    const SYN = 0x02;
    const ACK = 0x10;
    const FIN = 0x01;
    const RST = 0x04;

    if (flags & SYN) {
      if (flags & ACK) conn.syn_ack_seen = true;
      else conn.syn_seen = true;
    }
    if (conn.syn_seen && conn.syn_ack_seen && (flags & ACK) && conn.state === ConnectionState.NEW) {
      conn.state = ConnectionState.ESTABLISHED;
    }
    if (flags & FIN) conn.fin_seen = true;
    if (flags & RST) conn.state = ConnectionState.CLOSED;
    if (conn.fin_seen && (flags & ACK)) conn.state = ConnectionState.CLOSED;
  }

  getStats() {
    return {
      packets_processed: this.packetsProcessed,
      packets_forwarded: this.packetsForwarded,
      packets_dropped: this.packetsDropped,
      connections_tracked: this.connTracker.getActiveCount(),
      sni_extractions: this.sniExtractions,
      classification_hits: this.classificationHits,
      packet_app_counts: Object.fromEntries(this.packetAppCounts.entries()),
      detected_domains: [...this.detectedDomains.entries()],
      drop_reason_counts: Object.fromEntries(this.dropReasonCounts.entries()),
      drop_samples: this.dropSamples
    };
  }

  getConnectionTracker() {
    return this.connTracker;
  }
}

class FPManager {
  constructor(numFPs, ruleManager, outputCallback) {
    this.fps = [];
    for (let i = 0; i < numFPs; i++) {
      this.fps.push(new FastPathProcessor(i, ruleManager, outputCallback));
    }
  }

  getFP(id) {
    return this.fps[id];
  }

  getNumFPs() {
    return this.fps.length;
  }

  getAggregatedStats() {
    const stats = {
      total_processed: 0,
      total_forwarded: 0,
      total_dropped: 0,
      total_connections: 0,
      drop_reason_counts: new Map(),
      drop_samples: []
    };
    for (const fp of this.fps) {
      const fpStats = fp.getStats();
      stats.total_processed += fpStats.packets_processed;
      stats.total_forwarded += fpStats.packets_forwarded;
      stats.total_dropped += fpStats.packets_dropped;
      stats.total_connections += fpStats.connections_tracked;
      for (const [reason, count] of Object.entries(fpStats.drop_reason_counts ?? {})) {
        stats.drop_reason_counts.set(reason, (stats.drop_reason_counts.get(reason) ?? 0) + count);
      }
      for (const sample of fpStats.drop_samples ?? []) {
        if (stats.drop_samples.length >= 10) break;
        stats.drop_samples.push(sample);
      }
    }
    return stats;
  }

  generateClassificationReport() {
    const appCounts = new Map();
    let totalClassified = 0;
    let totalUnknown = 0;

    for (const fp of this.fps) {
      fp.getConnectionTracker().forEach((conn) => {
        appCounts.set(conn.app_type, (appCounts.get(conn.app_type) ?? 0) + 1);
        if (conn.app_type === AppType.UNKNOWN) totalUnknown += 1;
        else totalClassified += 1;
      });
    }

    const total = totalClassified + totalUnknown;
    const classifiedPct = total > 0 ? ((100 * totalClassified) / total).toFixed(1) : "0.0";
    const unknownPct = total > 0 ? ((100 * totalUnknown) / total).toFixed(1) : "0.0";

    const lines = [];
    lines.push("\n=== APPLICATION CLASSIFICATION REPORT ===");
    lines.push(`Total Connections: ${total}`);
    lines.push(`Classified: ${totalClassified} (${classifiedPct}%)`);
    lines.push(`Unidentified: ${totalUnknown} (${unknownPct}%)`);
    lines.push("Application Distribution:");

    const sortedApps = [...appCounts.entries()].sort((a, b) => b[1] - a[1]);
    for (const [app, count] of sortedApps) {
      const pct = total > 0 ? ((100 * count) / total).toFixed(1) : "0.0";
      lines.push(`- ${appTypeToString(app)}: ${count} (${pct}%)`);
    }

    return `${lines.join("\n")}\n`;
  }

  getPacketClassificationSummary() {
    const appCounts = new Map();
    const detectedDomains = new Map();
    let totalPackets = 0;

    for (const fp of this.fps) {
      const fpStats = fp.getStats();
      totalPackets += fpStats.packets_processed;

      for (const [app, count] of Object.entries(fpStats.packet_app_counts ?? {})) {
        appCounts.set(app, (appCounts.get(app) ?? 0) + count);
      }

      for (const [domain, app] of fpStats.detected_domains ?? []) {
        if (!detectedDomains.has(domain)) detectedDomains.set(domain, app);
      }
    }

    return {
      totalPackets,
      appCounts,
      detectedDomains
    };
  }
}

module.exports = {
  FastPathProcessor,
  FPManager
};
