const fs = require("fs");
const path = require("path");
const { Worker } = require("worker_threads");
const { PcapReader } = require("./pcap_reader");
const packetParser = require("./packet_parser");
const { RuleManager } = require("./rule_manager");
const { FPManager } = require("./fast_path");
const { LBManager } = require("./load_balancer");
const { GlobalConnectionTable } = require("./connection_tracker");
const { AppType, appTypeToString, ipToInt, fiveTupleHash } = require("./types");

function normalizeAppName(value) {
  return String(value ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "");
}

class DPIEngine {
  constructor(config = {}) {
    this.config = {
      num_load_balancers: config.num_load_balancers ?? 2,
      fps_per_lb: config.fps_per_lb ?? 2,
      queue_size: config.queue_size ?? 10000,
      rules_file: config.rules_file ?? "",
      verbose: config.verbose ?? false,
      use_worker_threads: config.use_worker_threads ?? true
    };

    this.ruleManager = null;
    this.fpManager = null;
    this.lbManager = null;
    this.globalConnTable = null;

    this.stats = {
      total_packets: 0,
      total_bytes: 0,
      forwarded_packets: 0,
      dropped_packets: 0,
      tcp_packets: 0,
      udp_packets: 0,
      other_packets: 0,
      active_connections: 0
    };

    this.outputFd = null;

    this.fpWorkers = [];
    this.fpWorkerFinalPromises = [];
    this.fpWorkerFinalStats = [];
    this.fpWorkerClassification = [];
    this.pendingWorkerPackets = 0;
    this.readerDone = false;
    this.finalizeSent = false;
    this.workerDispatchStats = { total_received: 0, total_dispatched: 0 };
    this.workerPerFPDispatched = [];
  }

  initialize() {
    this.ruleManager = new RuleManager();
    if (this.config.rules_file) this.ruleManager.loadRules(this.config.rules_file);

    if (this.config.use_worker_threads) {
      return true;
    }

    const outputCallback = (job, action) => this.handleOutput(job, action);
    const totalFPs = this.config.num_load_balancers * this.config.fps_per_lb;
    this.fpManager = new FPManager(totalFPs, this.ruleManager, outputCallback);
    this.lbManager = new LBManager(this.config.num_load_balancers, this.config.fps_per_lb, this.fpManager);

    this.globalConnTable = new GlobalConnectionTable(totalFPs);
    for (let i = 0; i < totalFPs; i++) {
      this.globalConnTable.registerTracker(i, this.fpManager.getFP(i).getConnectionTracker());
    }
    return true;
  }

  async processFile(inputFile, outputFile) {
    if (this.config.use_worker_threads) {
      return this.processFileWithWorkers(inputFile, outputFile);
    }
    return this.processFileSingleThread(inputFile, outputFile);
  }

  processFileSingleThread(inputFile, outputFile) {
    if (!this.ruleManager) this.initialize();

    const reader = new PcapReader();
    if (!reader.open(inputFile)) {
      console.error("[DPIEngine] Error: cannot open input file");
      return false;
    }

    this.outputFd = fs.openSync(outputFile, "w");
    this.writeOutputHeader(reader.globalHeader);

    let packetId = 0;
    while (true) {
      const raw = reader.readNextPacket();
      if (!raw) break;

      const parsed = packetParser.parse(raw);
      if (!parsed) continue;
      if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

      const job = this.createPacketJob(raw, parsed, packetId++);
      this.stats.total_packets += 1;
      this.stats.total_bytes += raw.data.length;
      if (parsed.has_tcp) this.stats.tcp_packets += 1;
      else if (parsed.has_udp) this.stats.udp_packets += 1;
      else this.stats.other_packets += 1;

      const lb = this.lbManager.getLBForPacket(job.tuple);
      lb.dispatch(job);
    }

    reader.close();
    fs.closeSync(this.outputFd);
    this.outputFd = null;

    return true;
  }

  async processFileWithWorkers(inputFile, outputFile) {
    if (!this.ruleManager) this.initialize();

    const reader = new PcapReader();
    if (!reader.open(inputFile)) {
      console.error("[DPIEngine] Error: cannot open input file");
      return false;
    }

    this.outputFd = fs.openSync(outputFile, "w");
    this.writeOutputHeader(reader.globalHeader);

    await this.startFPWorkers();

    let packetId = 0;
    while (true) {
      const raw = reader.readNextPacket();
      if (!raw) break;

      const parsed = packetParser.parse(raw);
      if (!parsed) continue;
      if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

      const job = this.createPacketJob(raw, parsed, packetId++);
      this.stats.total_packets += 1;
      this.stats.total_bytes += raw.data.length;
      if (parsed.has_tcp) this.stats.tcp_packets += 1;
      else if (parsed.has_udp) this.stats.udp_packets += 1;
      else this.stats.other_packets += 1;

      const workerIndex = this.selectWorkerIndex(job.tuple);
      this.pendingWorkerPackets += 1;
      this.workerDispatchStats.total_received += 1;
      this.workerDispatchStats.total_dispatched += 1;
      this.workerPerFPDispatched[workerIndex] += 1;

      this.fpWorkers[workerIndex].postMessage({ type: "job", job });
    }

    reader.close();
    this.readerDone = true;
    this.maybeFinalizeWorkers();

    await Promise.all(this.fpWorkerFinalPromises);
    await this.stopFPWorkers();

    fs.closeSync(this.outputFd);
    this.outputFd = null;
    return true;
  }

  async startFPWorkers() {
    this.fpWorkers = [];
    this.fpWorkerFinalPromises = [];
    this.fpWorkerFinalStats = [];
    this.fpWorkerClassification = [];
    this.pendingWorkerPackets = 0;
    this.readerDone = false;
    this.finalizeSent = false;
    this.workerDispatchStats = { total_received: 0, total_dispatched: 0 };

    const totalFPs = this.config.num_load_balancers * this.config.fps_per_lb;
    this.workerPerFPDispatched = new Array(totalFPs).fill(0);
    const workerFile = path.join(__dirname, "fp_worker.js");
    const rulesState = this.ruleManager.toJSON();

    for (let fpId = 0; fpId < totalFPs; fpId++) {
      const worker = new Worker(workerFile, {
        workerData: {
          fpId,
          rulesState
        }
      });

      const finalPromise = new Promise((resolve, reject) => {
        worker.on("message", (message) => {
          if (message.type === "result") {
            this.pendingWorkerPackets -= 1;
            if (message.action === "DROP") {
              this.stats.dropped_packets += 1;
            } else {
              this.stats.forwarded_packets += 1;
              this.writeOutputPacket({
                ts_sec: message.ts_sec,
                ts_usec: message.ts_usec,
                data: Buffer.from(message.data)
              });
            }
            this.maybeFinalizeWorkers();
            return;
          }

          if (message.type === "final") {
            this.fpWorkerFinalStats.push(message.stats);
            this.fpWorkerClassification.push(message.classification);
            resolve();
          }
        });

        worker.on("error", (error) => {
          reject(error);
        });

        worker.on("exit", (code) => {
          if (code !== 0) {
            reject(new Error(`FP worker ${fpId} exited with code ${code}`));
          }
        });
      });

      this.fpWorkers.push(worker);
      this.fpWorkerFinalPromises.push(finalPromise);
    }
  }

  maybeFinalizeWorkers() {
    if (!this.readerDone || this.pendingWorkerPackets !== 0 || this.finalizeSent) return;
    this.finalizeSent = true;
    for (const worker of this.fpWorkers) {
      worker.postMessage({ type: "finalize" });
    }
  }

  async stopFPWorkers() {
    const workers = this.fpWorkers;
    this.fpWorkers = [];
    await Promise.all(workers.map((worker) => worker.terminate()));
  }

  selectWorkerIndex(tuple) {
    const hash = fiveTupleHash(tuple);
    return hash % this.fpWorkers.length;
  }

  createPacketJob(raw, parsed, packetId) {
    const data = raw.data;
    const job = {
      packet_id: packetId,
      ts_sec: raw.header.ts_sec,
      ts_usec: raw.header.ts_usec,
      tuple: {
        src_ip: ipToInt(parsed.src_ip),
        dst_ip: ipToInt(parsed.dest_ip),
        src_port: parsed.src_port,
        dst_port: parsed.dest_port,
        protocol: parsed.protocol
      },
      tcp_flags: parsed.tcp_flags,
      data,
      eth_offset: 0,
      ip_offset: 14,
      transport_offset: 0,
      payload_offset: 0,
      payload_length: 0
    };

    if (data.length > 14) {
      const ihl = data[14] & 0x0f;
      const ipHeaderLen = ihl * 4;
      job.transport_offset = 14 + ipHeaderLen;

      if (parsed.has_tcp && data.length > job.transport_offset + 12) {
        const tcpDataOffset = (data[job.transport_offset + 12] >>> 4) & 0x0f;
        const tcpHeaderLen = tcpDataOffset * 4;
        job.payload_offset = job.transport_offset + tcpHeaderLen;
      } else if (parsed.has_udp) {
        job.payload_offset = job.transport_offset + 8;
      }

      if (job.payload_offset < data.length) {
        job.payload_length = data.length - job.payload_offset;
      }
    }

    return job;
  }

  handleOutput(job, action) {
    if (action === "DROP") {
      this.stats.dropped_packets += 1;
      return;
    }
    this.stats.forwarded_packets += 1;
    this.writeOutputPacket(job);
  }

  writeOutputHeader(header) {
    const buf = Buffer.alloc(24);
    buf.writeUInt32LE(header.magic_number >>> 0, 0);
    buf.writeUInt16LE(header.version_major & 0xffff, 4);
    buf.writeUInt16LE(header.version_minor & 0xffff, 6);
    buf.writeInt32LE(header.thiszone ?? 0, 8);
    buf.writeUInt32LE((header.sigfigs ?? 0) >>> 0, 12);
    buf.writeUInt32LE((header.snaplen ?? 65535) >>> 0, 16);
    buf.writeUInt32LE((header.network ?? 1) >>> 0, 20);
    fs.writeSync(this.outputFd, buf);
  }

  writeOutputPacket(job) {
    const header = Buffer.alloc(16);
    header.writeUInt32LE(job.ts_sec >>> 0, 0);
    header.writeUInt32LE(job.ts_usec >>> 0, 4);
    header.writeUInt32LE(job.data.length >>> 0, 8);
    header.writeUInt32LE(job.data.length >>> 0, 12);
    fs.writeSync(this.outputFd, header);
    fs.writeSync(this.outputFd, job.data);
  }

  blockIP(ip) {
    if (this.ruleManager) this.ruleManager.blockIP(ip);
  }

  unblockIP(ip) {
    if (this.ruleManager) this.ruleManager.unblockIP(ip);
  }

  blockApp(appOrName) {
    if (!this.ruleManager) return;
    if (Object.values(AppType).includes(appOrName)) {
      this.ruleManager.blockApp(appOrName);
      return;
    }
    const normalized = normalizeAppName(appOrName);
    const match = Object.values(AppType).find((app) => {
      return normalizeAppName(appTypeToString(app)) === normalized || normalizeAppName(app) === normalized;
    });
    if (match) this.ruleManager.blockApp(match);
  }

  unblockApp(appOrName) {
    if (!this.ruleManager) return;
    if (Object.values(AppType).includes(appOrName)) {
      this.ruleManager.unblockApp(appOrName);
      return;
    }
    const normalized = normalizeAppName(appOrName);
    const match = Object.values(AppType).find((app) => {
      return normalizeAppName(appTypeToString(app)) === normalized || normalizeAppName(app) === normalized;
    });
    if (match) this.ruleManager.unblockApp(match);
  }

  blockDomain(domain) {
    if (this.ruleManager) this.ruleManager.blockDomain(domain);
  }

  unblockDomain(domain) {
    if (this.ruleManager) this.ruleManager.unblockDomain(domain);
  }

  blockPort(port) {
    if (this.ruleManager) this.ruleManager.blockPort(port);
  }

  unblockPort(port) {
    if (this.ruleManager) this.ruleManager.unblockPort(port);
  }

  loadRules(filename) {
    return this.ruleManager ? this.ruleManager.loadRules(filename) : false;
  }

  saveRules(filename) {
    return this.ruleManager ? this.ruleManager.saveRules(filename) : false;
  }

  getDropDiagnostics() {
    const counts = new Map();
    const samples = [];

    if (this.config.use_worker_threads) {
      for (const stats of this.fpWorkerFinalStats) {
        for (const [reason, count] of Object.entries(stats.drop_reason_counts ?? {})) {
          counts.set(reason, (counts.get(reason) ?? 0) + count);
        }
        for (const sample of stats.drop_samples ?? []) {
          if (samples.length >= 10) break;
          samples.push(sample);
        }
      }
    } else if (this.fpManager) {
      const aggregated = this.fpManager.getAggregatedStats();
      for (const [reason, count] of aggregated.drop_reason_counts.entries()) {
        counts.set(reason, (counts.get(reason) ?? 0) + count);
      }
      samples.push(...aggregated.drop_samples.slice(0, 10));
    }

    return {
      counts,
      samples
    };
  }

  generateReport() {
    const lines = [];
    lines.push("\n=== DPI ENGINE STATISTICS ===");
    lines.push(`Total Packets: ${this.stats.total_packets}`);
    lines.push(`Total Bytes: ${this.stats.total_bytes}`);
    lines.push(`TCP Packets: ${this.stats.tcp_packets}`);
    lines.push(`UDP Packets: ${this.stats.udp_packets}`);
    lines.push(`Forwarded: ${this.stats.forwarded_packets}`);
    lines.push(`Dropped: ${this.stats.dropped_packets}`);
    if (this.stats.total_packets > 0) {
      const dropRate = ((100 * this.stats.dropped_packets) / this.stats.total_packets).toFixed(2);
      lines.push(`Drop Rate: ${dropRate}%`);
    }

    if (this.config.use_worker_threads) {
      lines.push(`LB Received: ${this.workerDispatchStats.total_received}`);
      lines.push(`LB Dispatched: ${this.workerDispatchStats.total_dispatched}`);
      lines.push("THREAD STATISTICS:");

      for (let lb = 0; lb < this.config.num_load_balancers; lb++) {
        const start = lb * this.config.fps_per_lb;
        const end = start + this.config.fps_per_lb;
        const lbDispatched = this.workerPerFPDispatched.slice(start, end).reduce((sum, value) => sum + value, 0);
        lines.push(`  LB${lb} dispatched: ${lbDispatched}`);
      }

      for (let fp = 0; fp < this.workerPerFPDispatched.length; fp++) {
        lines.push(`  FP${fp} processed: ${this.workerPerFPDispatched[fp]}`);
      }
    } else if (this.lbManager) {
      const lbStats = this.lbManager.getAggregatedStats();
      lines.push(`LB Received: ${lbStats.total_received}`);
      lines.push(`LB Dispatched: ${lbStats.total_dispatched}`);
    }

    if (this.config.use_worker_threads) {
      const fpStats = this.fpWorkerFinalStats.reduce(
        (acc, stats) => {
          acc.total_processed += stats.packets_processed;
          acc.total_forwarded += stats.packets_forwarded;
          acc.total_dropped += stats.packets_dropped;
          acc.total_connections += stats.connections_tracked;
          return acc;
        },
        { total_processed: 0, total_forwarded: 0, total_dropped: 0, total_connections: 0 }
      );
      lines.push(`FP Processed: ${fpStats.total_processed}`);
      lines.push(`FP Forwarded: ${fpStats.total_forwarded}`);
      lines.push(`FP Dropped: ${fpStats.total_dropped}`);
      lines.push(`Active Connections: ${fpStats.total_connections}`);
    } else if (this.fpManager) {
      const fpStats = this.fpManager.getAggregatedStats();
      lines.push(`FP Processed: ${fpStats.total_processed}`);
      lines.push(`FP Forwarded: ${fpStats.total_forwarded}`);
      lines.push(`FP Dropped: ${fpStats.total_dropped}`);
      lines.push(`Active Connections: ${fpStats.total_connections}`);
    }

    if (this.ruleManager) {
      const ruleStats = this.ruleManager.getStats();
      lines.push(`Blocked IPs: ${ruleStats.blocked_ips}`);
      lines.push(`Blocked Apps: ${ruleStats.blocked_apps}`);
      lines.push(`Blocked Domains: ${ruleStats.blocked_domains}`);
      lines.push(`Blocked Ports: ${ruleStats.blocked_ports}`);
    }

    const dropDiagnostics = this.getDropDiagnostics();
    if (dropDiagnostics.counts.size > 0) {
      lines.push("Drop Reasons:");
      for (const [reason, count] of [...dropDiagnostics.counts.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
        lines.push(`  ${reason}: ${count}`);
      }
    }
    if (dropDiagnostics.samples.length > 0) {
      lines.push("Sample Drop Details:");
      for (const sample of dropDiagnostics.samples) {
        lines.push(`  ${sample.type}: ${sample.detail}`);
      }
    }

    return `${lines.join("\n")}\n`;
  }

  generateClassificationReport() {
    if (this.config.use_worker_threads) {
      const appCounts = new Map();
      const packetAppCounts = new Map();
      const detectedDomains = new Map();
      let totalClassified = 0;
      let totalUnknown = 0;

      for (const part of this.fpWorkerClassification) {
        totalClassified += part.totalClassified;
        totalUnknown += part.totalUnknown;

        for (const [app, count] of Object.entries(part.appCounts)) {
          appCounts.set(app, (appCounts.get(app) ?? 0) + count);
        }

        for (const [app, count] of Object.entries(part.packetAppCounts ?? {})) {
          packetAppCounts.set(app, (packetAppCounts.get(app) ?? 0) + count);
        }

        for (const [domain, app] of part.detectedDomains ?? []) {
          if (!detectedDomains.has(domain)) detectedDomains.set(domain, app);
        }
      }

      const total = totalClassified + totalUnknown;
      const classifiedPct = total > 0 ? ((100 * totalClassified) / total).toFixed(1) : "0.0";
      const unknownPct = total > 0 ? ((100 * totalUnknown) / total).toFixed(1) : "0.0";
      const totalPackets = [...packetAppCounts.values()].reduce((sum, value) => sum + value, 0);

      const lines = [];
      lines.push("\n=== APPLICATION CLASSIFICATION REPORT ===");
      lines.push(`Total Connections: ${total}`);
      lines.push(`Classified: ${totalClassified} (${classifiedPct}%)`);
      lines.push(`Unidentified: ${totalUnknown} (${unknownPct}%)`);
      lines.push("Application Distribution (Connections):");

      const sortedApps = [...appCounts.entries()].sort((a, b) => b[1] - a[1]);
      for (const [app, count] of sortedApps) {
        const pct = total > 0 ? ((100 * count) / total).toFixed(1) : "0.0";
        lines.push(`- ${appTypeToString(app)}: ${count} (${pct}%)`);
      }

      lines.push("\nApplication Breakdown (Packets):");
      const sortedPacketApps = [...packetAppCounts.entries()].sort((a, b) => b[1] - a[1]);
      for (const [app, count] of sortedPacketApps) {
        const pct = totalPackets > 0 ? ((100 * count) / totalPackets).toFixed(1) : "0.0";
        lines.push(`- ${appTypeToString(app)}: ${count} (${pct}%)`);
      }

      lines.push("\nDetected Domains/SNIs:");
      const sortedDomains = [...detectedDomains.entries()].sort((a, b) => a[0].localeCompare(b[0]));
      for (const [domain, app] of sortedDomains) {
        lines.push(`- ${domain} -> ${appTypeToString(app)}`);
      }

      return `${lines.join("\n")}\n`;
    }

    if (!this.fpManager) return "";

    const baseReport = this.fpManager.generateClassificationReport().trimEnd();
    const packetSummary = this.fpManager.getPacketClassificationSummary();
    const lines = [baseReport, "", "Application Breakdown (Packets):"];

    const sortedPacketApps = [...packetSummary.appCounts.entries()].sort((a, b) => b[1] - a[1]);
    for (const [app, count] of sortedPacketApps) {
      const pct = packetSummary.totalPackets > 0 ? ((100 * count) / packetSummary.totalPackets).toFixed(1) : "0.0";
      lines.push(`- ${appTypeToString(app)}: ${count} (${pct}%)`);
    }

    lines.push("", "Detected Domains/SNIs:");
    const sortedDomains = [...packetSummary.detectedDomains.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    for (const [domain, app] of sortedDomains) {
      lines.push(`- ${domain} -> ${appTypeToString(app)}`);
    }

    return `${lines.join("\n")}\n`;
  }

  getStats() {
    const dropDiagnostics = this.getDropDiagnostics();
    return {
      ...this.stats,
      drop_reason_counts: Object.fromEntries(dropDiagnostics.counts.entries()),
      drop_samples: dropDiagnostics.samples
    };
  }

  printStatus() {
    console.log(`Packets=${this.stats.total_packets} Forwarded=${this.stats.forwarded_packets} Dropped=${this.stats.dropped_packets}`);
  }
}

module.exports = {
  DPIEngine
};
