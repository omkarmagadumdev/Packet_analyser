const { parentPort, workerData } = require("worker_threads");
const { FastPathProcessor } = require("./fast_path");
const { RuleManager } = require("./rule_manager");

const fpId = workerData.fpId;
const rules = RuleManager.fromJSON(workerData.rulesState);

const fp = new FastPathProcessor(fpId, rules, (job, action) => {
  if (action === "DROP") {
    parentPort.postMessage({ type: "result", packet_id: job.packet_id, action: "DROP" });
    return;
  }

  parentPort.postMessage({
    type: "result",
    packet_id: job.packet_id,
    action: "FORWARD",
    ts_sec: job.ts_sec,
    ts_usec: job.ts_usec,
    data: job.data
  });
});

function buildClassificationSnapshot() {
  const appCounts = new Map();
  let totalClassified = 0;
  let totalUnknown = 0;
  const domainCounts = new Map();

  fp.getConnectionTracker().forEach((conn) => {
    appCounts.set(conn.app_type, (appCounts.get(conn.app_type) ?? 0) + 1);
    if (conn.app_type === "UNKNOWN") totalUnknown += 1;
    else totalClassified += 1;
    if (conn.sni) domainCounts.set(conn.sni, (domainCounts.get(conn.sni) ?? 0) + 1);
  });

  return {
    appCounts: Object.fromEntries(appCounts.entries()),
    totalClassified,
    totalUnknown,
    topDomains: [...domainCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20),
    packetAppCounts: fp.getStats().packet_app_counts,
    detectedDomains: fp.getStats().detected_domains,
    dropReasonCounts: fp.getStats().drop_reason_counts,
    dropSamples: fp.getStats().drop_samples
  };
}

parentPort.on("message", (message) => {
  if (message.type === "job") {
    const job = {
      ...message.job,
      data: Buffer.from(message.job.data)
    };
    fp.process(job);
    return;
  }

  if (message.type === "finalize") {
    const stats = fp.getStats();
    const classification = buildClassificationSnapshot();
    parentPort.postMessage({
      type: "final",
      fpId,
      stats,
      classification
    });
  }
});
