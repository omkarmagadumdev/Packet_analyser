#!/usr/bin/env node
const path = require("path");

async function main() {
  try {
    const encoded = process.argv[2] || "";
    if (!encoded) {
      process.stdout.write(JSON.stringify({ ok: false, error: "Missing payload." }));
      return;
    }

    const payload = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
    const {
      inputPath,
      outputPath,
      config = {},
      blockIps = [],
      blockDomains = [],
      blockApps = [],
      blockPorts = []
    } = payload;

    const engineFile = path.resolve(__dirname, "..", "..", "js", "src", "dpi_engine.js");
    const { DPIEngine } = require(engineFile);

    const engine = new DPIEngine(config);
    if (!engine.initialize()) {
      process.stdout.write(JSON.stringify({ ok: false, error: "Failed to initialize DPI engine." }));
      return;
    }

    for (const ip of blockIps) engine.blockIP(ip);
    for (const app of blockApps) engine.blockApp(app);
    for (const domain of blockDomains) engine.blockDomain(domain);
    for (const port of blockPorts) engine.blockPort(port);

    const success = await engine.processFile(inputPath, outputPath);
    if (!success) {
      process.stdout.write(JSON.stringify({ ok: false, error: "DPI engine failed to process file." }));
      return;
    }

    const stats = engine.getStats();
    const dropRate =
      stats.total_packets > 0
        ? ((100 * stats.dropped_packets) / stats.total_packets).toFixed(2)
        : "0.00";

    process.stdout.write(
      JSON.stringify({
        ok: true,
        stats,
        dropRate,
        reportText: engine.generateReport(),
        classificationReportText: engine.generateClassificationReport()
      })
    );
  } catch (error) {
    process.stdout.write(JSON.stringify({ ok: false, error: error?.message || "Runner failure." }));
  }
}

main();
