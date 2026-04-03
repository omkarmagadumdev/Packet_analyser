const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { DPIEngine } = require("../src/dpi_engine");

test("single-thread DPI run produces drop-reason reporting for the sample capture", async () => {
  const inputFile = path.resolve(__dirname, "../../test_dpi.pcap");
  const outputFile = path.join(os.tmpdir(), `dpi-test-${process.pid}-${Date.now()}.pcap`);

  const engine = new DPIEngine({
    use_worker_threads: false,
    num_load_balancers: 2,
    fps_per_lb: 2
  });

  try {
    assert.equal(engine.initialize(), true);
    engine.blockApp("YouTube");
    engine.blockApp("TikTok");
    engine.blockIP("192.168.1.50");
    engine.blockDomain("facebook");

    const success = await engine.processFile(inputFile, outputFile);
    assert.equal(success, true);

    const stats = engine.getStats();
    assert.equal(stats.total_packets, 77);
    assert.ok(stats.dropped_packets > 0);
    assert.ok((stats.drop_reason_counts.APP ?? 0) > 0 || (stats.drop_reason_counts.DOMAIN ?? 0) > 0);

    const report = engine.generateReport();
    assert.match(report, /Drop Reasons:/);
    assert.match(report, /Sample Drop Details:/);
  } finally {
    fs.rmSync(outputFile, { force: true });
  }
});
