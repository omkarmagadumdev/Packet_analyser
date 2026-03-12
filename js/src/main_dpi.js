#!/usr/bin/env node
const { DPIEngine } = require("./dpi_engine");

function printUsage(program) {
  console.log(`Usage: ${program} <input.pcap> <output.pcap> [options]`);
  console.log("\nOptions:");
  console.log("  --block-ip <ip>");
  console.log("  --block-app <app>");
  console.log("  --block-domain <domain>");
  console.log("  --rules <file>");
  console.log("  --lbs <n>");
  console.log("  --fps <n>");
  console.log("  --worker-threads");
  console.log("  --no-worker-threads");
  console.log("  --verbose");
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length < 2 || argv.includes("--help") || argv.includes("-h")) {
    printUsage(process.argv[1]);
    process.exit(argv.length >= 2 ? 0 : 1);
  }

  const inputFile = argv[0];
  const outputFile = argv[1];

  const config = {
    num_load_balancers: 2,
    fps_per_lb: 2,
    verbose: false,
    rules_file: "",
    use_worker_threads: true
  };

  const blockIPs = [];
  const blockApps = [];
  const blockDomains = [];

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--block-ip" && i + 1 < argv.length) blockIPs.push(argv[++i]);
    else if (arg === "--block-app" && i + 1 < argv.length) blockApps.push(argv[++i]);
    else if (arg === "--block-domain" && i + 1 < argv.length) blockDomains.push(argv[++i]);
    else if (arg === "--rules" && i + 1 < argv.length) config.rules_file = argv[++i];
    else if (arg === "--lbs" && i + 1 < argv.length) config.num_load_balancers = Number.parseInt(argv[++i], 10);
    else if (arg === "--fps" && i + 1 < argv.length) config.fps_per_lb = Number.parseInt(argv[++i], 10);
    else if (arg === "--worker-threads") config.use_worker_threads = true;
    else if (arg === "--no-worker-threads") config.use_worker_threads = false;
    else if (arg === "--verbose") config.verbose = true;
  }

  const engine = new DPIEngine(config);
  if (!engine.initialize()) {
    console.error("Failed to initialize DPI engine");
    process.exit(1);
  }

  if (config.rules_file) engine.loadRules(config.rules_file);
  for (const ip of blockIPs) engine.blockIP(ip);
  for (const app of blockApps) engine.blockApp(app);
  for (const domain of blockDomains) engine.blockDomain(domain);

  const ok = await engine.processFile(inputFile, outputFile);
  if (!ok) {
    console.error("Failed to process file");
    process.exit(1);
  }

  console.log("\nProcessing complete!");
  console.log(`Output written to: ${outputFile}`);
  console.log(engine.generateReport());
  console.log(engine.generateClassificationReport());
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
