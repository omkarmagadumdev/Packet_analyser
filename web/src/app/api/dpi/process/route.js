import { randomUUID } from "crypto";
import { execFile } from "child_process";
import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { promisify } from "util";

export const runtime = "nodejs";
export const maxDuration = 60;
const execFileAsync = promisify(execFile);

function parseList(value) {
  if (!value) return [];
  return String(value)
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseIntSafe(value, fallback, min, max) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.max(min, Math.min(parsed, max));
}

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === "") return fallback;
  return String(value).toLowerCase() === "true";
}

function toPcapName(originalName) {
  const base = originalName?.replace(/\.pcap$/i, "") || "capture";
  return `${base}_filtered.pcap`;
}

export async function POST(request) {
  let inputPath = "";
  let outputPath = "";

  try {
    const form = await request.formData();
    const pcap = form.get("pcap");

    if (!pcap || typeof pcap === "string") {
      return Response.json({ error: "A PCAP file is required." }, { status: 400 });
    }

    const blockIps = parseList(form.get("blockIps"));
    const blockDomains = parseList(form.get("blockDomains"));
    const blockApps = parseList(form.get("blockApps"));
    const blockPorts = parseList(form.get("blockPorts"))
      .map((value) => Number.parseInt(value, 10))
      .filter((value) => Number.isInteger(value) && value >= 1 && value <= 65535);

    const config = {
      num_load_balancers: parseIntSafe(form.get("numLoadBalancers"), 2, 1, 16),
      fps_per_lb: parseIntSafe(form.get("fpsPerLb"), 2, 1, 16),
      verbose: parseBoolean(form.get("verbose"), false),
      use_worker_threads: parseBoolean(form.get("useWorkerThreads"), false)
    };

    const id = randomUUID();
    inputPath = path.join(os.tmpdir(), `${id}.pcap`);
    outputPath = path.join(os.tmpdir(), `${id}_out.pcap`);

    const pcapBuffer = Buffer.from(await pcap.arrayBuffer());
    await fs.writeFile(inputPath, pcapBuffer);

    const runner = path.resolve(process.cwd(), "scripts", "run_dpi_job.cjs");
    const payload = {
      inputPath,
      outputPath,
      config,
      blockIps,
      blockDomains,
      blockApps,
      blockPorts
    };

    const { stdout } = await execFileAsync("node", [runner, Buffer.from(JSON.stringify(payload), "utf8").toString("base64")], {
      maxBuffer: 1024 * 1024 * 8
    });

    const result = JSON.parse(stdout || "{}");
    if (!result.ok) {
      return Response.json({ error: result.error || "DPI engine could not process the uploaded file." }, { status: 500 });
    }

    const outputBuffer = await fs.readFile(outputPath);
    const maxInlineSize = 3 * 1024 * 1024;

    return Response.json({
      stats: {
        ...result.stats,
        drop_rate_pct: result.dropRate
      },
      config,
      reportText: result.reportText,
      classificationReportText: result.classificationReportText,
      outputFileName: toPcapName(pcap.name),
      outputPcapBase64: outputBuffer.length <= maxInlineSize ? outputBuffer.toString("base64") : null,
      downloadWarning:
        outputBuffer.length <= maxInlineSize
          ? ""
          : "Filtered PCAP is larger than inline transfer limits for this route. Reduce input size or stream output via object storage for production deployments.",
      appliedRules: {
        blockIps,
        blockDomains,
        blockApps,
        blockPorts
      }
    });
  } catch (error) {
    return Response.json(
      {
        error: error?.message || "Unexpected error while processing DPI request."
      },
      { status: 500 }
    );
  } finally {
    if (inputPath) await fs.rm(inputPath, { force: true }).catch(() => {});
    if (outputPath) await fs.rm(outputPath, { force: true }).catch(() => {});
  }
}