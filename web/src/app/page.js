"use client";

import { useMemo, useState } from "react";
import styles from "./page.module.css";

const APP_OPTIONS = [
  "UNKNOWN",
  "HTTP",
  "HTTPS",
  "DNS",
  "TLS",
  "QUIC",
  "GOOGLE",
  "FACEBOOK",
  "YOUTUBE",
  "TWITTER",
  "INSTAGRAM",
  "NETFLIX",
  "AMAZON",
  "MICROSOFT",
  "APPLE",
  "WHATSAPP",
  "TELEGRAM",
  "TIKTOK",
  "SPOTIFY",
  "ZOOM",
  "DISCORD",
  "GITHUB",
  "CLOUDFLARE"
];

function toMultiline(value) {
  if (!value) return "";
  return value
    .split(/[,\n]/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .join("\n");
}

function statsCards(stats = {}) {
  return [
    { label: "Total Packets", value: stats.total_packets ?? 0 },
    { label: "Forwarded", value: stats.forwarded_packets ?? 0 },
    { label: "Dropped", value: stats.dropped_packets ?? 0 },
    { label: "Drop Rate", value: `${stats.drop_rate_pct ?? 0}%` },
    { label: "TCP", value: stats.tcp_packets ?? 0 },
    { label: "UDP", value: stats.udp_packets ?? 0 }
  ];
}

function dropReasonEntries(stats = {}) {
  return Object.entries(stats.drop_reason_counts ?? {}).sort((a, b) => b[1] - a[1]);
}

export default function Home() {
  const [pcapFile, setPcapFile] = useState(null);
  const [blockIps, setBlockIps] = useState("");
  const [blockDomains, setBlockDomains] = useState("");
  const [blockPorts, setBlockPorts] = useState("");
  const [selectedApps, setSelectedApps] = useState([]);

  const [numLoadBalancers, setNumLoadBalancers] = useState(2);
  const [fpsPerLb, setFpsPerLb] = useState(2);
  const [useWorkerThreads, setUseWorkerThreads] = useState(false);
  const [verbose, setVerbose] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const cards = useMemo(() => statsCards(result?.stats), [result]);
  const dropReasons = useMemo(() => dropReasonEntries(result?.stats), [result]);
  const dropSamples = result?.stats?.drop_samples ?? [];

  function toggleApp(app) {
    setSelectedApps((prev) => {
      if (prev.includes(app)) return prev.filter((entry) => entry !== app);
      return [...prev, app];
    });
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setResult(null);

    if (!pcapFile) {
      setError("Please upload a PCAP file before processing.");
      return;
    }

    const formData = new FormData();
    formData.set("pcap", pcapFile);
    formData.set("blockIps", blockIps);
    formData.set("blockDomains", blockDomains);
    formData.set("blockPorts", blockPorts);
    formData.set("blockApps", selectedApps.join("\n"));
    formData.set("numLoadBalancers", String(numLoadBalancers));
    formData.set("fpsPerLb", String(fpsPerLb));
    formData.set("useWorkerThreads", String(useWorkerThreads));
    formData.set("verbose", String(verbose));

    setLoading(true);
    try {
      const response = await fetch("/api/dpi/process", {
        method: "POST",
        body: formData
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || "DPI processing failed");
      }

      setResult(payload);
      setBlockIps(toMultiline(payload.appliedRules?.blockIps?.join("\n") ?? ""));
      setBlockDomains(toMultiline(payload.appliedRules?.blockDomains?.join("\n") ?? ""));
      setBlockPorts(toMultiline(payload.appliedRules?.blockPorts?.join("\n") ?? ""));
    } catch (submitError) {
      setError(submitError.message);
    } finally {
      setLoading(false);
    }
  }

  function downloadOutput() {
    if (!result?.outputPcapBase64) return;
    const bytes = atob(result.outputPcapBase64);
    const data = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      data[i] = bytes.charCodeAt(i);
    }

    const blob = new Blob([data], { type: "application/vnd.tcpdump.pcap" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = result.outputFileName || "filtered_output.pcap";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div className={styles.shell}>
      <header className={styles.hero}>
        <p className={styles.badge}>Packet Analyzer UI</p>
        <h1>React Control Plane for DPI Processing</h1>
        <p>
          Upload a capture, apply IP/App/Domain/Port policies, run the DPI engine, inspect classification metrics, and download filtered PCAP output.
        </p>
      </header>

      <main className={styles.grid}>
        <section className={styles.panel}>
          <h2>Run Configuration</h2>
          <form onSubmit={handleSubmit} className={styles.form}>
            <label className={styles.field}>
              <span>Input PCAP</span>
              <input
                type="file"
                accept=".pcap"
                onChange={(event) => setPcapFile(event.target.files?.[0] ?? null)}
              />
            </label>

            <label className={styles.field}>
              <span>Block IPs (comma or newline)</span>
              <textarea
                value={blockIps}
                onChange={(event) => setBlockIps(event.target.value)}
                placeholder="192.168.1.50\n10.0.0.8"
                rows={3}
              />
            </label>

            <label className={styles.field}>
              <span>Block Domains (supports *.pattern)</span>
              <textarea
                value={blockDomains}
                onChange={(event) => setBlockDomains(event.target.value)}
                placeholder="youtube.com\n*.facebook.com"
                rows={3}
              />
            </label>

            <label className={styles.field}>
              <span>Block Ports</span>
              <textarea
                value={blockPorts}
                onChange={(event) => setBlockPorts(event.target.value)}
                placeholder="53\n443"
                rows={2}
              />
            </label>

            <div className={styles.field}>
              <span>Block Apps</span>
              <div className={styles.appGrid}>
                {APP_OPTIONS.map((app) => (
                  <button
                    type="button"
                    key={app}
                    className={`${styles.appChip} ${selectedApps.includes(app) ? styles.appChipActive : ""}`}
                    onClick={() => toggleApp(app)}
                  >
                    {app}
                  </button>
                ))}
              </div>
            </div>

            <div className={styles.row}>
              <label className={styles.field}>
                <span>Load Balancers</span>
                <input
                  type="number"
                  min="1"
                  max="16"
                  value={numLoadBalancers}
                  onChange={(event) => setNumLoadBalancers(Number.parseInt(event.target.value || "1", 10))}
                />
              </label>

              <label className={styles.field}>
                <span>Fast Paths per LB</span>
                <input
                  type="number"
                  min="1"
                  max="16"
                  value={fpsPerLb}
                  onChange={(event) => setFpsPerLb(Number.parseInt(event.target.value || "1", 10))}
                />
              </label>
            </div>

            <div className={styles.switches}>
              <label>
                <input
                  type="checkbox"
                  checked={useWorkerThreads}
                  onChange={(event) => setUseWorkerThreads(event.target.checked)}
                />
                Use worker threads
              </label>
              <label>
                <input type="checkbox" checked={verbose} onChange={(event) => setVerbose(event.target.checked)} />
                Verbose mode
              </label>
            </div>

            <button className={styles.submit} type="submit" disabled={loading}>
              {loading ? "Processing..." : "Run DPI Analysis"}
            </button>

            {error ? <p className={styles.error}>{error}</p> : null}
          </form>
        </section>

        <section className={styles.panel}>
          <h2>Output</h2>
          {!result ? <p className={styles.muted}>Run analysis to view packet metrics, classification summary, and filtered output.</p> : null}

          {result ? (
            <>
              <div className={styles.cards}>
                {cards.map((card) => (
                  <article key={card.label} className={styles.card}>
                    <p>{card.label}</p>
                    <strong>{card.value}</strong>
                  </article>
                ))}
              </div>

              <div className={styles.actions}>
                <button
                  type="button"
                  className={styles.download}
                  disabled={!result.outputPcapBase64}
                  onClick={downloadOutput}
                >
                  Download Filtered PCAP
                </button>
                {result.downloadWarning ? <p className={styles.warning}>{result.downloadWarning}</p> : null}
              </div>

              {(dropReasons.length > 0 || dropSamples.length > 0) ? (
                <section className={styles.insightCard}>
                  <div className={styles.insightHeader}>
                    <div>
                      <p className={styles.eyebrow}>Policy Insights</p>
                      <h3>Drop Reasons</h3>
                    </div>
                    <span className={styles.insightTotal}>{result.stats?.dropped_packets ?? 0} dropped</span>
                  </div>

                  {dropReasons.length > 0 ? (
                    <div className={styles.reasonGrid}>
                      {dropReasons.map(([reason, count]) => (
                        <article key={reason} className={styles.reasonTile}>
                          <span>{reason}</span>
                          <strong>{count}</strong>
                        </article>
                      ))}
                    </div>
                  ) : null}

                  {dropSamples.length > 0 ? (
                    <div className={styles.sampleSection}>
                      <p className={styles.sampleTitle}>Sample blocked matches</p>
                      <ul className={styles.sampleList}>
                        {dropSamples.map((sample, index) => (
                          <li key={`${sample.type}-${sample.detail}-${index}`}>
                            <span className={styles.sampleType}>{sample.type}</span>
                            <code>{sample.detail}</code>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </section>
              ) : null}

              <div className={styles.reportBox}>
                <h3>DPI Stats Report</h3>
                <pre>{result.reportText}</pre>
              </div>

              <div className={styles.reportBox}>
                <h3>Classification Report</h3>
                <pre>{result.classificationReportText}</pre>
              </div>
            </>
          ) : null}
        </section>
      </main>
    </div>
  );
}
