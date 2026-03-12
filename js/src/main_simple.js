#!/usr/bin/env node
const { PcapReader } = require("./pcap_reader");
const packetParser = require("./packet_parser");

function printUsage(program) {
  console.log(`Usage: ${program} <pcap_file> [max_packets]`);
}

function printPacketSummary(pkt, packetNum) {
  const date = new Date(pkt.timestamp_sec * 1000);
  const ts = `${date.toISOString().replace("T", " ").replace("Z", "")}.${String(pkt.timestamp_usec).padStart(6, "0")}`;

  console.log(`\n========== Packet #${packetNum} ==========`);
  console.log(`Time: ${ts}`);
  console.log("\n[Ethernet]");
  console.log(`  Source MAC:      ${pkt.src_mac}`);
  console.log(`  Destination MAC: ${pkt.dest_mac}`);
  console.log(`  EtherType:       0x${pkt.ether_type.toString(16).padStart(4, "0")}`);

  if (pkt.has_ip) {
    console.log(`\n[IPv${pkt.ip_version}]`);
    console.log(`  Source IP:      ${pkt.src_ip}`);
    console.log(`  Destination IP: ${pkt.dest_ip}`);
    console.log(`  Protocol:       ${packetParser.protocolToString(pkt.protocol)}`);
    console.log(`  TTL:            ${pkt.ttl}`);
  }

  if (pkt.has_tcp) {
    console.log("\n[TCP]");
    console.log(`  Source Port:      ${pkt.src_port}`);
    console.log(`  Destination Port: ${pkt.dest_port}`);
    console.log(`  Sequence Number:  ${pkt.seq_number}`);
    console.log(`  Ack Number:       ${pkt.ack_number}`);
    console.log(`  Flags:            ${packetParser.tcpFlagsToString(pkt.tcp_flags)}`);
  }

  if (pkt.has_udp) {
    console.log("\n[UDP]");
    console.log(`  Source Port:      ${pkt.src_port}`);
    console.log(`  Destination Port: ${pkt.dest_port}`);
  }

  if (pkt.payload_length > 0 && pkt.payload_data) {
    console.log("\n[Payload]");
    console.log(`  Length: ${pkt.payload_length} bytes`);
    const previewLen = Math.min(pkt.payload_length, 32);
    const preview = [...pkt.payload_data.subarray(0, previewLen)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
    console.log(`  Preview: ${preview}${pkt.payload_length > 32 ? " ..." : ""}`);
  }
}

function main() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    printUsage(process.argv[1]);
    process.exit(1);
  }

  const filename = args[0];
  const maxPackets = args.length >= 2 ? Number.parseInt(args[1], 10) : -1;

  const reader = new PcapReader();
  if (!reader.open(filename)) {
    console.error(`Failed to open ${filename}`);
    process.exit(1);
  }

  let packetCount = 0;
  let parseErrors = 0;

  while (true) {
    const raw = reader.readNextPacket();
    if (!raw) break;
    packetCount += 1;

    const parsed = packetParser.parse(raw);
    if (parsed) printPacketSummary(parsed, packetCount);
    else {
      console.error(`Warning: Failed to parse packet #${packetCount}`);
      parseErrors += 1;
    }

    if (maxPackets > 0 && packetCount >= maxPackets) {
      console.log(`\n(Stopped after ${maxPackets} packets)`);
      break;
    }
  }

  reader.close();
  console.log("\n====================================");
  console.log("Summary:");
  console.log(`  Total packets read:  ${packetCount}`);
  console.log(`  Parse errors:        ${parseErrors}`);
  console.log("====================================");
}

main();
