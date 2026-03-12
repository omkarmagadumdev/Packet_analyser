const EtherType = Object.freeze({
  IPv4: 0x0800,
  IPv6: 0x86dd,
  ARP: 0x0806
});

const Protocol = Object.freeze({
  ICMP: 1,
  TCP: 6,
  UDP: 17
});

const TCPFlags = Object.freeze({
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20
});

function macToString(buffer, offset) {
  const bytes = [];
  for (let i = 0; i < 6; i++) {
    bytes.push(buffer[offset + i].toString(16).padStart(2, "0"));
  }
  return bytes.join(":");
}

function ipFromNetworkBytesToInt(buffer, offset) {
  return ((buffer[offset] & 0xff) | ((buffer[offset + 1] & 0xff) << 8) | ((buffer[offset + 2] & 0xff) << 16) | ((buffer[offset + 3] & 0xff) << 24)) >>> 0;
}

function ipToString(ip) {
  return `${ip & 0xff}.${(ip >>> 8) & 0xff}.${(ip >>> 16) & 0xff}.${(ip >>> 24) & 0xff}`;
}

function protocolToString(protocol) {
  if (protocol === Protocol.ICMP) return "ICMP";
  if (protocol === Protocol.TCP) return "TCP";
  if (protocol === Protocol.UDP) return "UDP";
  return `Unknown(${protocol})`;
}

function tcpFlagsToString(flags) {
  const result = [];
  if (flags & TCPFlags.SYN) result.push("SYN");
  if (flags & TCPFlags.ACK) result.push("ACK");
  if (flags & TCPFlags.FIN) result.push("FIN");
  if (flags & TCPFlags.RST) result.push("RST");
  if (flags & TCPFlags.PSH) result.push("PSH");
  if (flags & TCPFlags.URG) result.push("URG");
  return result.length > 0 ? result.join(" ") : "none";
}

function parse(rawPacket) {
  const parsed = {
    timestamp_sec: rawPacket.header.ts_sec,
    timestamp_usec: rawPacket.header.ts_usec,
    src_mac: "",
    dest_mac: "",
    ether_type: 0,
    has_ip: false,
    ip_version: 0,
    src_ip: "",
    dest_ip: "",
    protocol: 0,
    ttl: 0,
    has_tcp: false,
    has_udp: false,
    src_port: 0,
    dest_port: 0,
    tcp_flags: 0,
    seq_number: 0,
    ack_number: 0,
    payload_length: 0,
    payload_data: null
  };

  const data = rawPacket.data;
  if (data.length < 14) return null;

  let offset = 0;
  parsed.dest_mac = macToString(data, 0);
  parsed.src_mac = macToString(data, 6);
  parsed.ether_type = data.readUInt16BE(12);
  offset = 14;

  if (parsed.ether_type === EtherType.IPv4) {
    if (data.length < offset + 20) return null;
    const versionIhl = data[offset];
    parsed.ip_version = (versionIhl >>> 4) & 0x0f;
    const ihl = versionIhl & 0x0f;
    if (parsed.ip_version !== 4) return null;

    const ipHeaderLen = ihl * 4;
    if (ipHeaderLen < 20 || data.length < offset + ipHeaderLen) return null;

    parsed.ttl = data[offset + 8];
    parsed.protocol = data[offset + 9];
    parsed.src_ip = ipToString(ipFromNetworkBytesToInt(data, offset + 12));
    parsed.dest_ip = ipToString(ipFromNetworkBytesToInt(data, offset + 16));
    parsed.has_ip = true;
    offset += ipHeaderLen;

    if (parsed.protocol === Protocol.TCP) {
      if (data.length < offset + 20) return null;
      parsed.src_port = data.readUInt16BE(offset);
      parsed.dest_port = data.readUInt16BE(offset + 2);
      parsed.seq_number = data.readUInt32BE(offset + 4);
      parsed.ack_number = data.readUInt32BE(offset + 8);
      const dataOffset = (data[offset + 12] >>> 4) & 0x0f;
      const tcpHeaderLen = dataOffset * 4;
      parsed.tcp_flags = data[offset + 13];
      if (tcpHeaderLen < 20 || data.length < offset + tcpHeaderLen) return null;
      parsed.has_tcp = true;
      offset += tcpHeaderLen;
    } else if (parsed.protocol === Protocol.UDP) {
      if (data.length < offset + 8) return null;
      parsed.src_port = data.readUInt16BE(offset);
      parsed.dest_port = data.readUInt16BE(offset + 2);
      parsed.has_udp = true;
      offset += 8;
    }
  }

  if (offset < data.length) {
    parsed.payload_length = data.length - offset;
    parsed.payload_data = data.subarray(offset);
  }

  return parsed;
}

module.exports = {
  EtherType,
  Protocol,
  TCPFlags,
  parse,
  macToString,
  ipToString,
  protocolToString,
  tcpFlagsToString
};
