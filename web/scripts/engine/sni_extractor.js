function readUint16BE(buffer, offset) {
  return (buffer[offset] << 8) | buffer[offset + 1];
}

function readUint24BE(buffer, offset) {
  return (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
}

function isTLSClientHello(payload) {
  if (!payload || payload.length < 9) return false;
  if (payload[0] !== 0x16) return false;
  const version = readUint16BE(payload, 1);
  if (version < 0x0300 || version > 0x0304) return false;
  const recordLen = readUint16BE(payload, 3);
  if (recordLen > payload.length - 5) return false;
  return payload[5] === 0x01;
}

function extractSNI(payload) {
  if (!isTLSClientHello(payload)) return null;
  let offset = 5;
  const handshakeLength = readUint24BE(payload, offset + 1);
  offset += 4;
  if (handshakeLength <= 0) return null;

  offset += 2;
  offset += 32;
  if (offset >= payload.length) return null;

  const sessionIdLength = payload[offset];
  offset += 1 + sessionIdLength;
  if (offset + 2 > payload.length) return null;

  const cipherSuitesLength = readUint16BE(payload, offset);
  offset += 2 + cipherSuitesLength;
  if (offset >= payload.length) return null;

  const compressionMethodsLength = payload[offset];
  offset += 1 + compressionMethodsLength;
  if (offset + 2 > payload.length) return null;

  const extensionsLength = readUint16BE(payload, offset);
  offset += 2;
  const extensionsEnd = Math.min(offset + extensionsLength, payload.length);

  while (offset + 4 <= extensionsEnd) {
    const extensionType = readUint16BE(payload, offset);
    const extensionLength = readUint16BE(payload, offset + 2);
    offset += 4;
    if (offset + extensionLength > extensionsEnd) break;

    if (extensionType === 0x0000) {
      if (extensionLength < 5) break;
      const sniListLength = readUint16BE(payload, offset);
      if (sniListLength < 3) break;
      const sniType = payload[offset + 2];
      const sniLength = readUint16BE(payload, offset + 3);
      if (sniType !== 0x00) break;
      if (sniLength > extensionLength - 5) break;
      return payload.subarray(offset + 5, offset + 5 + sniLength).toString("utf8");
    }

    offset += extensionLength;
  }

  return null;
}

function isHTTPRequest(payload) {
  if (!payload || payload.length < 4) return false;
  const head = payload.subarray(0, 4).toString("ascii");
  return ["GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"].includes(head);
}

function extractHTTPHost(payload) {
  if (!isHTTPRequest(payload)) return null;
  const text = payload.toString("latin1");
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    if (line.toLowerCase().startsWith("host:")) {
      const value = line.slice(5).trim();
      if (!value) return null;
      const idx = value.indexOf(":");
      return idx >= 0 ? value.slice(0, idx) : value;
    }
  }
  return null;
}

function isDNSQuery(payload) {
  if (!payload || payload.length < 12) return false;
  const flags = payload[2];
  if (flags & 0x80) return false;
  const qdcount = readUint16BE(payload, 4);
  return qdcount > 0;
}

function extractDNSQuery(payload) {
  if (!isDNSQuery(payload)) return null;
  let offset = 12;
  const labels = [];

  while (offset < payload.length) {
    const len = payload[offset];
    if (len === 0) break;
    if (len > 63) break;
    offset += 1;
    if (offset + len > payload.length) break;
    labels.push(payload.subarray(offset, offset + len).toString("ascii"));
    offset += len;
  }

  if (labels.length === 0) return null;
  return labels.join(".");
}

function isQUICInitial(payload) {
  if (!payload || payload.length < 5) return false;
  return (payload[0] & 0x80) !== 0;
}

function extractQUICSNI(payload) {
  if (!isQUICInitial(payload)) return null;
  for (let i = 0; i + 50 < payload.length; i++) {
    if (payload[i] === 0x01 && i >= 5) {
      const maybe = extractSNI(payload.subarray(i - 5));
      if (maybe) return maybe;
    }
  }
  return null;
}

module.exports = {
  isTLSClientHello,
  extractSNI,
  isHTTPRequest,
  extractHTTPHost,
  isDNSQuery,
  extractDNSQuery,
  isQUICInitial,
  extractQUICSNI
};
