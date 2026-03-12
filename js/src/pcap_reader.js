const fs = require("fs");

const PCAP_MAGIC_NATIVE = 0xa1b2c3d4;
const PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

function swap16(value) {
  return ((value & 0xff00) >>> 8) | ((value & 0x00ff) << 8);
}

function swap32(value) {
  return (((value & 0xff000000) >>> 24) | ((value & 0x00ff0000) >>> 8) | ((value & 0x0000ff00) << 8) | ((value & 0x000000ff) << 24)) >>> 0;
}

class PcapReader {
  constructor() {
    this.fd = null;
    this.position = 0;
    this.needsByteSwap = false;
    this.globalHeader = null;
  }

  open(filename) {
    this.close();
    this.fd = fs.openSync(filename, "r");

    const header = Buffer.alloc(24);
    const read = fs.readSync(this.fd, header, 0, 24, this.position);
    if (read !== 24) {
      this.close();
      return false;
    }
    this.position += 24;

    const magic = header.readUInt32LE(0);
    if (magic === PCAP_MAGIC_NATIVE) {
      this.needsByteSwap = false;
    } else if (magic === PCAP_MAGIC_SWAPPED) {
      this.needsByteSwap = true;
    } else {
      this.close();
      return false;
    }

    const maybe16 = (off) => {
      const raw = header.readUInt16LE(off);
      return this.needsByteSwap ? swap16(raw) : raw;
    };
    const maybe32 = (off) => {
      const raw = header.readUInt32LE(off);
      return this.needsByteSwap ? swap32(raw) : raw;
    };

    this.globalHeader = {
      magic_number: magic,
      version_major: maybe16(4),
      version_minor: maybe16(6),
      thiszone: header.readInt32LE(8),
      sigfigs: maybe32(12),
      snaplen: maybe32(16),
      network: maybe32(20)
    };

    return true;
  }

  close() {
    if (this.fd !== null) {
      fs.closeSync(this.fd);
      this.fd = null;
    }
    this.position = 0;
    this.needsByteSwap = false;
    this.globalHeader = null;
  }

  readNextPacket() {
    if (this.fd === null) return null;

    const packetHeaderBuf = Buffer.alloc(16);
    const readHeader = fs.readSync(this.fd, packetHeaderBuf, 0, 16, this.position);
    if (readHeader !== 16) return null;
    this.position += 16;

    const maybe32 = (off) => {
      const raw = packetHeaderBuf.readUInt32LE(off);
      return this.needsByteSwap ? swap32(raw) : raw;
    };

    const header = {
      ts_sec: maybe32(0),
      ts_usec: maybe32(4),
      incl_len: maybe32(8),
      orig_len: maybe32(12)
    };

    if (!this.globalHeader || header.incl_len > this.globalHeader.snaplen || header.incl_len > 65535) {
      return null;
    }

    const data = Buffer.alloc(header.incl_len);
    const readData = fs.readSync(this.fd, data, 0, header.incl_len, this.position);
    if (readData !== header.incl_len) return null;
    this.position += header.incl_len;

    return { header, data };
  }
}

module.exports = { PcapReader };
