// PCAP and PCAPNG Binary Parser for XoIP VoIP Forensics
// Supports Classic PCAP (.pcap, .cap) and PCAPNG (.pcapng) formats
// Dissects Ethernet, Linux Cooked (SLL/SLL2), IPv4, IPv6, UDP, TCP, SIP, RTP, RTCP, TLS

export interface DissectedPacket {
  id: string;
  timestamp: string; // ISO string
  rawTimestampMs: number;
  sourceIP: string;
  destIP: string;
  sourcePort: number;
  destPort: number;
  protocol: 'SIP' | 'RTP' | 'RTCP' | 'UDP' | 'TCP' | 'TLS' | string;
  method: string;
  status: string;
  size: number;
  encrypted: boolean;
  suspicious: boolean;
  callType?: 'incoming' | 'outgoing' | 'internal' | 'conference';
  alertType?: 'failed-calls' | 'malformed' | 'suspicious-ip' | 'auth-failure' | 'unusual-ports';
  metadata: Record<string, string | number | boolean>;
  rawBytes?: Uint8Array;
  payloadBytes?: Uint8Array;
  rtpData?: {
    payloadType: number;
    payloadName: string;
    sequenceNumber: number;
    timestamp: number;
    ssrc: number;
    marker: boolean;
    audioPayload?: Uint8Array;
  };
}

export interface ParsePcapResult {
  packets: DissectedPacket[];
  summary: {
    totalPackets: number;
    sipPackets: number;
    rtpPackets: number;
    rtcpPackets: number;
    encryptedPackets: number;
    suspiciousPackets: number;
    durationMs: number;
    startTime?: Date;
    endTime?: Date;
  };
}

// Map of standard RTP payload types to names
const RTP_PAYLOAD_MAP: Record<number, string> = {
  0: 'PCMU (G.711 µ-law)',
  3: 'GSM',
  4: 'G.723',
  8: 'PCMA (G.711 A-law)',
  9: 'G.722',
  18: 'G.729',
  101: 'telephone-event (DTMF)',
  111: 'Opus (dynamic)',
};

// Helper to safely convert any serialized binary data back to Uint8Array
export function toUint8Array(val: unknown): Uint8Array | undefined {
  if (!val) return undefined;
  if (val instanceof Uint8Array) return val;
  if (Array.isArray(val)) return new Uint8Array(val);
  if (typeof val === 'object') {
    const obj = val as Record<string, unknown>;
    if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
      return new Uint8Array(obj.data);
    }
    const keys = Object.keys(obj);
    if (keys.length > 0 && !isNaN(Number(keys[0]))) {
      const arr = new Uint8Array(keys.length);
      for (let i = 0; i < keys.length; i++) {
        arr[i] = Number(obj[i]) || 0;
      }
      return arr;
    }
  }
  return undefined;
}

// Normalizes a packet that may have been deserialized from JSON / WebSocket
export function normalizePacket(raw: Record<string, unknown> | DissectedPacket): DissectedPacket {
  if (!raw) return raw as DissectedPacket;
  const p = raw as unknown as DissectedPacket;
  return {
    ...p,
    rawBytes: toUint8Array(p.rawBytes),
    payloadBytes: toUint8Array(p.payloadBytes),
    rtpData: p.rtpData ? {
      ...p.rtpData,
      audioPayload: toUint8Array(p.rtpData.audioPayload)
    } : undefined
  };
}

export class PcapParser {
  /**
   * Main entry point to parse a File or ArrayBuffer (supports .pcap, .cap, .pcapng)
   */
  static async parse(fileOrBuffer: File | ArrayBuffer): Promise<ParsePcapResult> {
    const buffer = fileOrBuffer instanceof File
      ? await fileOrBuffer.arrayBuffer()
      : fileOrBuffer;

    const dataView = new DataView(buffer);
    if (dataView.byteLength < 24) {
      throw new Error('File too small to be a valid capture file (minimum 24 bytes required).');
    }

    const first32 = dataView.getUint32(0, false);

    // PCAPNG Magic: 0x0A0D0D0A (Section Header Block)
    if (first32 === 0x0a0d0d0a) {
      return this.parsePcapNg(buffer);
    }

    // Classic PCAP Magics:
    // 0xa1b2c3d4 (Big Endian, microseconds)
    // 0xd4c3b2a1 (Little Endian, microseconds)
    // 0xa1b23c4d (Big Endian, nanoseconds)
    // 0x4d3cb2a1 (Little Endian, nanoseconds)
    const isPcapLE = (first32 === 0xd4c3b2a1 || first32 === 0x4d3cb2a1);
    const isPcapBE = (first32 === 0xa1b2c3d4 || first32 === 0xa1b23c4d);

    if (isPcapLE || isPcapBE) {
      const isNano = (first32 === 0xa1b23c4d || first32 === 0x4d3cb2a1);
      return this.parseClassicPcap(buffer, isPcapLE, isNano);
    }

    throw new Error('Unrecognized packet capture format. Must be a valid .pcap or .pcapng file.');
  }

  /**
   * Parses standard libpcap format
   */
  private static parseClassicPcap(buffer: ArrayBuffer, littleEndian: boolean, isNanoseconds: boolean): ParsePcapResult {
    const view = new DataView(buffer);
    const snaplen = view.getUint32(16, littleEndian);
    const network = view.getUint32(20, littleEndian); // Link Layer Type

    const packets: DissectedPacket[] = [];
    let offset = 24;
    const totalBytes = buffer.byteLength;
    let packetIndex = 0;

    while (offset + 16 <= totalBytes) {
      const tsSec = view.getUint32(offset, littleEndian);
      const tsSub = view.getUint32(offset + 4, littleEndian);
      const inclLen = view.getUint32(offset + 8, littleEndian);
      const origLen = view.getUint32(offset + 12, littleEndian);
      offset += 16;

      if (offset + inclLen > totalBytes) {
        // truncated packet at end of file
        break;
      }

      const rawPacket = new Uint8Array(buffer, offset, inclLen);
      offset += inclLen;

      // Calculate timestamp in milliseconds
      const subMs = isNanoseconds ? Math.floor(tsSub / 1_000_000) : Math.floor(tsSub / 1_000);
      const timestampMs = tsSec * 1000 + subMs;

      const packet = this.dissectFrame(rawPacket, network, timestampMs, packetIndex++, origLen);
      if (packet) {
        packets.push(packet);
      }
    }

    return this.buildResult(packets);
  }

  /**
   * Parses PCAP Next Generation (pcapng) format
   */
  private static parsePcapNg(buffer: ArrayBuffer): ParsePcapResult {
    const view = new DataView(buffer);
    let offset = 0;
    const totalBytes = buffer.byteLength;
    let littleEndian = true; // default, will be adjusted by Section Header Block
    let tsResol = 1_000_000; // default 10^-6 (microseconds)
    let linkType = 1; // default Ethernet
    const packets: DissectedPacket[] = [];
    let packetIndex = 0;

    while (offset + 8 <= totalBytes) {
      const blockType = view.getUint32(offset, littleEndian);
      let blockTotalLength = view.getUint32(offset + 4, littleEndian);

      // Section Header Block (SHB) type is 0x0A0D0D0A regardless of endianness
      if (blockType === 0x0a0d0d0a) {
        // Byte Order Magic at offset + 8
        const byteOrderMagic = view.getUint32(offset + 8, false);
        if (byteOrderMagic === 0x1a2b3c4d) {
          littleEndian = false;
        } else if (byteOrderMagic === 0x4d3c2b1a) {
          littleEndian = true;
        }
        // re-read block total length with detected endianness
        blockTotalLength = view.getUint32(offset + 4, littleEndian);
      }

      if (blockTotalLength < 12 || offset + blockTotalLength > totalBytes) {
        break;
      }

      // Interface Description Block (IDB): 0x00000001
      if (blockType === 0x00000001) {
        linkType = view.getUint16(offset + 8, littleEndian);
        // Look for if_tsresol in options
        let optOffset = offset + 16;
        const optEnd = offset + blockTotalLength - 4;
        while (optOffset + 4 <= optEnd) {
          const optCode = view.getUint16(optOffset, littleEndian);
          const optLen = view.getUint16(optOffset + 2, littleEndian);
          optOffset += 4;
          if (optCode === 9 && optLen === 1 && optOffset < optEnd) {
            // if_tsresol
            const val = view.getUint8(optOffset);
            const isBinary = (val & 0x80) !== 0;
            const exp = val & 0x7f;
            tsResol = isBinary ? Math.pow(2, exp) : Math.pow(10, exp);
          }
          if (optCode === 0) break; // opt_endofopt
          optOffset += (optLen + 3) & ~3; // 32-bit aligned
        }
      }

      // Enhanced Packet Block (EPB): 0x00000006
      if (blockType === 0x00000006) {
        const tsHigh = view.getUint32(offset + 12, littleEndian);
        const tsLow = view.getUint32(offset + 16, littleEndian);
        const capLen = view.getUint32(offset + 20, littleEndian);
        const origLen = view.getUint32(offset + 24, littleEndian);

        const tsUnits = BigInt(tsHigh) * BigInt(4294967296) + BigInt(tsLow);
        const timestampMs = Number(tsUnits * BigInt(1000) / BigInt(tsResol));

        const packetDataOffset = offset + 28;
        if (packetDataOffset + capLen <= offset + blockTotalLength) {
          const rawPacket = new Uint8Array(buffer, packetDataOffset, capLen);
          const packet = this.dissectFrame(rawPacket, linkType, timestampMs, packetIndex++, origLen);
          if (packet) {
            packets.push(packet);
          }
        }
      }

      // Simple Packet Block (SPB): 0x00000003
      if (blockType === 0x00000003) {
        const origLen = view.getUint32(offset + 8, littleEndian);
        const capLen = Math.min(origLen, blockTotalLength - 16);
        const rawPacket = new Uint8Array(buffer, offset + 12, capLen);
        const packet = this.dissectFrame(rawPacket, linkType, Date.now(), packetIndex++, origLen);
        if (packet) {
          packets.push(packet);
        }
      }

      // Move to next block (32-bit aligned)
      offset += (blockTotalLength + 3) & ~3;
    }

    return this.buildResult(packets);
  }

  /**
   * Dissects Link Layer, IP, Transport, and Application Layer protocols
   */
  public static dissectFrame(
    frame: Uint8Array,
    linkType: number,
    timestampMs: number,
    index: number,
    origLen: number
  ): DissectedPacket | null {
    if (frame.length < 14) return null;

    let ipOffset = 0;
    let etherType = 0x0800; // default IPv4

    // 1: DLT_EN10MB (Ethernet II)
    if (linkType === 1) {
      etherType = (frame[12] << 8) | frame[13];
      ipOffset = 14;

      // 802.1Q VLAN Tagging
      if (etherType === 0x8100 && frame.length >= 18) {
        etherType = (frame[16] << 8) | frame[17];
        ipOffset = 18;
      }
    }
    // 113: DLT_LINUX_SLL (Linux Cooked Capture v1)
    else if (linkType === 113) {
      if (frame.length < 16) return null;
      etherType = (frame[14] << 8) | frame[15];
      ipOffset = 16;
    }
    // 276: DLT_LINUX_SLL2 (Linux Cooked Capture v2)
    else if (linkType === 276) {
      if (frame.length < 20) return null;
      etherType = (frame[0] << 8) | frame[1];
      ipOffset = 20;
    }
    // 0: DLT_NULL / Loopback
    else if (linkType === 0) {
      if (frame.length < 4) return null;
      // 4-byte family: 2 is AF_INET
      etherType = 0x0800;
      ipOffset = 4;
    }
    // 12 or 101: Raw IP
    else if (linkType === 12 || linkType === 101) {
      const version = (frame[0] >> 4) & 0x0f;
      etherType = version === 6 ? 0x86dd : 0x0800;
      ipOffset = 0;
    } else {
      // Default assume Ethernet
      etherType = (frame[12] << 8) | frame[13];
      ipOffset = 14;
    }

    let sourceIP = '';
    let destIP = '';
    let ipProtocol = 0;
    let transportOffset = ipOffset;

    // IPv4 (0x0800)
    if (etherType === 0x0800) {
      if (frame.length < ipOffset + 20) return null;
      const ihl = (frame[ipOffset] & 0x0f) * 4;
      ipProtocol = frame[ipOffset + 9];
      sourceIP = `${frame[ipOffset + 12]}.${frame[ipOffset + 13]}.${frame[ipOffset + 14]}.${frame[ipOffset + 15]}`;
      destIP = `${frame[ipOffset + 16]}.${frame[ipOffset + 17]}.${frame[ipOffset + 18]}.${frame[ipOffset + 19]}`;
      transportOffset = ipOffset + ihl;
    }
    // IPv6 (0x86DD)
    else if (etherType === 0x86dd) {
      if (frame.length < ipOffset + 40) return null;
      ipProtocol = frame[ipOffset + 6];
      sourceIP = this.formatIPv6(frame.subarray(ipOffset + 8, ipOffset + 24));
      destIP = this.formatIPv6(frame.subarray(ipOffset + 24, ipOffset + 40));
      transportOffset = ipOffset + 40;
    } else {
      // Non-IP packet (ARP, etc.) - ignore for VoIP forensics
      return null;
    }

    let sourcePort = 0;
    let destPort = 0;
    let appOffset = transportOffset;
    let isTcp = false;
    let isUdp = false;

    // UDP (Protocol 17)
    if (ipProtocol === 17) {
      if (frame.length < transportOffset + 8) return null;
      sourcePort = (frame[transportOffset] << 8) | frame[transportOffset + 1];
      destPort = (frame[transportOffset + 2] << 8) | frame[transportOffset + 3];
      appOffset = transportOffset + 8;
      isUdp = true;
    }
    // TCP (Protocol 6)
    else if (ipProtocol === 6) {
      if (frame.length < transportOffset + 20) return null;
      sourcePort = (frame[transportOffset] << 8) | frame[transportOffset + 1];
      destPort = (frame[transportOffset + 2] << 8) | frame[transportOffset + 3];
      const dataOffset = ((frame[transportOffset + 12] >> 4) & 0x0f) * 4;
      appOffset = transportOffset + dataOffset;
      isTcp = true;
    } else {
      // Other IP protocol (ICMP, etc.)
      return null;
    }

    const payload = frame.subarray(appOffset);
    const packetId = `pkt-${index + 1}-${Date.now().toString(36)}`;
    const date = new Date(timestampMs > 0 ? timestampMs : Date.now());

    // Dissect Application / VoIP layer
    return this.dissectVoipPayload({
      id: packetId,
      timestamp: date.toISOString(),
      rawTimestampMs: date.getTime(),
      sourceIP,
      destIP,
      sourcePort,
      destPort,
      size: origLen || frame.length,
      payload,
      isTcp,
      isUdp,
      rawFrame: frame
    });
  }

  /**
   * Dissects SIP, RTP, RTCP, TLS or generic UDP/TCP payload
   */
  private static dissectVoipPayload(params: {
    id: string;
    timestamp: string;
    rawTimestampMs: number;
    sourceIP: string;
    destIP: string;
    sourcePort: number;
    destPort: number;
    size: number;
    payload: Uint8Array;
    isTcp: boolean;
    isUdp: boolean;
    rawFrame: Uint8Array;
  }): DissectedPacket {
    const { id, timestamp, rawTimestampMs, sourceIP, destIP, sourcePort, destPort, size, payload, isTcp, isUdp, rawFrame } = params;

    const basePacket: DissectedPacket = {
      id,
      timestamp,
      rawTimestampMs,
      sourceIP,
      destIP,
      sourcePort,
      destPort,
      protocol: isUdp ? 'UDP' : isTcp ? 'TCP' : 'IP',
      method: isUdp ? `UDP ${sourcePort}→${destPort}` : `TCP ${sourcePort}→${destPort}`,
      status: 'Captured',
      size,
      encrypted: false,
      suspicious: false,
      metadata: {},
      rawBytes: rawFrame,
      payloadBytes: payload
    };

    if (payload.length === 0) {
      return basePacket;
    }

    // 1. Check for TLS / Encrypted SIP (Port 5061, or TLS Record Header: 0x16/0x17, 0x03, 0x01/0x02/0x03)
    if (
      sourcePort === 5061 || destPort === 5061 ||
      (payload.length >= 5 && (payload[0] === 22 || payload[0] === 23) && payload[1] === 3 && payload[2] <= 4)
    ) {
      basePacket.protocol = 'TLS';
      basePacket.encrypted = true;
      basePacket.method = payload[0] === 22 ? 'TLS Handshake' : 'TLS Application Data';
      basePacket.status = 'Encrypted Stream';
      basePacket.metadata = {
        'TLS Version': `TLS 1.${payload[2] - 1}`,
        'Record Type': payload[0] === 22 ? 'Handshake' : 'Application Data',
        'Payload Length': (payload[3] << 8) | payload[4]
      };
      return basePacket;
    }

    // 2. Check for SIP (Session Initiation Protocol)
    const textPreview = this.decodeAscii(payload, Math.min(payload.length, 512));
    const isSipPort = sourcePort === 5060 || destPort === 5060 || sourcePort === 5080 || destPort === 5080;
    const isSipHeader = (
      textPreview.startsWith('SIP/2.0 ') ||
      /^(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|PRACK|SUBSCRIBE|NOTIFY|PUBLISH|INFO|REFER|MESSAGE|UPDATE) /i.test(textPreview)
    );

    if (isSipPort || isSipHeader) {
      return this.dissectSip(basePacket, payload, textPreview);
    }

    // 3. Check for RTCP (Payload Type 200..204)
    if (payload.length >= 8) {
      const v = (payload[0] >> 6) & 0x03;
      const pt = payload[1];
      if (v === 2 && pt >= 200 && pt <= 204) {
        return this.dissectRtcp(basePacket, payload);
      }
    }

    // 4. Check for RTP (Real-time Transport Protocol)
    // RTP Header: V=2 (2 bits), P (1 bit), X (1 bit), CC (4 bits), M (1 bit), PT (7 bits), Seq (16 bits)
    if (payload.length >= 12) {
      const v = (payload[0] >> 6) & 0x03;
      const pt = payload[1] & 0x7f;
      // Valid RTP version is 2, and payload type is 0..127
      // Typically VoIP RTP uses UDP ports >= 1024
      if (v === 2 && isUdp && (sourcePort >= 1024 || destPort >= 1024)) {
        return this.dissectRtp(basePacket, payload);
      }
    }

    // Default UDP / TCP packet
    if (isUdp) {
      basePacket.protocol = 'UDP';
      basePacket.method = `UDP Port ${destPort}`;
      basePacket.status = `${payload.length} bytes`;
    } else {
      basePacket.protocol = 'TCP';
      basePacket.method = `TCP Port ${destPort}`;
      basePacket.status = `${payload.length} bytes`;
    }

    return basePacket;
  }

  /**
   * Dissect SIP message
   */
  private static dissectSip(packet: DissectedPacket, payload: Uint8Array, text: string): DissectedPacket {
    packet.protocol = 'SIP';
    const lines = text.split(/\r?\n/);
    const firstLine = lines[0] || '';

    let method = 'SIP';
    let status = '200 OK';
    let isResponse = false;

    if (firstLine.startsWith('SIP/2.0 ')) {
      // SIP Response: SIP/2.0 200 OK
      isResponse = true;
      status = firstLine.substring(8).trim();
      const code = status.split(' ')[0] || '';
      method = `SIP ${code}`;
    } else {
      // SIP Request: INVITE sip:alice@example.com SIP/2.0
      const parts = firstLine.split(' ');
      method = parts[0] || 'INVITE';
      status = parts[1] || 'sip:unknown';
    }

    packet.method = method;
    packet.status = status;

    // Parse Headers
    const headers: Record<string, string> = {};
    let sdpBody = '';
    let readingBody = false;

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (readingBody) {
        sdpBody += line + '\n';
        continue;
      }
      if (line === '') {
        readingBody = true;
        continue;
      }
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0) {
        const key = line.substring(0, colonIdx).trim();
        const value = line.substring(colonIdx + 1).trim();
        headers[key] = value;
      }
    }

    packet.metadata = {
      'First Line': firstLine,
      'Call-ID': headers['Call-ID'] || headers['i'] || '',
      'From': headers['From'] || headers['f'] || '',
      'To': headers['To'] || headers['t'] || '',
      'CSeq': headers['CSeq'] || '',
      'Via': headers['Via'] || headers['v'] || '',
      'Contact': headers['Contact'] || headers['m'] || '',
      'User-Agent': headers['User-Agent'] || headers['Server'] || 'Standard SIP Endpoint',
      'Content-Type': headers['Content-Type'] || headers['c'] || '',
      'Content-Length': headers['Content-Length'] || headers['l'] || payload.length.toString()
    };

    // Extract SDP media information if present
    if (sdpBody) {
      const codecMatch = sdpBody.match(/m=audio\s+(\d+)\s+RTP\/AVP\s+([\d\s]+)/i);
      if (codecMatch) {
        const audioPort = codecMatch[1];
        const codecPts = codecMatch[2].trim().split(/\s+/);
        const codecNames = codecPts.map(pt => RTP_PAYLOAD_MAP[Number(pt)] || `PT-${pt}`).join(', ');
        packet.metadata['SDP Audio Port'] = audioPort;
        packet.metadata['SDP Codecs'] = codecNames;
      }
      const connMatch = sdpBody.match(/c=IN\s+IP4\s+([\d.]+)/i);
      if (connMatch) {
        packet.metadata['SDP Connection IP'] = connMatch[1];
      }
    }

    // Forensic classification
    const fromStr = headers['From'] || '';
    const toStr = headers['To'] || '';

    // Call Direction
    if (fromStr.includes('internal') || fromStr.includes('192.168.') || fromStr.includes('10.0.')) {
      packet.callType = (toStr.includes('internal') || toStr.includes('192.168.')) ? 'internal' : 'outgoing';
    } else {
      packet.callType = 'incoming';
    }
    if (toStr.includes('conf') || toStr.includes('meet')) {
      packet.callType = 'conference';
    }

    // Security and Forensic Alerts
    const statusCode = isResponse ? parseInt(status.split(' ')[0], 10) : 0;

    if (statusCode >= 400) {
      packet.suspicious = true;
      packet.alertType = (statusCode === 401 || statusCode === 407) ? 'auth-failure' : 'failed-calls';
    } else if (method === 'CANCEL') {
      packet.suspicious = true;
      packet.alertType = 'failed-calls';
    } else if (!headers['Call-ID'] || !headers['From'] || !headers['To']) {
      packet.suspicious = true;
      packet.alertType = 'malformed';
    } else if (packet.destPort !== 5060 && packet.destPort !== 5061 && packet.destPort !== 5080) {
      packet.suspicious = true;
      packet.alertType = 'unusual-ports';
    }

    return packet;
  }

  /**
   * Dissect RTP packet
   */
  private static dissectRtp(packet: DissectedPacket, payload: Uint8Array): DissectedPacket {
    packet.protocol = 'RTP';
    const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);

    const cc = payload[0] & 0x0f;
    const hasExtension = ((payload[0] >> 4) & 1) === 1;
    const marker = ((payload[1] >> 7) & 1) === 1;
    const pt = payload[1] & 0x7f;
    const seq = view.getUint16(2, false);
    const rtpTs = view.getUint32(4, false);
    const ssrc = view.getUint32(8, false);

    let headerLen = 12 + cc * 4;
    if (hasExtension && payload.length >= headerLen + 4) {
      const extLen = view.getUint16(headerLen + 2, false) * 4;
      headerLen += 4 + extLen;
    }

    const payloadName = RTP_PAYLOAD_MAP[pt] || `Codec PT-${pt}`;
    const audioPayload = payload.subarray(Math.min(headerLen, payload.length));

    packet.method = `RTP (${payloadName})`;
    packet.status = `Seq: ${seq} | SSRC: 0x${ssrc.toString(16).toUpperCase()}`;
    packet.metadata = {
      'Payload Type': `${pt} (${payloadName})`,
      'Sequence Number': seq,
      'RTP Timestamp': rtpTs,
      'SSRC': `0x${ssrc.toString(16).toUpperCase()}`,
      'Marker Bit': marker ? 'Set (Talkspurt start)' : 'Not set',
      'Audio Payload Size': `${audioPayload.length} bytes`
    };

    packet.rtpData = {
      payloadType: pt,
      payloadName,
      sequenceNumber: seq,
      timestamp: rtpTs,
      ssrc,
      marker,
      audioPayload
    };

    // Check if RTP is on privileged or unusual port
    if (packet.destPort < 1024 || packet.sourcePort < 1024) {
      packet.suspicious = true;
      packet.alertType = 'unusual-ports';
    }

    return packet;
  }

  /**
   * Dissect RTCP packet
   */
  private static dissectRtcp(packet: DissectedPacket, payload: Uint8Array): DissectedPacket {
    packet.protocol = 'RTCP';
    const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const pt = payload[1];
    const ssrc = view.getUint32(4, false);

    let rtcpType = 'RTCP Packet';
    if (pt === 200) rtcpType = 'Sender Report (SR)';
    else if (pt === 201) rtcpType = 'Receiver Report (RR)';
    else if (pt === 202) rtcpType = 'Source Description (SDES)';
    else if (pt === 203) rtcpType = 'Goodbye (BYE)';
    else if (pt === 204) rtcpType = 'Application (APP)';

    packet.method = rtcpType;
    packet.status = `SSRC: 0x${ssrc.toString(16).toUpperCase()}`;
    packet.metadata = {
      'RTCP Type': rtcpType,
      'Payload Type': pt,
      'SSRC': `0x${ssrc.toString(16).toUpperCase()}`,
      'Packet Length': view.getUint16(2, false) * 4 + 4
    };

    if (pt === 200 && payload.length >= 28) {
      packet.metadata['NTP Sec'] = view.getUint32(8, false);
      packet.metadata['RTP Timestamp'] = view.getUint32(16, false);
      packet.metadata['Sender Packets'] = view.getUint32(20, false);
      packet.metadata['Sender Octets'] = view.getUint32(24, false);
    }

    return packet;
  }

  /**
   * Builds the final summary stats for the parsed capture
   */
  private static buildResult(packets: DissectedPacket[]): ParsePcapResult {
    let sipCount = 0;
    let rtpCount = 0;
    let rtcpCount = 0;
    let encryptedCount = 0;
    let suspiciousCount = 0;

    for (const p of packets) {
      if (p.protocol === 'SIP') sipCount++;
      else if (p.protocol === 'RTP') rtpCount++;
      else if (p.protocol === 'RTCP') rtcpCount++;
      if (p.encrypted) encryptedCount++;
      if (p.suspicious) suspiciousCount++;
    }

    const startTime = packets.length > 0 ? new Date(packets[0].rawTimestampMs) : undefined;
    const endTime = packets.length > 0 ? new Date(packets[packets.length - 1].rawTimestampMs) : undefined;
    const durationMs = (startTime && endTime) ? Math.max(0, endTime.getTime() - startTime.getTime()) : 0;

    return {
      packets,
      summary: {
        totalPackets: packets.length,
        sipPackets: sipCount,
        rtpPackets: rtpCount,
        rtcpPackets: rtcpCount,
        encryptedPackets: encryptedCount,
        suspiciousPackets: suspiciousCount,
        durationMs,
        startTime,
        endTime
      }
    };
  }

  /**
   * Helper to decode ASCII string from bytes
   */
  private static decodeAscii(bytes: Uint8Array, maxLen: number): string {
    const len = Math.min(bytes.length, maxLen);
    let str = '';
    for (let i = 0; i < len; i++) {
      const code = bytes[i];
      str += (code >= 32 && code <= 126) || code === 10 || code === 13 ? String.fromCharCode(code) : '.';
    }
    return str;
  }

  /**
   * Helper to format IPv6 address
   */
  private static formatIPv6(bytes: Uint8Array): string {
    const parts: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    }
    return parts.join(':');
  }

  /**
   * Generates a standard binary PCAP file from an array of DissectedPackets.
   * Enables Wireshark-compatible export directly from the browser!
   */
  static exportToPcap(packets: DissectedPacket[]): Uint8Array {
    // 24-byte PCAP Global Header
    // 0xa1b2c3d4 (magic), v2.4, 0 thiszone, 0 sigfigs, 65535 snaplen, 1 linktype (Ethernet)
    let totalSize = 24;
    for (const p of packets) {
      const len = p.rawBytes ? p.rawBytes.length : (p.payloadBytes ? p.payloadBytes.length + 42 : 54);
      totalSize += 16 + len;
    }

    const buffer = new ArrayBuffer(totalSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // Write Global Header (Little Endian: magic 0xa1b2c3d4 in LE)
    view.setUint32(0, 0xa1b2c3d4, true);
    view.setUint16(4, 2, true);  // major
    view.setUint16(6, 4, true);  // minor
    view.setInt32(8, 0, true);   // thiszone
    view.setUint32(12, 0, true);  // sigfigs
    view.setUint32(16, 65535, true); // snaplen
    view.setUint32(20, 1, true);  // Link-Type: DLT_EN10MB (Ethernet)

    let offset = 24;

    for (const p of packets) {
      let frameBytes: Uint8Array;

      if (p.rawBytes && p.rawBytes.length >= 14) {
        frameBytes = p.rawBytes;
      } else {
        // Construct a clean synthetic Ethernet + IP + UDP/TCP packet if raw frame was not captured
        const payload = p.payloadBytes || new Uint8Array(0);
        const isTcp = p.protocol === 'TCP';
        const proto = isTcp ? 6 : 17;
        const ipTotalLen = 20 + (isTcp ? 20 : 8) + payload.length;
        frameBytes = new Uint8Array(14 + ipTotalLen);

        // Ethernet (14 bytes): Fake MACs, EtherType IPv4 (0x0800)
        frameBytes[12] = 0x08;
        frameBytes[13] = 0x00;

        // IPv4 (20 bytes)
        frameBytes[14] = 0x45; // Version 4, IHL 5 (20 bytes)
        frameBytes[15] = 0x00; // DSCP/ECN
        frameBytes[16] = (ipTotalLen >> 8) & 0xff;
        frameBytes[17] = ipTotalLen & 0xff;
        frameBytes[18] = 0x12; // ID
        frameBytes[19] = 0x34;
        frameBytes[20] = 0x40; // Don't fragment
        frameBytes[21] = 0x00;
        frameBytes[22] = 64;   // TTL
        frameBytes[23] = proto; // UDP/TCP

        // IPs
        const srcParts = p.sourceIP.split('.').map(n => parseInt(n, 10) || 0);
        const dstParts = p.destIP.split('.').map(n => parseInt(n, 10) || 0);
        frameBytes.set(srcParts, 26);
        frameBytes.set(dstParts, 30);

        // Transport header (UDP 8 bytes or TCP 20 bytes)
        const trOff = 34;
        frameBytes[trOff] = (p.sourcePort >> 8) & 0xff;
        frameBytes[trOff + 1] = p.sourcePort & 0xff;
        frameBytes[trOff + 2] = (p.destPort >> 8) & 0xff;
        frameBytes[trOff + 3] = p.destPort & 0xff;

        if (!isTcp) {
          const udpLen = 8 + payload.length;
          frameBytes[trOff + 4] = (udpLen >> 8) & 0xff;
          frameBytes[trOff + 5] = udpLen & 0xff;
          frameBytes.set(payload, trOff + 8);
        } else {
          frameBytes[trOff + 12] = 0x50; // Data offset 5 (20 bytes)
          frameBytes[trOff + 13] = 0x18; // ACK + PSH
          frameBytes.set(payload, trOff + 20);
        }
      }

      const tsSec = Math.floor(p.rawTimestampMs / 1000);
      const tsUsec = (p.rawTimestampMs % 1000) * 1000;
      const capLen = frameBytes.length;

      // Packet Header: ts_sec, ts_usec, incl_len, orig_len
      view.setUint32(offset, tsSec, true);
      view.setUint32(offset + 4, tsUsec, true);
      view.setUint32(offset + 8, capLen, true);
      view.setUint32(offset + 12, capLen, true);

      offset += 16;
      bytes.set(frameBytes, offset);
      offset += capLen;
    }

    return bytes;
  }
}
