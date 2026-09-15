// Live Packet Capture & VoIP Telemetry Server for XoIP
// Provides WebSocket streaming, live network interface packet sniffing (tcpdump),
// and a live UDP socket listener for incoming VoIP traffic.

import http from 'node:http';
import dgram from 'node:dgram';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import os from 'node:os';
import { WebSocketServer, WebSocket } from 'ws';
import { PcapParser, type DissectedPacket } from '../src/lib/pcapParser.ts';

const PORT = parseInt(process.env.PORT || '8081', 10);
const SIP_PORT = parseInt(process.env.SIP_PORT || '5060', 10);

interface CaptureStatus {
  capturing: boolean;
  activeInterface: string | null;
  packetsCaptured: number;
  connectedClients: number;
  udpListenerActive: boolean;
  udpPort: number;
  availableInterfaces: string[];
}

let packetsCaptured = 0;
let activeInterface: string | null = null;
let tcpdumpProcess: ChildProcess | null = null;
let udpSocket: dgram.Socket | null = null;
let udpListenerActive = false;
let activeUdpPort = SIP_PORT;

// Create HTTP server for REST endpoints and WebSocket upgrade
const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

  // GET /api/status
  if (req.method === 'GET' && url.pathname === '/api/status') {
    const status: CaptureStatus = {
      capturing: tcpdumpProcess !== null,
      activeInterface,
      packetsCaptured,
      connectedClients: wss.clients.size,
      udpListenerActive,
      udpPort: activeUdpPort,
      availableInterfaces: getNetworkInterfaces()
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(status));
    return;
  }

  // GET /api/interfaces
  if (req.method === 'GET' && url.pathname === '/api/interfaces') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ interfaces: getNetworkInterfaces() }));
    return;
  }

  // POST /api/capture/start
  if (req.method === 'POST' && url.pathname === '/api/capture/start') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const data = body ? JSON.parse(body) : {};
        const iface = data.interface || 'any';
        const filter = data.filter || 'port 5060 or port 5061 or port 5080 or (udp and portrange 10000-20000)';
        const success = startTcpdumpCapture(iface, filter);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success, interface: iface }));
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: msg }));
      }
    });
    return;
  }

  // POST /api/capture/stop
  if (req.method === 'POST' && url.pathname === '/api/capture/stop') {
    stopTcpdumpCapture();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // POST /api/server/shutdown
  if (req.method === 'POST' && url.pathname === '/api/server/shutdown') {
    stopTcpdumpCapture();
    if (udpSocket) {
      try { udpSocket.close(); } catch { /* socket already closed */ }
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, message: 'XoIP capture server shutting down' }));
    setTimeout(() => {
      process.exit(0);
    }, 150);
    return;
  }

  // POST /api/capture/packet (Ingest packet from external probe or softphone)
  if (req.method === 'POST' && url.pathname === '/api/capture/packet') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const packet = JSON.parse(body);
        broadcastPacket(packet);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, id: packet.id }));
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: msg }));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

// Create WebSocket server for real-time live streaming
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws: WebSocket) => {
  console.log(`[XoIP Server] New client connected. Total clients: ${wss.clients.size}`);

  // Send initial handshake and status
  ws.send(JSON.stringify({
    type: 'connected',
    status: {
      capturing: tcpdumpProcess !== null,
      activeInterface,
      packetsCaptured,
      udpListenerActive,
      udpPort: activeUdpPort,
      availableInterfaces: getNetworkInterfaces()
    }
  }));

  ws.on('message', (message: string) => {
    try {
      const data = JSON.parse(message.toString());
      if (data.type === 'start_capture') {
        const iface = data.interface || 'any';
        startTcpdumpCapture(iface, data.filter);
      } else if (data.type === 'stop_capture') {
        stopTcpdumpCapture();
      } else if (data.type === 'replay_sample') {
        replaySampleTrace();
      } else if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
      }
    } catch (e) {
      console.error('[XoIP Server] Failed to parse message:', e);
    }
  });

  ws.on('close', () => {
    console.log(`[XoIP Server] Client disconnected. Remaining: ${wss.clients.size}`);
  });
});

let lastBroadcastReset = Date.now();
let packetsSentThisSecond = 0;
const MAX_GENERIC_PACKETS_PER_SEC = 150; // Cap generic non-VoIP packets to 150/sec to protect client memory

function broadcastPacket(packet: DissectedPacket) {
  packetsCaptured++;

  const now = Date.now();
  if (now - lastBroadcastReset >= 1000) {
    lastBroadcastReset = now;
    packetsSentThisSecond = 0;
  }

  // Always prioritize SIP and RTP voice packets. Throttle high-speed non-VoIP background traffic (e.g. video streams, downloads)
  if (packet.protocol !== 'SIP' && packet.protocol !== 'RTP' && packet.protocol !== 'RTCP') {
    if (packetsSentThisSecond >= MAX_GENERIC_PACKETS_PER_SEC) {
      return; // Drop excessive background traffic to maintain smooth 60fps and low RAM
    }
  }

  packetsSentThisSecond++;

  // Create a lightweight wire-safe copy to prevent JSON ballooning and memory bloat
  const wsPacket: DissectedPacket = {
    ...packet,
    rawBytes: undefined, // Drop duplicate full frame to save 90% WebSocket payload bandwidth
    payloadBytes: packet.payloadBytes && packet.payloadBytes.length > 256 && packet.protocol !== 'SIP' && packet.protocol !== 'RTP'
      ? packet.payloadBytes.subarray(0, 256)
      : packet.payloadBytes
  };

  const payload = JSON.stringify({ type: 'packet', packet: wsPacket });
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      // Backpressure protection: If client write buffer exceeds 128KB, drop packet instead of queuing in RAM
      if (client.bufferedAmount > 128 * 1024) {
        continue;
      }
      client.send(payload);
    }
  }
}

function getNetworkInterfaces(): string[] {
  const ifaces = os.networkInterfaces();
  const list = Object.keys(ifaces);
  if (!list.includes('any')) list.unshift('any');
  return list;
}

/**
 * Ensures tcpdump BPF filter NEVER captures the capture server's own WebSocket or dev ports,
 * which would trigger an exponential infinite feedback loop!
 */
function sanitizeBpfFilter(userFilter?: string): string {
  const selfExclude = `not (port ${PORT} or port 8080 or port 5173)`;
  if (!userFilter || userFilter.trim() === '' || userFilter === 'all' || userFilter === 'ip or ip6') {
    return `(ip or ip6) and ${selfExclude}`;
  }
  // Exclude our own ports from any custom filter
  return `(${userFilter}) and ${selfExclude}`;
}

/**
 * Starts live packet capture using tcpdump if permitted
 */
function startTcpdumpCapture(iface: string = 'any', filter: string = 'ip or ip6'): boolean {
  if (tcpdumpProcess) {
    stopTcpdumpCapture();
  }

  activeInterface = iface;
  const safeFilter = sanitizeBpfFilter(filter);
  console.log(`[XoIP Server] Starting live capture on interface '${iface}' with filter '${safeFilter}'...`);

  try {
    // -U: unbuffered output, -w -: write raw pcap stream to stdout, -s 0: full packet snapshot
    const args = ['-i', iface, '-U', '-w', '-', '-s', '0', safeFilter];
    tcpdumpProcess = spawn('tcpdump', args, { stdio: ['ignore', 'pipe', 'pipe'] });

    let pcapHeaderRead = false;
    let leftoverBuffer: Buffer = Buffer.alloc(0);
    let isLittleEndian = true;
    let linkType = 1;

    tcpdumpProcess.stdout?.on('data', (chunk: Buffer) => {
      leftoverBuffer = Buffer.concat([leftoverBuffer, chunk]);

      // Read 24-byte PCAP Global Header
      if (!pcapHeaderRead) {
        if (leftoverBuffer.length < 24) return;
        const magic = leftoverBuffer.readUInt32BE(0);
        isLittleEndian = (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1);
        linkType = isLittleEndian ? leftoverBuffer.readUInt32LE(20) : leftoverBuffer.readUInt32BE(20);
        leftoverBuffer = leftoverBuffer.subarray(24);
        pcapHeaderRead = true;
      }

      // Read individual packets (16-byte record header + incl_len bytes)
      while (leftoverBuffer.length >= 16) {
        const tsSec = isLittleEndian ? leftoverBuffer.readUInt32LE(0) : leftoverBuffer.readUInt32BE(0);
        const tsUsec = isLittleEndian ? leftoverBuffer.readUInt32LE(4) : leftoverBuffer.readUInt32BE(4);
        const inclLen = isLittleEndian ? leftoverBuffer.readUInt32LE(8) : leftoverBuffer.readUInt32BE(8);
        const origLen = isLittleEndian ? leftoverBuffer.readUInt32LE(12) : leftoverBuffer.readUInt32BE(12);

        if (leftoverBuffer.length < 16 + inclLen) {
          // Wait for more bytes
          break;
        }

        const packetBytes = new Uint8Array(leftoverBuffer.subarray(16, 16 + inclLen));
        leftoverBuffer = leftoverBuffer.subarray(16 + inclLen);

        const timestampMs = tsSec * 1000 + Math.floor(tsUsec / 1000);
        const dissected = PcapParser.dissectFrame(packetBytes, linkType, timestampMs, packetsCaptured, origLen);

        if (dissected) {
          broadcastPacket(dissected);
        }
      }

      // Release parent buffer references to allow V8 garbage collector to free memory
      if (leftoverBuffer.length > 1024 * 1024) {
        // Prevent buffer runaway if stream is corrupted
        leftoverBuffer = Buffer.alloc(0);
      } else if (leftoverBuffer.length > 0) {
        leftoverBuffer = Buffer.from(leftoverBuffer);
      } else {
        leftoverBuffer = Buffer.alloc(0);
      }
    });

    tcpdumpProcess.stderr?.on('data', (data: Buffer) => {
      const msg = data.toString();
      if (msg.includes('permission') || msg.includes('CAP_NET_RAW')) {
        console.warn('[XoIP Server] tcpdump requires elevated privileges. Live UDP listener remains available.');
        broadcastCaptureError('tcpdump requires root/CAP_NET_RAW privileges. Live UDP socket listener is active on port ' + activeUdpPort);
      }
    });

    tcpdumpProcess.on('exit', (code) => {
      console.log(`[XoIP Server] tcpdump exited with code ${code}`);
      tcpdumpProcess = null;
      activeInterface = null;
      broadcastCaptureState();
    });

    broadcastCaptureState();
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[XoIP Server] Failed to spawn tcpdump:', msg);
    tcpdumpProcess = null;
    activeInterface = null;
    broadcastCaptureError(msg);
    return false;
  }
}

function stopTcpdumpCapture() {
  if (tcpdumpProcess) {
    tcpdumpProcess.kill('SIGINT');
    tcpdumpProcess = null;
    activeInterface = null;
    broadcastCaptureState();
  }
}

function broadcastCaptureState() {
  const payload = JSON.stringify({
    type: 'capture_state',
    capturing: tcpdumpProcess !== null,
    activeInterface,
    packetsCaptured,
    udpListenerActive,
    udpPort: activeUdpPort
  });
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}

function broadcastCaptureError(message: string) {
  const payload = JSON.stringify({ type: 'capture_error', error: message });
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}

/**
 * Initializes a live UDP socket to receive real VoIP SIP packets directly
 */
function startLiveUdpListener(port: number) {
  try {
    udpSocket = dgram.createSocket('udp4');

    udpSocket.on('message', (msg: Buffer, rinfo: dgram.RemoteInfo) => {
      // Dissect the incoming UDP packet
      const bytes = new Uint8Array(msg);
      const text = msg.toString('utf8');
      const isSip = text.startsWith('SIP/2.0 ') || /^(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER)/i.test(text);

      const packet: DissectedPacket = {
        id: `live-udp-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
        timestamp: new Date().toISOString(),
        rawTimestampMs: Date.now(),
        sourceIP: rinfo.address,
        destIP: '127.0.0.1',
        sourcePort: rinfo.port,
        destPort: port,
        protocol: isSip ? 'SIP' : 'UDP',
        method: isSip ? (text.split(' ')[0] || 'SIP') : `UDP Port ${port}`,
        status: isSip ? (text.split('\r\n')[0] || 'SIP Message') : `${bytes.length} bytes`,
        size: bytes.length,
        encrypted: false,
        suspicious: false,
        metadata: {},
        payloadBytes: bytes
      };

      if (isSip) {
        // Parse SIP headers
        const lines = text.split(/\r?\n/);
        const headers: Record<string, string> = {};
        for (const line of lines) {
          const colon = line.indexOf(':');
          if (colon > 0) {
            headers[line.substring(0, colon).trim()] = line.substring(colon + 1).trim();
          }
        }
        packet.metadata = {
          'Call-ID': headers['Call-ID'] || headers['i'] || '',
          'From': headers['From'] || headers['f'] || '',
          'To': headers['To'] || headers['t'] || '',
          'CSeq': headers['CSeq'] || '',
          'User-Agent': headers['User-Agent'] || 'Live UDP Client'
        };
      }

      broadcastPacket(packet);
    });

    udpSocket.on('error', (err: unknown) => {
      const errObj = err as { code?: string; message?: string };
      if (errObj.code === 'EACCES') {
        console.warn(`[XoIP Server] Cannot bind UDP port ${port} (permission denied). Trying unprivileged port 5080...`);
        if (port === 5060) {
          startLiveUdpListener(5080);
        }
      } else {
        console.error('[XoIP Server] UDP listener error:', errObj.message || String(err));
      }
    });

    udpSocket.bind(port, () => {
      activeUdpPort = port;
      udpListenerActive = true;
      console.log(`[XoIP Server] Live UDP VoIP listener active on 0.0.0.0:${port}`);
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn('[XoIP Server] Could not start UDP listener:', msg);
  }
}

/**
 * Replays genuine binary PCAP sample packets in real-time over WebSocket
 */
async function replaySampleTrace() {
  try {
    const samplePath = path.resolve(process.cwd(), 'public/samples/voip_call_success.pcap');
    if (!fs.existsSync(samplePath)) return;
    const fileBytes = fs.readFileSync(samplePath);
    const parsed = await PcapParser.parse(fileBytes.buffer);

    const sessionRunId = Date.now().toString(36);
    const newCallId = `live-call-${Date.now()}@192.168.1.100`;
    console.log(`[XoIP Server] Replaying ${parsed.packets.length} genuine VoIP packets over WebSocket (Session Call-ID: ${newCallId})...`);
    
    let lastTime = parsed.packets[0]?.rawTimestampMs || 0;
    let idx = 0;

    for (const originalPkt of parsed.packets) {
      idx++;
      const delta = originalPkt.rawTimestampMs - lastTime;
      const delay = Math.min(400, Math.max(25, delta));
      lastTime = originalPkt.rawTimestampMs;
      await new Promise(r => setTimeout(r, delay));

      const now = Date.now();
      const pkt: DissectedPacket = {
        ...originalPkt,
        id: `live-sample-${sessionRunId}-${idx}`,
        timestamp: new Date(now).toISOString(),
        rawTimestampMs: now,
        metadata: {
          ...originalPkt.metadata,
          ...(originalPkt.metadata?.['Call-ID'] ? { 'Call-ID': newCallId } : {})
        }
      };

      // Update SIP headers in payload bytes if present
      if (pkt.protocol === 'SIP' && pkt.payloadBytes) {
        const text = new TextDecoder().decode(pkt.payloadBytes);
        const updatedText = text.replace(/Call-ID:\s*[^\r\n]+/i, `Call-ID: ${newCallId}`);
        pkt.payloadBytes = new TextEncoder().encode(updatedText);
      }

      broadcastPacket(pkt);
    }
    console.log('[XoIP Server] Replay completed.');
  } catch (err) {
    console.error('[XoIP Server] Replay failed:', err);
  }
}

// Start HTTP & WS Server
server.listen(PORT, () => {
  console.log(`[XoIP Server] Live Telemetry & Capture Server listening on http://localhost:${PORT}`);
  console.log(`[XoIP Server] WebSocket streaming endpoint: ws://localhost:${PORT}/ws`);
  startLiveUdpListener(SIP_PORT);
});
