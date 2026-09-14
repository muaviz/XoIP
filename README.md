# XoIP Forensics — VoIP Network Analysis & Forensics Platform

**XoIP Forensics** is a cybersecurity forensics dashboard and VoIP packet analysis tool built for network engineers, security analysts, and forensic investigators. It provides deep wire-level dissection of **SIP**, **RTP**, **RTCP**, and **TLS** network traffic, stateful call session correlation, anomaly detection, and in-browser call audio reconstruction.

---

## Key Features

- **Binary PCAP & PCAPNG Dissector**: Native pure-TypeScript decoder for standard `.pcap`, `.pcapng`, and `.cap` capture files without third-party binary dependencies.
- **Deep VoIP Protocol Dissection**:
  - **SIP (RFC 3261)**: Full header parsing (`Call-ID`, `From`, `To`, `CSeq`, `Via`, `User-Agent`, `WWW-Authenticate`, etc.) and SDP codec/port extraction (`m=audio`, `c=IN IP4`, `a=rtpmap`).
  - **RTP (RFC 3550)**: Sequence tracking, timestamp synchronization, SSRC extraction, and audio payload preservation (PCMU, PCMA, G.722, G.729, Opus).
  - **RTCP (RFC 3550)**: Sender Reports (SR), Receiver Reports (RR), jitter, and packet loss metrics.
  - **TLS / SRTP**: Encrypted VoIP stream detection and record layer classification.
- **In-Browser VoIP Audio Player & WAV Export**:
  - Decodes G.711 µ-law (`PCMU`) and A-law (`PCMA`) RTP audio payloads directly into playable audio using the Web Audio API.
  - One-click export to standard 8000 Hz 16-bit uncompressed `.wav` audio files.
- **Stateful SIP Call Flow Engine**: Tracks call progression (`INVITE` → `100 Trying` → `180 Ringing` → `200 OK` / `ACK` → `BYE` / `CANCEL` / Error), duration, and endpoint correlation.
- **Automated Forensic Security Alerts**:
  - Failed Calls (SIP 4xx, 5xx, 6xx responses).
  - Authentication Failures (SIP 401 Unauthorized / 407 Proxy Authentication Required).
  - Malformed Headers (missing mandatory RFC 3261 fields).
  - Suspicious IP / Port Activity (SIP on non-standard ports, RTP below port 1024).
- **Live Packet Capture Daemon**:
  - WebSocket streaming on `ws://localhost:8081/ws`.
  - Live UDP listener on port `5060` (or `5080`) capturing incoming softphone and PBX traffic.
  - Network interface packet sniffer (using unbuffered `tcpdump` stream).
- **Wireshark-Compatible PCAP Export**: Generate and download filtered packet traces as standard `.pcap` files, full JSON forensic dumps, or CSV tables.

---

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Frontend Only (Offline PCAP Analysis)
```bash
npm run dev
```
Open `http://localhost:8080` in your browser. Drag and drop any `.pcap` or `.pcapng` file or click one of the built-in sample forensic captures.

### 3. Start Frontend + Live Capture Telemetry Server
```bash
npm run dev:all
```
This launches:
1. The **Vite Frontend** on `http://localhost:8080`
2. The **XoIP Live Telemetry & Capture Daemon** on `http://localhost:8081` (WebSocket on `/ws`, UDP VoIP listener on port `5060`).

---

## NPM Scripts

| Command | Description |
| :--- | :--- |
| `npm run dev` | Starts Vite development server for the UI |
| `npm run capture` | Starts the backend Live Capture and UDP listener daemon |
| `npm run dev:all` | Runs both the live capture backend and Vite frontend concurrently |
| `npm run build` | Builds the production bundle |
| `npm run generate:samples` | Generates sample binary `.pcap` files in `public/samples/` |
| `npm run lint` | Runs ESLint checks across the codebase |

---

## Forensic Architecture

```
                      [ Live UDP / PBX Traffic ]
                                   │
                                   ▼
 [ Network Interface ] ──► [ captureServer.ts ] ──(WebSocket)──┐
                                                               │
 [ Upload .pcap / .pcapng ] ──► [ pcapParser.ts ] ────────────►├──► [ CallFlowAnalyzer.ts ]
                                       │                       │             │
                                       ▼                       ▼             ▼
                               [ Hex/ASCII View ]        [ PacketLog ]  [ LiveCallMonitor ]
                                                                             │
                                                                             ▼
                                                                     [ AudioDecoder.ts ]
                                                                     (Play / Export WAV)
```
