// Script to generate authentic binary PCAP sample traces for XoIP VoIP Forensics testing
import fs from 'node:fs';
import path from 'node:path';
import { PcapParser, type DissectedPacket } from '../src/lib/pcapParser.ts';

const outDir = path.resolve(process.cwd(), 'public/samples');
if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

// Generate Sample 1: Successful SIP Call with RTP G.711 Audio Stream
function generateSuccessfulCall(): DissectedPacket[] {
  const callId = 'c8b41a92-f01e-450a-9e12-329b8c049d56@192.168.1.100';
  const caller = '101';
  const callee = '102';
  const baseTime = Date.now() - 60000;
  const packets: DissectedPacket[] = [];

  const sdpOffer = [
    'v=0',
    'o=alice 2890844526 2890844526 IN IP4 192.168.1.100',
    's=VoIP Call',
    'c=IN IP4 192.168.1.100',
    't=0 0',
    'm=audio 16384 RTP/AVP 0 8 101',
    'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:8 PCMA/8000',
    'a=rtpmap:101 telephone-event/8000',
    'a=sendrecv'
  ].join('\r\n');

  const sdpAnswer = [
    'v=0',
    'o=bob 2890844527 2890844527 IN IP4 192.168.1.150',
    's=VoIP Call',
    'c=IN IP4 192.168.1.150',
    't=0 0',
    'm=audio 18422 RTP/AVP 0',
    'a=rtpmap:0 PCMU/8000',
    'a=sendrecv'
  ].join('\r\n');

  // 1. INVITE
  const inviteSip = [
    `INVITE sip:${callee}@192.168.1.150:5060 SIP/2.0`,
    'Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-741258',
    'Max-Forwards: 70',
    `From: "Alice" <sip:${caller}@192.168.1.100>;tag=as56412e`,
    `To: <sip:${callee}@192.168.1.150>`,
    `Call-ID: ${callId}`,
    'CSeq: 101 INVITE',
    'User-Agent: Asterisk PBX 18.15.0',
    'Contact: <sip:101@192.168.1.100:5060>',
    'Content-Type: application/sdp',
    `Content-Length: ${sdpOffer.length}`,
    '',
    sdpOffer
  ].join('\r\n');

  packets.push({
    id: 'pkt-1',
    timestamp: new Date(baseTime).toISOString(),
    rawTimestampMs: baseTime,
    sourceIP: '192.168.1.100',
    destIP: '192.168.1.150',
    sourcePort: 5060,
    destPort: 5060,
    protocol: 'SIP',
    method: 'INVITE',
    status: `sip:${callee}@192.168.1.150`,
    size: inviteSip.length + 42,
    encrypted: false,
    suspicious: false,
    callType: 'internal',
    metadata: {
      'Call-ID': callId,
      'From': `"Alice" <sip:${caller}@192.168.1.100>`,
      'To': `<sip:${callee}@192.168.1.150>`,
      'CSeq': '101 INVITE',
      'User-Agent': 'Asterisk PBX 18.15.0',
      'SDP Codecs': 'PCMU (G.711 µ-law), PCMA (G.711 A-law)',
      'SDP Audio Port': '16384'
    },
    payloadBytes: stringToBytes(inviteSip)
  });

  // 2. 100 Trying
  const tryingSip = [
    'SIP/2.0 100 Trying',
    'Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-741258',
    `From: "Alice" <sip:${caller}@192.168.1.100>;tag=as56412e`,
    `To: <sip:${callee}@192.168.1.150>`,
    `Call-ID: ${callId}`,
    'CSeq: 101 INVITE',
    'User-Agent: Cisco-CP7960G/8.0',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  packets.push({
    id: 'pkt-2',
    timestamp: new Date(baseTime + 25).toISOString(),
    rawTimestampMs: baseTime + 25,
    sourceIP: '192.168.1.150',
    destIP: '192.168.1.100',
    sourcePort: 5060,
    destPort: 5060,
    protocol: 'SIP',
    method: 'SIP 100',
    status: '100 Trying',
    size: tryingSip.length + 42,
    encrypted: false,
    suspicious: false,
    metadata: {
      'Call-ID': callId,
      'From': `"Alice" <sip:${caller}@192.168.1.100>`,
      'To': `<sip:${callee}@192.168.1.150>`,
      'CSeq': '101 INVITE',
      'User-Agent': 'Cisco-CP7960G/8.0'
    },
    payloadBytes: stringToBytes(tryingSip)
  });

  // 3. 180 Ringing
  const ringingSip = [
    'SIP/2.0 180 Ringing',
    'Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-741258',
    `From: "Alice" <sip:${caller}@192.168.1.100>;tag=as56412e`,
    `To: <sip:${callee}@192.168.1.150>;tag=cisco4921`,
    `Call-ID: ${callId}`,
    'CSeq: 101 INVITE',
    'Contact: <sip:102@192.168.1.150:5060>',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  packets.push({
    id: 'pkt-3',
    timestamp: new Date(baseTime + 150).toISOString(),
    rawTimestampMs: baseTime + 150,
    sourceIP: '192.168.1.150',
    destIP: '192.168.1.100',
    sourcePort: 5060,
    destPort: 5060,
    protocol: 'SIP',
    method: 'SIP 180',
    status: '180 Ringing',
    size: ringingSip.length + 42,
    encrypted: false,
    suspicious: false,
    metadata: {
      'Call-ID': callId,
      'From': `"Alice" <sip:${caller}@192.168.1.100>`,
      'To': `<sip:${callee}@192.168.1.150>;tag=cisco4921`,
      'CSeq': '101 INVITE'
    },
    payloadBytes: stringToBytes(ringingSip)
  });

  // 4. 200 OK (Call Answered)
  const okSip = [
    'SIP/2.0 200 OK',
    'Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-741258',
    `From: "Alice" <sip:${caller}@192.168.1.100>;tag=as56412e`,
    `To: <sip:${callee}@192.168.1.150>;tag=cisco4921`,
    `Call-ID: ${callId}`,
    'CSeq: 101 INVITE',
    'Contact: <sip:102@192.168.1.150:5060>',
    'Content-Type: application/sdp',
    `Content-Length: ${sdpAnswer.length}`,
    '',
    sdpAnswer
  ].join('\r\n');

  packets.push({
    id: 'pkt-4',
    timestamp: new Date(baseTime + 1800).toISOString(),
    rawTimestampMs: baseTime + 1800,
    sourceIP: '192.168.1.150',
    destIP: '192.168.1.100',
    sourcePort: 5060,
    destPort: 5060,
    protocol: 'SIP',
    method: 'SIP 200',
    status: '200 OK',
    size: okSip.length + 42,
    encrypted: false,
    suspicious: false,
    metadata: {
      'Call-ID': callId,
      'From': `"Alice" <sip:${caller}@192.168.1.100>`,
      'To': `<sip:${callee}@192.168.1.150>;tag=cisco4921`,
      'CSeq': '101 INVITE',
      'SDP Codecs': 'PCMU (G.711 µ-law)',
      'SDP Audio Port': '18422'
    },
    payloadBytes: stringToBytes(okSip)
  });

  // 5. ACK
  const ackSip = [
    `ACK sip:102@192.168.1.150:5060 SIP/2.0`,
    'Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-994821',
    'Max-Forwards: 70',
    `From: "Alice" <sip:${caller}@192.168.1.100>;tag=as56412e`,
    `To: <sip:${callee}@192.168.1.150>;tag=cisco4921`,
    `Call-ID: ${callId}`,
    'CSeq: 101 ACK',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  packets.push({
    id: 'pkt-5',
    timestamp: new Date(baseTime + 1820).toISOString(),
    rawTimestampMs: baseTime + 1820,
    sourceIP: '192.168.1.100',
    destIP: '192.168.1.150',
    sourcePort: 5060,
    destPort: 5060,
    protocol: 'SIP',
    method: 'ACK',
    status: 'sip:102@192.168.1.150',
    size: ackSip.length + 42,
    encrypted: false,
    suspicious: false,
    metadata: {
      'Call-ID': callId,
      'From': `"Alice" <sip:${caller}@192.168.1.100>`,
      'To': `<sip:${callee}@192.168.1.150>;tag=cisco4921`,
      'CSeq': '101 ACK'
    },
    payloadBytes: stringToBytes(ackSip)
  });

  // 6. RTP Voice Audio Stream (Packets carrying PCMU voice tones at 20ms intervals)
  let rtpSeq = 1000;
  let rtpTs = 160000;
  const ssrc = 0x482910fa;

  for (let i = 0; i < 30; i++) {
    const pktTime = baseTime + 1850 + i * 20;
    // 12-byte RTP header + 160 bytes G.711 audio payload (20ms @ 8000Hz)
    const rtpBuf = new Uint8Array(12 + 160);
    rtpBuf[0] = 0x80; // V=2, P=0, X=0, CC=0
    rtpBuf[1] = (i === 0 ? 0x80 : 0x00) | 0x00; // Marker on first packet, PT=0 (PCMU)
    rtpBuf[2] = (rtpSeq >> 8) & 0xff;
    rtpBuf[3] = rtpSeq & 0xff;
    rtpBuf[4] = (rtpTs >> 24) & 0xff;
    rtpBuf[5] = (rtpTs >> 16) & 0xff;
    rtpBuf[6] = (rtpTs >> 8) & 0xff;
    rtpBuf[7] = rtpTs & 0xff;
    rtpBuf[8] = (ssrc >> 24) & 0xff;
    rtpBuf[9] = (ssrc >> 16) & 0xff;
    rtpBuf[10] = (ssrc >> 8) & 0xff;
    rtpBuf[11] = ssrc & 0xff;

    // Generate a pleasant dial tone / voice audio wave (440Hz tone encoded in G.711 mu-law)
    for (let s = 0; s < 160; s++) {
      const sample = Math.sin(2 * Math.PI * 440 * (s / 8000)) * 0.5;
      // Simple linear to mu-law approximation byte
      rtpBuf[12 + s] = (Math.floor((sample + 1) * 127) ^ 0xff) & 0xff;
    }

    packets.push({
      id: `pkt-rtp-${i + 1}`,
      timestamp: new Date(pktTime).toISOString(),
      rawTimestampMs: pktTime,
      sourceIP: '192.168.1.100',
      destIP: '192.168.1.150',
      sourcePort: 16384,
      destPort: 18422,
      protocol: 'RTP',
      method: 'RTP (PCMU)',
      status: `Seq: ${rtpSeq} | SSRC: 0x${ssrc.toString(16).toUpperCase()}`,
      size: 172 + 42,
      encrypted: false,
      suspicious: false,
      metadata: {
        'Payload Type': '0 (PCMU (G.711 µ-law))',
        'Sequence Number': rtpSeq,
        'RTP Timestamp': rtpTs,
        'SSRC': `0x${ssrc.toString(16).toUpperCase()}`,
        'Marker Bit': i === 0 ? 'Set (Talkspurt start)' : 'Not set',
        'Audio Payload Size': '160 bytes'
      },
      payloadBytes: rtpBuf,
      rtpData: {
        payloadType: 0,
        payloadName: 'PCMU (G.711 µ-law)',
        sequenceNumber: rtpSeq,
        timestamp: rtpTs,
        ssrc,
        marker: i === 0,
        audioPayload: rtpBuf.subarray(12)
      }
    });

    rtpSeq++;
    rtpTs += 160;
  }

  // 7. BYE
  const byeTime = baseTime + 4500;
  const byeSip = [
    `BYE sip:102@192.168.1.150:5060 SIP/2.0`,
    'Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-994899',
    'Max-Forwards: 70',
    `From: "Alice" <sip:${caller}@192.168.1.100>;tag=as56412e`,
    `To: <sip:${callee}@192.168.1.150>;tag=cisco4921`,
    `Call-ID: ${callId}`,
    'CSeq: 102 BYE',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  packets.push({
    id: 'pkt-bye',
    timestamp: new Date(byeTime).toISOString(),
    rawTimestampMs: byeTime,
    sourceIP: '192.168.1.100',
    destIP: '192.168.1.150',
    sourcePort: 5060,
    destPort: 5060,
    protocol: 'SIP',
    method: 'BYE',
    status: 'sip:102@192.168.1.150',
    size: byeSip.length + 42,
    encrypted: false,
    suspicious: false,
    metadata: {
      'Call-ID': callId,
      'From': `"Alice" <sip:${caller}@192.168.1.100>`,
      'To': `<sip:${callee}@192.168.1.150>;tag=cisco4921`,
      'CSeq': '102 BYE'
    },
    payloadBytes: stringToBytes(byeSip)
  });

  // 8. 200 OK to BYE
  const byeOkSip = [
    'SIP/2.0 200 OK',
    'Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-994899',
    `From: "Alice" <sip:${caller}@192.168.1.100>;tag=as56412e`,
    `To: <sip:${callee}@192.168.1.150>;tag=cisco4921`,
    `Call-ID: ${callId}`,
    'CSeq: 102 BYE',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  packets.push({
    id: 'pkt-bye-ok',
    timestamp: new Date(byeTime + 15).toISOString(),
    rawTimestampMs: byeTime + 15,
    sourceIP: '192.168.1.150',
    destIP: '192.168.1.100',
    sourcePort: 5060,
    destPort: 5060,
    protocol: 'SIP',
    method: 'SIP 200',
    status: '200 OK',
    size: byeOkSip.length + 42,
    encrypted: false,
    suspicious: false,
    metadata: {
      'Call-ID': callId,
      'From': `"Alice" <sip:${caller}@192.168.1.100>`,
      'To': `<sip:${callee}@192.168.1.150>;tag=cisco4921`,
      'CSeq': '102 BYE'
    },
    payloadBytes: stringToBytes(byeOkSip)
  });

  return packets;
}

// Generate Sample 2: SIP Authentication Failure (Forensic Investigation trace)
function generateAuthFailureCall(): DissectedPacket[] {
  const callId = 'auth-fail-82910-18491820@external-gateway.com';
  const baseTime = Date.now() - 30000;
  const packets: DissectedPacket[] = [];

  const invite = [
    'INVITE sip:admin@192.168.1.100:5060 SIP/2.0',
    'Via: SIP/2.0/UDP 203.0.113.45:5060;branch=z9hG4bK-authbr1',
    'From: <sip:scanner@203.0.113.45>;tag=scan123',
    'To: <sip:admin@192.168.1.100>',
    `Call-ID: ${callId}`,
    'CSeq: 1 INVITE',
    'User-Agent: friendly-scanner / SIPVicious',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  packets.push({
    id: 'auth-1',
    timestamp: new Date(baseTime).toISOString(),
    rawTimestampMs: baseTime,
    sourceIP: '203.0.113.45',
    destIP: '192.168.1.100',
    sourcePort: 5060,
    destPort: 5060,
    protocol: 'SIP',
    method: 'INVITE',
    status: 'sip:admin@192.168.1.100',
    size: invite.length + 42,
    encrypted: false,
    suspicious: true,
    alertType: 'auth-failure',
    metadata: {
      'Call-ID': callId,
      'From': '<sip:scanner@203.0.113.45>',
      'To': '<sip:admin@192.168.1.100>',
      'User-Agent': 'friendly-scanner / SIPVicious'
    },
    payloadBytes: stringToBytes(invite)
  });

  const response401 = [
    'SIP/2.0 401 Unauthorized',
    'Via: SIP/2.0/UDP 203.0.113.45:5060;branch=z9hG4bK-authbr1',
    'From: <sip:scanner@203.0.113.45>;tag=scan123',
    'To: <sip:admin@192.168.1.100>;tag=srv-sec99',
    `Call-ID: ${callId}`,
    'CSeq: 1 INVITE',
    'WWW-Authenticate: Digest realm="asterisk", nonce="5a8b9c1d", algorithm=MD5',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  packets.push({
    id: 'auth-2',
    timestamp: new Date(baseTime + 20).toISOString(),
    rawTimestampMs: baseTime + 20,
    sourceIP: '192.168.1.100',
    destIP: '203.0.113.45',
    sourcePort: 5060,
    destPort: 5060,
    protocol: 'SIP',
    method: 'SIP 401',
    status: '401 Unauthorized',
    size: response401.length + 42,
    encrypted: false,
    suspicious: true,
    alertType: 'auth-failure',
    metadata: {
      'Call-ID': callId,
      'From': '<sip:scanner@203.0.113.45>',
      'To': '<sip:admin@192.168.1.100>;tag=srv-sec99',
      'CSeq': '1 INVITE',
      'WWW-Authenticate': 'Digest realm="asterisk", nonce="5a8b9c1d"'
    },
    payloadBytes: stringToBytes(response401)
  });

  return packets;
}

// Generate files
const pcapSuccess = PcapParser.exportToPcap(generateSuccessfulCall());
fs.writeFileSync(path.join(outDir, 'voip_call_success.pcap'), pcapSuccess);
console.log(`Generated voip_call_success.pcap (${pcapSuccess.length} bytes)`);

const pcapAuthFail = PcapParser.exportToPcap(generateAuthFailureCall());
fs.writeFileSync(path.join(outDir, 'voip_auth_failure.pcap'), pcapAuthFail);
console.log(`Generated voip_auth_failure.pcap (${pcapAuthFail.length} bytes)`);
