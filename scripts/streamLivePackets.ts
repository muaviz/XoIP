// Script to transmit live SIP and RTP packets over real UDP sockets to test XoIP Live Capture
import dgram from 'node:dgram';

const TARGET_HOST = process.env.TARGET_HOST || '127.0.0.1';
const TARGET_PORT = parseInt(process.env.TARGET_PORT || '5060', 10);

const client = dgram.createSocket('udp4');
const callId = `live-call-${Date.now()}@xoip.local`;

console.log(`[Live Streamer] Transmitting live VoIP traffic to udp://${TARGET_HOST}:${TARGET_PORT}...`);

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function sendUdp(data: string | Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => {
    client.send(data, TARGET_PORT, TARGET_HOST, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function runLiveVoipSession() {
  // 1. Send SIP INVITE
  const invite = [
    'INVITE sip:102@127.0.0.1:5060 SIP/2.0',
    'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-live9921',
    'Max-Forwards: 70',
    'From: "Alice" <sip:101@127.0.0.1>;tag=live-alice-1',
    'To: <sip:102@127.0.0.1>',
    `Call-ID: ${callId}`,
    'CSeq: 1 INVITE',
    'User-Agent: Linphone/5.2.0',
    'Contact: <sip:101@127.0.0.1:5060>',
    'Content-Type: application/sdp',
    'Content-Length: 130',
    '',
    'v=0',
    'o=alice 12345 12345 IN IP4 127.0.0.1',
    's=Live Test Call',
    'c=IN IP4 127.0.0.1',
    't=0 0',
    'm=audio 16384 RTP/AVP 0',
    'a=rtpmap:0 PCMU/8000'
  ].join('\r\n');

  console.log('Sending SIP INVITE...');
  await sendUdp(invite);
  await sleep(150);

  // 2. Send SIP 100 Trying
  const trying = [
    'SIP/2.0 100 Trying',
    'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-live9921',
    'From: "Alice" <sip:101@127.0.0.1>;tag=live-alice-1',
    'To: <sip:102@127.0.0.1>',
    `Call-ID: ${callId}`,
    'CSeq: 1 INVITE',
    'User-Agent: Asterisk PBX 18.0.0',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  console.log('Sending SIP 100 Trying...');
  await sendUdp(trying);
  await sleep(300);

  // 3. Send SIP 180 Ringing
  const ringing = [
    'SIP/2.0 180 Ringing',
    'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-live9921',
    'From: "Alice" <sip:101@127.0.0.1>;tag=live-alice-1',
    'To: <sip:102@127.0.0.1>;tag=live-bob-2',
    `Call-ID: ${callId}`,
    'CSeq: 1 INVITE',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  console.log('Sending SIP 180 Ringing...');
  await sendUdp(ringing);
  await sleep(800);

  // 4. Send SIP 200 OK
  const ok = [
    'SIP/2.0 200 OK',
    'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-live9921',
    'From: "Alice" <sip:101@127.0.0.1>;tag=live-alice-1',
    'To: <sip:102@127.0.0.1>;tag=live-bob-2',
    `Call-ID: ${callId}`,
    'CSeq: 1 INVITE',
    'Contact: <sip:102@127.0.0.1:5060>',
    'Content-Type: application/sdp',
    'Content-Length: 120',
    '',
    'v=0',
    'o=bob 54321 54321 IN IP4 127.0.0.1',
    's=Live Test Call',
    'c=IN IP4 127.0.0.1',
    't=0 0',
    'm=audio 18422 RTP/AVP 0',
    'a=rtpmap:0 PCMU/8000'
  ].join('\r\n');

  console.log('Sending SIP 200 OK (Answered)...');
  await sendUdp(ok);
  await sleep(100);

  // 5. Send ACK
  const ack = [
    'ACK sip:102@127.0.0.1:5060 SIP/2.0',
    'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-live9922',
    'From: "Alice" <sip:101@127.0.0.1>;tag=live-alice-1',
    'To: <sip:102@127.0.0.1>;tag=live-bob-2',
    `Call-ID: ${callId}`,
    'CSeq: 1 ACK',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  console.log('Sending SIP ACK...');
  await sendUdp(ack);
  await sleep(200);

  // 6. Send 15 RTP audio packets (simulating live voice)
  console.log('Streaming live RTP voice packets...');
  let seq = 500;
  let ts = 10000;
  const ssrc = 0x12ab34cd;

  for (let i = 0; i < 15; i++) {
    const rtpBuf = new Uint8Array(12 + 160);
    rtpBuf[0] = 0x80; // V=2
    rtpBuf[1] = 0x00; // PT=0 (PCMU)
    rtpBuf[2] = (seq >> 8) & 0xff;
    rtpBuf[3] = seq & 0xff;
    rtpBuf[4] = (ts >> 24) & 0xff;
    rtpBuf[5] = (ts >> 16) & 0xff;
    rtpBuf[6] = (ts >> 8) & 0xff;
    rtpBuf[7] = ts & 0xff;
    rtpBuf[8] = (ssrc >> 24) & 0xff;
    rtpBuf[9] = (ssrc >> 16) & 0xff;
    rtpBuf[10] = (ssrc >> 8) & 0xff;
    rtpBuf[11] = ssrc & 0xff;

    // Fill audio bytes (sine tone)
    for (let s = 0; s < 160; s++) {
      const sample = Math.sin(2 * Math.PI * 440 * (s / 8000)) * 0.5;
      rtpBuf[12 + s] = (Math.floor((sample + 1) * 127) ^ 0xff) & 0xff;
    }

    await sendUdp(rtpBuf);
    seq++;
    ts += 160;
    await sleep(40); // Fast stream
  }

  await sleep(1000);

  // 7. Send BYE
  const bye = [
    'BYE sip:102@127.0.0.1:5060 SIP/2.0',
    'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-live9923',
    'From: "Alice" <sip:101@127.0.0.1>;tag=live-alice-1',
    'To: <sip:102@127.0.0.1>;tag=live-bob-2',
    `Call-ID: ${callId}`,
    'CSeq: 2 BYE',
    'Content-Length: 0',
    '',
    ''
  ].join('\r\n');

  console.log('Sending SIP BYE (Ending call)...');
  await sendUdp(bye);

  await sleep(100);
  console.log('[Live Streamer] Live call completed successfully.');
  client.close();
}

runLiveVoipSession().catch(err => {
  console.error('[Live Streamer] Error:', err);
  client.close();
});
