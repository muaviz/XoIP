import type { DissectedPacket } from "./pcapParser";

export interface SipCallMessage {
  packetId: string;
  timestamp: Date;
  rawTimestampMs: number;
  from: string;
  to: string;
  sourceIP: string;
  destIP: string;
  sourcePort: number;
  destPort: number;
  protocol: string;
  method: string;
  status: string;
  isResponse: boolean;
  statusCode?: number;
  cseq?: string;
  details?: string;
}

export interface RtpQualityMetrics {
  totalPackets: number;
  expectedPackets: number;
  lostPackets: number;
  lossRatePercent: number;
  jitterMs: number;
  maxJitterMs: number;
  avgJitterMs: number;
  outOfOrderPackets: number;
  minSeq: number;
  maxSeq: number;
  mosScore: number; // Estimated Mean Opinion Score (1.0 - 4.5)
  durationSeconds: number;
}

export interface CallSession {
  id: string;
  callId: string;
  fromIP: string;
  toIP: string;
  fromNumber?: string;
  toNumber?: string;
  state: 'initiated' | 'trying' | 'ringing' | 'answered' | 'ended' | 'failed';
  startTime: Date;
  endTime?: Date;
  duration?: number;
  lastActivity: Date;
  sipMethod: string;
  sipStatus?: string;
  packets: string[];
  sipMessages: SipCallMessage[];
  codec?: string;
  failed: boolean;
  failureReason?: string;
  userAgent?: string;
  rtpPacketsCount?: number;
  rtpPayloadType?: number;
  audioBytesList?: Uint8Array[];
  rtpMetrics?: RtpQualityMetrics;
  // Internal RTP tracking state
  _lastRtpSeq?: number;
  _lastRtpTs?: number;
  _lastRtpArrivalMs?: number;
  _jitter?: number;
  _jitterSum?: number;
  _jitterCount?: number;
  _maxJitter?: number;
  _outOfOrderCount?: number;
  _firstRtpSeq?: number;
  _highestRtpSeq?: number;
}

export interface CallFlowAnalyzerState {
  activeCalls: Map<string, CallSession>;
  completedCalls: CallSession[];
  totalCalls: number;
  failedCalls: number;
  avgCallDuration: number;
}

export class CallFlowAnalyzer {
  private state: CallFlowAnalyzerState = {
    activeCalls: new Map(),
    completedCalls: [],
    totalCalls: 0,
    failedCalls: 0,
    avgCallDuration: 0
  };

  private listeners: ((state: CallFlowAnalyzerState) => void)[] = [];

  reset() {
    this.state = {
      activeCalls: new Map(),
      completedCalls: [],
      totalCalls: 0,
      failedCalls: 0,
      avgCallDuration: 0
    };
    this.notifyListeners();
  }

  processPacket(packet: DissectedPacket) {
    if (!packet) return;
    this.processBatch([packet]);
  }

  processBatch(packets: DissectedPacket[]) {
    if (!packets || packets.length === 0) return;
    let changed = false;

    for (const packet of packets) {
      if (!packet) continue;
      if (packet.protocol === 'SIP') {
        this.processSipPacketInternal(packet);
        changed = true;
      } else if (packet.protocol === 'RTP') {
        this.processRtpPacket(packet);
        changed = true;
      }
    }

    if (changed) {
      this.notifyListeners();
    }
  }

  private processSipPacketInternal(packet: DissectedPacket) {
    const rawCallId = packet.metadata?.['Call-ID'] || '';
    const callId = rawCallId || this.generateCallId(packet);
    const method = (packet.method || '').toUpperCase();
    const status = (packet.status || '').toUpperCase();

    if (method.includes('INVITE')) {
      this.handleInvite(callId, packet);
    } else if (method.includes('ACK')) {
      this.handleAck(callId, packet);
    } else if (method.includes('BYE')) {
      this.handleBye(callId, packet);
    } else if (method.includes('CANCEL')) {
      this.handleCancel(callId, packet);
    } else if (packet.method.startsWith('SIP ') || status.includes('OK') || status.includes('RINGING') || status.includes('TRYING') || status.includes('BUSY') || status.match(/^[1-6]\d\d/)) {
      this.handleSipResponse(callId, packet);
    } else {
      // General SIP request (OPTIONS, REGISTER, etc.)
      this.handleGenericSip(callId, packet);
    }
  }

  private processRtpPacket(packet: DissectedPacket) {
    // Correlate RTP packet with active call sessions by matching IP endpoints
    for (const call of this.state.activeCalls.values()) {
      const matchEndpoints = (
        (call.fromIP === packet.sourceIP && call.toIP === packet.destIP) ||
        (call.fromIP === packet.destIP && call.toIP === packet.sourceIP)
      );

      if (matchEndpoints) {
        if (call.packets.length < 1000) {
          call.packets.push(packet.id);
        }
        const arrivalMs = packet.rawTimestampMs || new Date(packet.timestamp).getTime();
        call.lastActivity = new Date(arrivalMs);
        call.rtpPacketsCount = (call.rtpPacketsCount || 0) + 1;

        // Extract RTP sequence and timestamp for RFC 3550 Jitter & Loss tracking
        if (packet.rtpData) {
          const { sequenceNumber: seq, timestamp: rtpTs, payloadType } = packet.rtpData;
          if (call.rtpPayloadType === undefined) {
            call.rtpPayloadType = payloadType;
          }

          // Sequence tracking
          if (call._firstRtpSeq === undefined) {
            call._firstRtpSeq = seq;
            call._highestRtpSeq = seq;
          } else {
            if (seq < (call._lastRtpSeq || 0) && (call._lastRtpSeq || 0) - seq < 32000) {
              call._outOfOrderCount = (call._outOfOrderCount || 0) + 1;
            } else if (seq > (call._highestRtpSeq || 0)) {
              call._highestRtpSeq = seq;
            }
          }

          // RFC 3550 Interarrival Jitter Calculation
          // 8000 Hz clock rate (8 samples per millisecond for G.711 / standard VoIP)
          const clockRateKhz = 8;
          if (call._lastRtpTs !== undefined && call._lastRtpArrivalMs !== undefined) {
            const transitTimeDiff = (arrivalMs - call._lastRtpArrivalMs) - Math.floor((rtpTs - call._lastRtpTs) / clockRateKhz);
            const d = Math.abs(transitTimeDiff);
            const currentJitter = (call._jitter || 0) + (d - (call._jitter || 0)) / 16;
            call._jitter = currentJitter;
            call._jitterSum = (call._jitterSum || 0) + currentJitter;
            call._jitterCount = (call._jitterCount || 0) + 1;
            call._maxJitter = Math.max(call._maxJitter || 0, currentJitter);
          }

          call._lastRtpSeq = seq;
          call._lastRtpTs = rtpTs;
          call._lastRtpArrivalMs = arrivalMs;

          // Compute RTP Quality Metrics
          const totalPkts = call.rtpPacketsCount;
          const minSeq = call._firstRtpSeq || 0;
          const maxSeq = call._highestRtpSeq || seq;
          const expectedPkts = Math.max(totalPkts, maxSeq - minSeq + 1);
          const lostPkts = Math.max(0, expectedPkts - totalPkts);
          const lossRate = expectedPkts > 0 ? (lostPkts / expectedPkts) * 100 : 0;
          const jitterMs = Math.round((call._jitter || 0) * 100) / 100;
          const avgJitter = call._jitterCount ? Math.round(((call._jitterSum || 0) / call._jitterCount) * 100) / 100 : jitterMs;
          const maxJitter = Math.round((call._maxJitter || jitterMs) * 100) / 100;
          const durationSec = Math.max(0, (arrivalMs - call.startTime.getTime()) / 1000);

          // ITU-T E-Model MOS Score Approximation (1.0 to 4.5)
          const rFactor = Math.max(0, Math.min(100, 93.2 - (lossRate * 2.5) - (avgJitter * 0.4)));
          let mos = 1.0;
          if (rFactor > 0) {
            mos = 1.0 + 0.035 * rFactor + rFactor * (rFactor - 60) * (100 - rFactor) * 0.000007;
            mos = Math.max(1.0, Math.min(4.5, Math.round(mos * 10) / 10));
          }

          call.rtpMetrics = {
            totalPackets: totalPkts,
            expectedPackets: expectedPkts,
            lostPackets: lostPkts,
            lossRatePercent: Math.round(lossRate * 10) / 10,
            jitterMs,
            maxJitterMs: maxJitter,
            avgJitterMs: avgJitter,
            outOfOrderPackets: call._outOfOrderCount || 0,
            minSeq,
            maxSeq,
            mosScore: mos,
            durationSeconds: Math.round(durationSec * 10) / 10
          };
        }

        if (packet.rtpData?.audioPayload && packet.rtpData.audioPayload.length > 0) {
          if (!call.audioBytesList) call.audioBytesList = [];
          if (call.audioBytesList.length < 1000) { // Limit stored chunks to ~20 seconds to prevent memory explosion
            call.audioBytesList.push(packet.rtpData.audioPayload);
          }
        }
        break;
      }
    }
  }

  private addSipMessageToCall(call: CallSession, packet: DissectedPacket, isResponse: boolean, statusCode?: number) {
    const ts = new Date(packet.rawTimestampMs || packet.timestamp);
    const fromNum = this.extractNumber(packet.metadata?.['From'] as string | undefined) || packet.sourceIP;
    const toNum = this.extractNumber(packet.metadata?.['To'] as string | undefined) || packet.destIP;

    const msg: SipCallMessage = {
      packetId: packet.id,
      timestamp: ts,
      rawTimestampMs: packet.rawTimestampMs || ts.getTime(),
      from: fromNum,
      to: toNum,
      sourceIP: packet.sourceIP,
      destIP: packet.destIP,
      sourcePort: packet.sourcePort,
      destPort: packet.destPort,
      protocol: packet.protocol,
      method: packet.method,
      status: packet.status,
      isResponse,
      statusCode,
      cseq: packet.metadata?.['CSeq'] as string | undefined,
      details: packet.metadata?.['User-Agent'] ? `UA: ${packet.metadata['User-Agent']}` : undefined
    };

    if (!call.sipMessages) call.sipMessages = [];
    if (call.sipMessages.length < 50) {
      call.sipMessages.push(msg);
    }
  }

  private handleInvite(callId: string, packet: DissectedPacket) {
    const existingCall = this.state.activeCalls.get(callId);
    const ts = new Date(packet.rawTimestampMs || packet.timestamp);
    const codec = (packet.metadata?.['SDP Codecs'] || packet.metadata?.['Content-Type']) as string | undefined;
    const userAgent = packet.metadata?.['User-Agent'] as string | undefined;

    if (!existingCall) {
      // Prevent activeCalls map from growing unboundedly (cap at 50)
      if (this.state.activeCalls.size >= 50) {
        const oldestKey = this.state.activeCalls.keys().next().value;
        if (oldestKey) {
          const oldCall = this.state.activeCalls.get(oldestKey);
          if (oldCall) this.moveToCompleted(oldCall);
        }
      }

      const newCall: CallSession = {
        id: callId,
        callId,
        fromIP: packet.sourceIP,
        toIP: packet.destIP,
        fromNumber: this.extractNumber(packet.metadata?.['From'] as string | undefined),
        toNumber: this.extractNumber(packet.metadata?.['To'] as string | undefined),
        state: 'initiated',
        startTime: ts,
        lastActivity: ts,
        sipMethod: packet.method,
        packets: [packet.id],
        sipMessages: [],
        failed: false,
        codec,
        userAgent,
        rtpPacketsCount: 0
      };

      this.addSipMessageToCall(newCall, packet, false);
      this.state.activeCalls.set(callId, newCall);
      this.state.totalCalls++;
    } else {
      existingCall.packets.push(packet.id);
      existingCall.lastActivity = ts;
      if (codec && !existingCall.codec) existingCall.codec = codec;
      if (userAgent && !existingCall.userAgent) existingCall.userAgent = userAgent;
      this.addSipMessageToCall(existingCall, packet, false);
    }
  }

  private handleSipResponse(callId: string, packet: DissectedPacket) {
    let call = this.state.activeCalls.get(callId);
    const ts = new Date(packet.rawTimestampMs || packet.timestamp);
    const statusText = packet.status || '';
    const statusCodeMatch = statusText.match(/^(\d{3})/);
    const statusCode = statusCodeMatch ? parseInt(statusCodeMatch[1], 10) : undefined;

    // If call wasn't tracked by Call-ID yet, see if any call matches endpoints
    if (!call) {
      for (const c of this.state.activeCalls.values()) {
        if ((c.fromIP === packet.destIP && c.toIP === packet.sourceIP) || (c.fromIP === packet.sourceIP && c.toIP === packet.destIP)) {
          call = c;
          break;
        }
      }
    }

    if (!call) return;

    call.packets.push(packet.id);
    call.lastActivity = ts;
    call.sipStatus = statusText;

    if (packet.metadata?.['SDP Codecs'] && !call.codec) {
      call.codec = packet.metadata['SDP Codecs'] as string;
    }

    this.addSipMessageToCall(call, packet, true, statusCode);

    if (statusText.includes('100')) {
      call.state = 'trying';
    } else if (statusText.includes('180') || statusText.includes('183')) {
      call.state = 'ringing';
    } else if (statusText.includes('200')) {
      call.state = 'answered';
    } else if (statusText.match(/^[4-6]\d\d/) || statusText.toLowerCase().includes('busy') || statusText.toLowerCase().includes('forbidden') || statusText.toLowerCase().includes('not found')) {
      call.state = 'failed';
      call.failed = true;
      call.failureReason = statusText;
      this.moveToCompleted(call);
    }
  }

  private handleAck(callId: string, packet: DissectedPacket) {
    const call = this.state.activeCalls.get(callId);
    if (!call) return;

    call.packets.push(packet.id);
    call.lastActivity = new Date(packet.rawTimestampMs || packet.timestamp);
    call.state = 'answered';
    this.addSipMessageToCall(call, packet, false);
  }

  private handleBye(callId: string, packet: DissectedPacket) {
    const call = this.state.activeCalls.get(callId);
    if (!call) return;

    const ts = new Date(packet.rawTimestampMs || packet.timestamp);
    call.packets.push(packet.id);
    call.endTime = ts;
    call.duration = Math.max(0, call.endTime.getTime() - call.startTime.getTime());
    call.state = 'ended';
    this.addSipMessageToCall(call, packet, false);

    this.moveToCompleted(call);
  }

  private handleCancel(callId: string, packet: DissectedPacket) {
    const call = this.state.activeCalls.get(callId);
    if (!call) return;

    const ts = new Date(packet.rawTimestampMs || packet.timestamp);
    call.packets.push(packet.id);
    call.endTime = ts;
    call.state = 'failed';
    call.failed = true;
    call.failureReason = 'Cancelled by caller';
    this.addSipMessageToCall(call, packet, false);

    this.moveToCompleted(call);
  }

  private handleGenericSip(callId: string, packet: DissectedPacket) {
    const call = this.state.activeCalls.get(callId);
    if (call) {
      call.packets.push(packet.id);
      call.lastActivity = new Date(packet.rawTimestampMs || packet.timestamp);
      this.addSipMessageToCall(call, packet, false);
    }
  }

  private moveToCompleted(call: CallSession) {
    this.state.activeCalls.delete(call.callId);
    // Avoid duplicates in completedCalls
    if (!this.state.completedCalls.some(c => c.callId === call.callId)) {
      this.state.completedCalls.unshift(call);
    }

    if (call.failed) {
      this.state.failedCalls++;
    }

    // Keep only last 30 completed calls
    if (this.state.completedCalls.length > 30) {
      this.state.completedCalls = this.state.completedCalls.slice(0, 30);
    }

    this.updateAverageCallDuration();
  }

  private updateAverageCallDuration() {
    const completedWithDuration = this.state.completedCalls.filter(c => c.duration && !c.failed);
    if (completedWithDuration.length > 0) {
      const totalDuration = completedWithDuration.reduce((sum, call) => sum + (call.duration || 0), 0);
      this.state.avgCallDuration = Math.round(totalDuration / completedWithDuration.length);
    }
  }

  private generateCallId(packet: DissectedPacket): string {
    return `${packet.sourceIP}-${packet.destIP}-${packet.rawTimestampMs || Date.now()}`;
  }

  private extractNumber(field?: string): string | undefined {
    if (!field) return undefined;
    // Format: "Alice" <sip:alice@192.168.1.1> or <sip:+1234567890@domain.com;tag=xyz>
    const match = field.match(/sip:([^@>;\s]+)/i);
    if (match) return match[1];
    const userMatch = field.match(/"([^"]+)"/);
    if (userMatch) return userMatch[1];
    return field.substring(0, 20);
  }

  subscribe(listener: (state: CallFlowAnalyzerState) => void) {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  private notifyListeners() {
    this.listeners.forEach(listener => listener({
      ...this.state,
      activeCalls: new Map(this.state.activeCalls),
      completedCalls: [...this.state.completedCalls]
    }));
  }

  getState(): CallFlowAnalyzerState {
    return { ...this.state };
  }

  cleanup() {
    // Remove calls inactive for more than 5 minutes
    const cutoff = new Date(Date.now() - 5 * 60 * 1000);

    for (const [callId, call] of this.state.activeCalls.entries()) {
      if (call.lastActivity < cutoff) {
        call.state = 'failed';
        call.failed = true;
        call.failureReason = 'Session Inactivity Timeout';
        call.endTime = call.lastActivity;
        this.moveToCompleted(call);
      }
    }

    this.notifyListeners();
  }
}
