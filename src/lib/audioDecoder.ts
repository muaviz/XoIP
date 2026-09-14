// G.711 µ-law (PCMU) and A-law (PCMA) Audio Decoder for VoIP Forensics
// Converts raw RTP payload bytes to 8000Hz PCM audio for Web Audio API playback

// G.711 µ-law decompression lookup table
const ULAW_TO_LINEAR = new Int16Array(256);
for (let i = 0; i < 256; i++) {
  const ulaw = ~i;
  const t = ((ulaw & 0x0f) << 3) + 0x84;
  const seg = (ulaw & 0x70) >> 4;
  let sample = t << seg;
  sample -= 0x84;
  ULAW_TO_LINEAR[i] = (ulaw & 0x80) !== 0 ? -sample : sample;
}

// G.711 A-law decompression lookup table
const ALAW_TO_LINEAR = new Int16Array(256);
for (let i = 0; i < 256; i++) {
  const alaw = i ^ 0x55;
  const seg = (alaw & 0x70) >> 4;
  let sample = (alaw & 0x0f) << 4;
  if (seg === 0) {
    sample += 8;
  } else {
    sample += 0x108;
    sample <<= seg - 1;
  }
  ALAW_TO_LINEAR[i] = (alaw & 0x80) !== 0 ? sample : -sample;
}

export class AudioDecoder {
  /**
   * Decodes G.711 (PCMU or PCMA) bytes to an AudioBuffer that can be played with Web Audio API
   */
  static decodeG711ToAudioBuffer(
    audioBytes: Uint8Array,
    payloadType: number,
    audioContext: AudioContext
  ): AudioBuffer {
    const isAlaw = payloadType === 8;
    const table = isAlaw ? ALAW_TO_LINEAR : ULAW_TO_LINEAR;
    const numSamples = audioBytes.length;
    const sampleRate = 8000;

    const audioBuffer = audioContext.createBuffer(1, numSamples, sampleRate);
    const channelData = audioBuffer.getChannelData(0);

    for (let i = 0; i < numSamples; i++) {
      // Normalize 16-bit signed integer (-32768 to 32767) to float (-1.0 to 1.0)
      channelData[i] = table[audioBytes[i]] / 32768.0;
    }

    return audioBuffer;
  }

  /**
   * Converts decoded PCM samples to standard WAV file format for direct download
   */
  static pcmToWav(audioBytes: Uint8Array, payloadType: number): Blob {
    const isAlaw = payloadType === 8;
    const table = isAlaw ? ALAW_TO_LINEAR : ULAW_TO_LINEAR;
    const numSamples = audioBytes.length;
    const sampleRate = 8000;
    const numChannels = 1;
    const bitsPerSample = 16;
    const byteRate = sampleRate * numChannels * (bitsPerSample / 8);
    const blockAlign = numChannels * (bitsPerSample / 8);
    const dataSize = numSamples * 2;

    const buffer = new ArrayBuffer(44 + dataSize);
    const view = new DataView(buffer);

    // RIFF chunk descriptor
    this.writeString(view, 0, 'RIFF');
    view.setUint32(4, 36 + dataSize, true);
    this.writeString(view, 8, 'WAVE');

    // "fmt " sub-chunk
    this.writeString(view, 12, 'fmt ');
    view.setUint32(16, 16, true); // Subchunk1Size (16 for PCM)
    view.setUint16(20, 1, true);  // AudioFormat (1 for PCM)
    view.setUint16(22, numChannels, true);
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, byteRate, true);
    view.setUint16(32, blockAlign, true);
    view.setUint16(34, bitsPerSample, true);

    // "data" sub-chunk
    this.writeString(view, 36, 'data');
    view.setUint32(40, dataSize, true);

    // Write 16-bit PCM samples
    let offset = 44;
    for (let i = 0; i < numSamples; i++) {
      const sample = table[audioBytes[i]];
      view.setInt16(offset, sample, true);
      offset += 2;
    }

    return new Blob([buffer], { type: 'audio/wav' });
  }

  private static writeString(view: DataView, offset: number, string: string) {
    for (let i = 0; i < string.length; i++) {
      view.setUint8(offset + i, string.charCodeAt(i));
    }
  }
}
