import type { ChatMessage } from '../types';

type AudioMeta = NonNullable<ChatMessage['audio']>;

/** Map the per-response SSE `audio` payload to a playable URL under `base`. */
export function toAudioMeta(base: string, audio?: { url: string }): AudioMeta | undefined {
  return audio?.url ? { url: base + audio.url } : undefined;
}
