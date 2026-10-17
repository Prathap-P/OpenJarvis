import { describe, expect, it } from 'vitest';
import { toAudioMeta } from './audioMeta';

describe('toAudioMeta', () => {
  it('prefixes the payload audio url with the base', () => {
    const payload: { audio?: { url: string } } = { audio: { url: '/api/digest/audio' } };
    expect(toAudioMeta('http://x', payload.audio)).toEqual({ url: 'http://x/api/digest/audio' });
  });

  it('returns undefined when the payload has no audio key', () => {
    const payload: { audio?: { url: string } } = {};
    expect(toAudioMeta('http://x', payload.audio)).toBeUndefined();
  });

  it('returns undefined for an undefined audio argument', () => {
    expect(toAudioMeta('http://x', undefined)).toBeUndefined();
  });

  it('returns undefined when the audio url is empty', () => {
    expect(toAudioMeta('http://x', { url: '' })).toBeUndefined();
  });
});
