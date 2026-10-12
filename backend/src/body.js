// Bound bytes as they arrive, before decoding or collecting the whole body.
export const MAX_BODY_BYTES = 32 * 1024;
export class BodyTooLargeError extends Error {}

export async function readBody(stream) {
  if (!stream) return '';
  let bytes = 0;
  let text = '';
  const decoder = new TextDecoder();
  for await (const chunk of stream) {
    bytes += chunk.byteLength;
    if (bytes > MAX_BODY_BYTES) throw new BodyTooLargeError('Request body too large');
    text += decoder.decode(chunk, { stream: true });
  }
  return text + decoder.decode();
}
