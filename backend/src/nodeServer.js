import http from 'node:http';
import { BodyTooLargeError, MAX_BODY_BYTES, readBody } from './body.js';

export function createNodeServer(handle) {
  return http.createServer(async (req, res) => {
    try {
      if (Number(req.headers['content-length'] || 0) > MAX_BODY_BYTES) {
        throw new BodyTooLargeError();
      }
      // Keep the socket alive on early iterator exit so we can return 413.
      const body = await readBody(req.iterator({ destroyOnReturn: false }));
      const headers = Object.fromEntries(
        ['content-type', 'x-install-id'].filter((n) => req.headers[n] != null)
          .map((n) => [n, req.headers[n]]),
      );
      const request = new Request(`http://${req.headers.host || 'localhost'}${req.url}`, {
        method: req.method, headers,
        body: req.method === 'GET' || req.method === 'HEAD' ? undefined : body,
      });
      const response = await handle(request);
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        res.writeHead(413, { 'content-type': 'application/json', connection: 'close' });
        res.once('finish', () => req.destroy());
        res.end(JSON.stringify({ error: 'too_large' }));
      } else {
        console.error(err);
        res.writeHead(500).end();
      }
    }
  });
}
