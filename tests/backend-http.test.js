import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createNodeServer } from '../backend/src/nodeServer.js';

for (const declared of [false, true]) {
  test(`Node rejects oversized ${declared ? 'declared' : 'chunked'} body before upload finishes`, async (t) => {
    let calls = 0;
    const server = createNodeServer(async () => { calls++; return Response.json({ ok: true }); });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    t.after(() => { server.closeAllConnections(); server.close(); });
    const status = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: server.address().port, path: '/classify', method: 'POST',
        headers: declared ? { 'content-length': 1048576 } : {},
      }, (res) => { res.resume(); resolve(res.statusCode); req.destroy(); });
      req.on('error', reject);
      req.setTimeout(2000, () => req.destroy(new Error('Server waited for full upload')));
      req.write(Buffer.alloc(declared ? 1 : 32769));
      // Deliberately never end: the server must reject without buffering the rest.
    });
    assert.equal(status, 413);
    assert.equal(calls, 0);
  });
}

test('Node forwards a valid multibyte request', async (t) => {
  const server = createNodeServer(async (request) => Response.json(await request.json()));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const result = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: server.address().port, path: '/classify', method: 'POST' }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve(JSON.parse(text)));
    });
    req.on('error', reject);
    req.end(JSON.stringify({ text: 'café' }));
  });
  assert.deepEqual(result, { text: 'café' });
});
