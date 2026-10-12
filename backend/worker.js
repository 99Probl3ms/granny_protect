// Cloudflare Workers entry point. Configure JEV_API_KEY as a secret
// (`wrangler secret put JEV_API_KEY`) and the other variables from server.js
// as vars. Decision log lines go to the Workers log (console.log).
// Note: the rate limiter is in memory, so it is per isolate.

import { createHandler } from './src/handler.js';
import { createJevModel } from './src/jev.js';

let handle;

export default {
  async fetch(request, env) {
    handle ??= createHandler({
      model: env.JEV_API_KEY
        ? createJevModel({ apiKey: env.JEV_API_KEY, url: env.JEV_API_URL || undefined, model: env.JEV_MODEL || undefined })
        : null,
      disabled: env.TIER3_DISABLED === '1',
      ratePerMinute: Number(env.RATE_PER_MINUTE) || 60,
      log: (entry) => console.log(JSON.stringify(entry)),
    });
    return handle(request);
  },
};
