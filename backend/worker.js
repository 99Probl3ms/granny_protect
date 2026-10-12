// Cloudflare Workers entry point. Configure TYPESAFE_API_KEY as a secret
// (`wrangler secret put TYPESAFE_API_KEY`) and the other variables from server.js
// as vars. Decision log lines go to the Workers log (console.log).
// Note: the rate limiter is in memory, so it is per isolate.

import { createHandler } from './src/handler.js';
import { createJevModel, jevConfigFromEnv } from './src/jev.js';

let handle;

export default {
  async fetch(request, env) {
    const jev = jevConfigFromEnv(env);
    handle ??= createHandler({
      model: jev ? createJevModel(jev) : null,
      disabled: env.TIER3_DISABLED === '1',
      ratePerMinute: Number(env.RATE_PER_MINUTE) || 60,
      log: (entry) => console.log(JSON.stringify(entry)),
    });
    return handle(request);
  },
};
