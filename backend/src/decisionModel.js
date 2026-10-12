// The Tier 3 model interface. Jev implements it today (jev.js); a local
// classifier trained on logged decisions can replace it later.

/**
 * @typedef {Object} DecisionModel
 * @property {string} name
 * @property {(summary: import('../../extension/lib/summary.js').PageSummary) =>
 *   Promise<import('../../extension/lib/fusion.js').ModelResult & {usage?: object}>} classify
 */

export {};
