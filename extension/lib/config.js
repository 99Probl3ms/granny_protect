// Build-time settings. The backend URL can also be set at runtime (for
// testing) with chrome.storage.local.set({ backendUrl: 'https://...' }) from
// the service worker console; an empty string turns Tier 3 off.

// Where the granny_protect backend (backend/) is deployed. Empty = Tier 3 off,
// the extension then works fully locally on Tiers 0-2.
export const DEFAULT_BACKEND_URL = '';

// POC: send every page that isn't trusted or blocklisted to Tier 3, so Jev can
// be measured against the heuristics alone (ARCHITECTURE.md §10). Before any
// wider release set this to true to only ask about gray-zone pages.
export const GRAY_ZONE_ONLY = false;
export const GRAY_ZONE = { min: 0.3, max: 0.85 };

// How long the page waits for Tier 3 before falling back to heuristics. The
// call keeps running and its result is cached for the next check.
export const MODEL_WAIT_MS = 1500;
