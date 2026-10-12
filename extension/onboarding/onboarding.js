import { DEFAULT_BACKEND_URL } from '../lib/config.js';

const { backendUrl = DEFAULT_BACKEND_URL } = await chrome.storage.local.get('backendUrl');
if (backendUrl) {
  document.getElementById('privacy-local').hidden = true;
  document.getElementById('privacy-remote').hidden = false;
}

document.getElementById('done').addEventListener('click', () => window.close());
