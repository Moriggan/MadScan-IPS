// Autofill scan form from config (if any)
window.addEventListener('DOMContentLoaded', async () => {
  try {
    const r = await fetch('/api/config/load');
    const j = await r.json();
    const cfg = j.settings || {};
    if (cfg && cfg.max_connections) {
      // could update UI if needed
    }
  } catch(e){}
});
