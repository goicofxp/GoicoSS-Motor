// GoicoSS - REPORTE FORENSE TOTAL V19 (Full Database)
// Autor: @goicofxp

const SCANNER_NAME = "Goico";
const SCANNER_VERSION = "SS";

// --- BASE DE DATOS COMPLETA ---
const VPS_HOSTING_KEYWORDS = ["hostinger", "hstgr", "locaweb", "kinghost", "umbler", "hostgator", "digitalocean", "linode", "vultr", "hetzner", "ovh", "contabo", "aws", "azure", "googlecloud", "choopa", "psychz", "m247", "path.net", "datacamp", "tzulo", "servermania", "multacom"];

const CHEAT_APPS = {
  "com.touchingapp.potatsolite": "PotatsoLite — proxy iOS",
  "com.monite.proxyff": "ProxyFF — proxy iOS (Cheat)",
  "com.shadowrocket.Shadowrocket": "Shadowrocket — proxy iOS",
  "com.opa334.dopamine": "Dopamine — Jailbreak",
  "com.opa334.TrollStore": "TrollStore — Sideload",
  "com.esign.ios": "ESign — IPA Installer",
  "com.iosgods.iosgods": "iOSGods — Cheat Store",
  "com.tigisoftware.Filza": "Filza — Root File Manager",
  "com.apple.Preferences.Developer": "Opciones de Desarrollador Activas"
};

const CHEAT_DOMAINS = ["purplevioleto.com", "ggpolarbear.com", "ggwhitehawk.com", "anubisw.online", "baontq.xyz", "fatalitycheats.xyz", "proxy.builders", "authtool.app", "isigncloud", "1xlite"];

const RDNS_PATTERNS = ["hstgr.cloud", "staticip", "srv.", "vps.", "dedicated."];

// --- MOTOR LOGICO ---
const Parser = {
  ndjson: (raw) => raw.split('\n').filter(l => l.trim()).map(l => { try { return JSON.parse(l); } catch(e) { return null; } }).filter(x => x),
  ips: (raw) => { try { return JSON.parse(raw); } catch(e) { return null; } }
};

function runAnalysis(netEntries, ipsData) {
  let appGroups = {};
  let appsInUsage = new Set(ipsData?.entries?.map(e => e.bundleId) || []);

  netEntries.forEach(e => {
    if (!e.bundleID || !e.domain) return;
    
    let isVps = VPS_HOSTING_KEYWORDS.some(k => e.domain.toLowerCase().includes(k)) || RDNS_PATTERNS.some(p => e.domain.toLowerCase().includes(p));
    let isCheatDom = CHEAT_DOMAINS.some(d => e.domain.toLowerCase().includes(d));
    
    if (!appGroups[e.bundleID]) {
      appGroups[e.bundleID] = {
        bundleID: e.bundleID,
        domains: new Set(),
        isCritical: !!CHEAT_APPS[e.bundleID] || isCheatDom,
        isVpsRelay: isVps,
        isGhost: !appsInUsage.has(e.bundleID) && !e.bundleID.includes("apple")
      };
    }
    appGroups[e.bundleID].domains.add(e.domain);
  });

  return {
    critical: Object.values(appGroups).filter(a => a.isCritical),
    vpsHits: Object.values(appGroups).filter(a => a.isVpsRelay),
    ghosts: Object.values(appGroups).filter(a => a.isGhost),
    ffSessions: ipsData?.entries?.filter(e => e.bundleId?.toLowerCase().includes("freefire")) || []
  };
}

// --- INTERFAZ GRAFICA ---
function buildHTML(data) {
  return `
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { background:#0a0e14; color:#aab2bd; font-family: -apple-system; padding:20px; }
  .header { text-align:center; margin-bottom: 30px; }
  .title { font-size:32px; font-weight:900; color:#fff; letter-spacing:-1px; }
  .title span { color:#00ffff; }
  .stat-card { background:#11161d; border-radius:15px; padding:20px; text-align:center; border:1px solid #1e2530; margin-bottom:20px; }
  .card { background:#11161d; border-radius:12px; padding:15px; margin-bottom:12px; border:1px solid #1e2530; position:relative; overflow:hidden; }
  .crit { border-left: 4px solid #ff00cc; }
  .vps { border-left: 4px solid #58a6ff; }
  .ghost { border-left: 4px solid #ffaa00; }
  .bundle { font-size:14px; color:#fff; font-weight:700; font-family:monospace; }
  .tag { background:#1c2128; color:#00ffff; font-size:10px; padding:4px 8px; border-radius:5px; margin-top:8px; display:inline-block; border:1px solid #2d333b; }
  .reason { color:#ff00cc; font-size:11px; margin-top:4px; font-weight:bold; }
  .section-title { font-size:12px; font-weight:bold; color:#4a5568; text-transform:uppercase; margin:20px 0 10px 5px; }
</style>
</head>
<body>
  <div class="header">
    <div class="title">Goico<span>SS</span></div>
    <div style="font-size:10px; color:#4a5568;">DATABASE V19 • FORENSIC ENGINE</div>
  </div>

  <div class="stat-card">
    <div style="font-size:11px; color:#4a5568; text-transform:uppercase;">Registros Free Fire</div>
    <div style="font-size:32px; color:#fff; font-weight:bold;">${data.ffSessions.length}</div>
  </div>

  ${data.critical.length > 0 ? '<div class="section-title">Hallazgos Críticos</div>' : ''}
  ${data.critical.map(a => `
    <div class="card crit">
      <div class="bundle">${a.bundleID}</div>
      <div class="reason">${CHEAT_APPS[a.bundleID] || "Conexión a Servidor de Cheat"}</div>
      ${Array.from(a.domains).map(d => `<div class="tag">${d}</div>`).join(' ')}
    </div>
  `).join('')}

  ${data.vpsHits.length > 0 ? '<div class="section-title">Relays & Hosting (VPS)</div>' : ''}
  ${data.vpsHits.map(a => `
    <div class="card vps">
      <div class="bundle">${a.bundleID}</div>
      <div style="font-size:11px; color:#58a6ff; margin-top:4px;">Tráfico por Hosting/Proxy</div>
      ${Array.from(a.domains).map(d => `<div class="tag">${d}</div>`).join(' ')}
    </div>
  `).join('')}

  ${data.ghosts.length > 0 ? '<div class="section-title">Apps Fantasma (Sin Uso)</div>' : ''}
  ${data.ghosts.map(a => `
    <div class="card ghost">
      <div class="bundle">${a.bundleID}</div>
      <div style="font-size:11px; color:#ffaa00; margin-top:4px;">Actividad detectada sin rastro de apertura</div>
    </div>
  `).join('')}

</body>
</html>`;
}

async function main() {
  try {
    let p1 = await DocumentPicker.openFile(); let n = Parser.ndjson(FileManager.iCloud().readString(p1));
    let p2 = await DocumentPicker.openFile(); let i = Parser.ips(FileManager.iCloud().readString(p2));
    let analysis = runAnalysis(n, i);
    let wv = new WebView(); await wv.loadHTML(buildHTML(analysis)); await wv.present();
  } catch (e) {
    let err = new Alert(); err.title = "Error"; err.message = "Carga los archivos NDJSON e IPS."; await err.present();
  }
}
main();
