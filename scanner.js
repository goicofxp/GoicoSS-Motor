// GoicoSS - REPORTE FORENSE TOTAL V18 (Base de Datos Keller Integrada)
// Autor: @goicofxp

const SCANNER_NAME = "Goico";
const SCANNER_VERSION = "SS";

// --- BASE DE DATOS EXTENDIDA (KELLER LOGIC) ---
const VPS_HOSTING_KEYWORDS = ["hostinger", "hstgr", "locaweb", "kinghost", "umbler", "hostgator", "uolhost", "digitalocean", "linode", "akamai", "vultr", "hetzner", "ovh", "contabo", "aws", "azure", "googlecloud", "choopa", "psychz", "m247", "path.net", "datacamp"];
const CHEAT_APPS = {
  "com.touchingapp.potatsolite": "PotatsoLite — proxy iOS (mitmproxy cheat)",
  "com.monite.proxyff": "ProxyFF — proxy iOS (cheat confirmado)",
  "com.shadowrocket.Shadowrocket": "Shadowrocket — proxy iOS",
  "com.opa334.dopamine": "Dopamine — Jailbreak",
  "com.opa334.TrollStore": "TrollStore — sideload sem JB",
  "com.esign.ios": "ESign — sideload/IPA installer",
  "com.iosgods.iosgods": "iOSGods — cheat app store",
  "com.tigisoftware.Filza": "Filza — file manager root",
  "com.apple.Preferences.Developer": "Preferencias de Desenvolvedor (activas)"
};
const CHEAT_DOMAINS = ["purplevioleto.com", "ggpolarbear.com", "ggwhitehawk.com", "anubisw.online", "baontq.xyz", "fatalitycheats.xyz", "proxy.builders"];
const SUSPICIOUS_TLDS = [".site", ".store", ".netlify.app", ".xyz", ".icu", ".monster", ".fun"];

// --- MOTOR DE ANÁLISIS ---
const Parser = {
  ndjson: (raw) => raw.split('\n').filter(l => l.trim()).map(l => { try { return JSON.parse(l); } catch(e) { return null; } }).filter(x => x),
  ips: (raw) => { try { return JSON.parse(raw); } catch(e) { return null; } }
};

function runAnalysis(netEntries, ipsData) {
  let appGroups = {};
  let appsInUsage = new Set(ipsData?.entries?.map(e => e.bundleId) || []);
  let batteryApps = new Set(ipsData?.battery_usage?.map(b => b.bundleId) || []);

  netEntries.forEach(e => {
    if (!e.bundleID || !e.domain) return;
    let isVps = VPS_HOSTING_KEYWORDS.some(k => e.domain.toLowerCase().includes(k));
    let isCheatDom = CHEAT_DOMAINS.some(d => e.domain.toLowerCase().includes(d));
    let isSuspiciousTld = SUSPICIOUS_TLDS.some(t => e.domain.toLowerCase().endsWith(t));

    if (!appGroups[e.bundleID]) {
      appGroups[e.bundleID] = {
        bundleID: e.bundleID,
        domains: new Set(),
        isCritical: !!CHEAT_APPS[e.bundleID] || isCheatDom,
        isVpsRelay: isVps,
        isGhost: !appsInUsage.has(e.bundleID) && e.bundleID !== "com.apple.mobilesafari"
      };
    }
    appGroups[e.bundleID].domains.add(e.domain);
  });

  return {
    critical: Object.values(appGroups).filter(a => a.isCritical),
    vpsHits: Object.values(appGroups).filter(a => a.isVpsRelay),
    ghosts: Object.values(appGroups).filter(a => a.isGhost),
    ffSessions: ipsData?.entries?.filter(e => e.bundleId?.includes("freefire")) || [],
    totalConexiones: netEntries.length,
    inicio: netEntries[0]?.timeStamp || Date.now()
  };
}

// --- INTERFAZ VISUAL ---
function buildHTML(data) {
  return `
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { background:#0a0e14; color:#aab2bd; font-family: -apple-system; padding:15px; }
  .header { text-align:center; padding: 20px 0; border-bottom: 1px solid #1e2530; margin-bottom: 20px; }
  .title { font-size:35px; font-weight:900; color:#fff; }
  .title span { color:#00ffff; }
  .card { background:#11161d; border-radius:12px; padding:15px; margin-bottom:12px; border:1px solid #1e2530; }
  .crit-border { border-left: 5px solid #ff00cc; }
  .vps-border { border-left: 5px solid #58a6ff; }
  .bundle { font-size:14px; color:#fff; font-weight:bold; }
  .tag { background:#1c2128; color:#00ffff; font-size:10px; padding:3px 7px; border-radius:4px; margin-right:5px; }
  .label { color: #4a5568; font-size: 10px; text-transform: uppercase; font-weight: bold; }
</style>
</head>
<body>
  <div class="header">
    <div class="title">Goico<span>SS</span></div>
    <div style="font-size:10px; color:#4a5568; margin-top:5px;">DATABASE V18 - MOTOR FORENSE</div>
  </div>

  <div class="card">
    <div class="label">Sesiones Free Fire</div>
    <div style="font-size:24px; color:#fff; font-weight:bold;">${data.ffSessions.length} Aperturas</div>
  </div>

  <h3 style="color:#ff00cc; font-size:12px;">[ HALLAZGOS CRÍTICOS ]</h3>
  ${data.critical.map(a => `
    <div class="card crit-border">
      <div class="bundle">${a.bundleID}</div>
      <div style="font-size:11px; color:#ff00cc; margin:5px 0;">${CHEAT_APPS[a.bundleID] || "Dominio de Cheat Detectado"}</div>
      <div>${Array.from(a.domains).slice(0,3).map(d => `<span class="tag">${d}</span>`).join('')}</div>
    </div>
  `).join('') || '<p style="font-size:12px;">Limpio</p>'}

  <h3 style="color:#58a6ff; font-size:12px;">[ RELAYS / VPS HOSTING ]</h3>
  ${data.vpsHits.map(a => `
    <div class="card vps-border">
      <div class="bundle">${a.bundleID}</div>
      <div style="font-size:11px; color:#58a6ff; margin:5px 0;">Conexión a Hosting/Proxy</div>
      <div>${Array.from(a.domains).slice(0,3).map(d => `<span class="tag">${d}</span>`).join('')}</div>
    </div>
  `).join('') || '<p style="font-size:12px;">Sin proxies detectados</p>'}
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
    let err = new Alert(); err.title = "Error"; err.message = "Carga los archivos requeridos."; err.present();
  }
}
main();
