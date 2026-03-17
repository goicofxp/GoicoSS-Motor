// GoicoSS - REPORTE FORENSE TOTAL V16 (Final)
// Autor: @goicofxp

const SCANNER_NAME = "Goico";
const SCANNER_VERSION = "SS";

// --- BASE DE DATOS DE AMENAZAS ---
const CHEAT_DOMAINS = [
  "purplevioleto.com", "ggpolarbear.com", "ggwhitehawk.com", "proxy.builders", 
  "authtool.app", "ipa-download", "isigncloud", "khoind", "anubisw.online", 
  "baontq.xyz", "prreqcroab.icu", "1xlite", "apple-dns.net", "udid"
];

const VPN_KEYWORDS = ["vpn", "tunnel", "proxy", "1.1.1.1", "wireguard", "adguard", "shadowsocks", "hotspot"];

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
    let ts = typeof e.timeStamp === 'string' ? Date.parse(e.timeStamp) : e.timeStamp;
    if (isNaN(ts)) ts = Date.now();

    if (!appGroups[e.bundleID]) {
      appGroups[e.bundleID] = {
        bundleID: e.bundleID,
        domains: new Set(),
        hits: 0,
        lastSeen: ts,
        isGhost: !appsInUsage.has(e.bundleID),
        isVPN: VPN_KEYWORDS.some(k => e.bundleID.toLowerCase().includes(k) || e.domain.toLowerCase().includes(k)),
        isCheat: CHEAT_DOMAINS.some(d => e.domain.toLowerCase().includes(d)),
        isSpoofed: (e.bundleID.includes("spotify") || e.bundleID.includes("apple") || e.bundleID.includes("stocks")) && (e.domain.includes("freefire") || CHEAT_DOMAINS.some(d => e.domain.includes(d)))
      };
    }
    appGroups[e.bundleID].domains.add(e.domain);
    appGroups[e.bundleID].hits++;
    if (ts > appGroups[e.bundleID].lastSeen) appGroups[e.bundleID].lastSeen = ts;
  });

  let sortedApps = Object.values(appGroups).sort((a, b) => b.lastSeen - a.lastSeen);

  return {
    critical: sortedApps.filter(a => a.isCheat || a.isSpoofed || (a.bundleID === "com.spotify.client" && a.isGhost)),
    suspects: sortedApps.filter(a => (a.isVPN || !a.bundleID.includes("apple")) && !a.isCheat && !a.isSpoofed && a.bundleID !== "com.dts.freefiremax"),
    deletedRecently: Array.from(batteryApps).filter(id => !appsInUsage.has(id)),
    ghosts: sortedApps.filter(a => a.isGhost && a.hits > 0),
    ffSessions: ipsData?.entries?.filter(e => e.bundleId?.includes("freefire")) || [],
    appStore: ipsData?.entries?.find(e => e.bundleId === "com.apple.AppStore"),
    reboots: ipsData?.reboot_history || []
  };
}

function buildHTML(data) {
  return `
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { background:#0a0e14; color:#aab2bd; font-family: -apple-system; padding:15px; margin:0; }
  .header { text-align:center; margin-bottom:20px; }
  .header h1 { color:#fff; font-size:26px; margin:0; font-weight:900; }
  .header h1 span { color:#00ffff; }
  .header p { font-size:9px; color:#4a5568; text-transform:uppercase; margin-top:5px; }

  .stat-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-bottom: 20px; }
  .stat-box { background:#161b22; border-radius:8px; padding:12px; text-align:center; border:1px solid #21262d; }
  .stat-box .val { display:block; font-size:20px; font-weight:bold; color:#fff; }
  .stat-box .lab { font-size:8px; color:#8b949e; text-transform:uppercase; margin-top:4px; }

  .card { background:#0d1117; border-radius:12px; padding:15px; margin-bottom:12px; border:1px solid #30363d; position:relative; }
  .border-blue { border-left: 4px solid #00ffff; }
  .border-green { border-left: 4px solid #4caf50; }
  .border-red { border-left: 4px solid #ff4444; }
  .border-crit { border-left: 4px solid #ff00cc; background: rgba(255, 0, 204, 0.02); }

  .label-header { font-size:10px; font-weight:bold; margin-bottom:6px; text-transform:uppercase; }
  .big-val { font-size:19px; color:#fff; font-weight:bold; }
  .bundle { font-size:15px; color:#fff; font-weight:bold; margin:5px 0; word-break:break-all; }
  .tag { background:#161b22; border-radius:5px; padding:2px 6px; font-size:10px; color:#58a6ff; border:1px solid #30363d; display:inline-block; margin:2px; }
  .situa { background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; margin:8px 0; font-size:12px; }
  .badge-ghost { background:#ff00cc; color:#fff; padding:1px 5px; border-radius:4px; font-size:9px; float:right; }
</style>
</head>
<body>
  <div class="header">
    <h1>Goico<span>SS</span></h1>
    <p>ANÁLISIS FORENSE — RAMOS MEJÍA — @goicofxp</p>
  </div>

  <div class="stat-grid">
    <div class="stat-box"><span class="val" style="color:#ff00cc;">${data.critical.length}</span><span class="lab">CRÍTICO</span></div>
    <div class="stat-box"><span class="val" style="color:#ffbb00;">${data.suspects.length}</span><span class="lab">SUSPECT</span></div>
    <div class="stat-box"><span class="val" style="color:#58a6ff;">${data.deletedRecently.length}</span><span class="lab">POSSÍVEL</span></div>
  </div>

  <div class="card border-blue">
    <div class="label-header" style="color:#00ffff;">🛒 APP STORE ABIERTA</div>
    <div class="big-val">${data.appStore ? new Date(data.appStore.lastOpen).toLocaleString('es-AR') : 'SIN REGISTROS'}</div>
  </div>

  <div class="card border-green">
    <div class="label-header" style="color:#4caf50;">🔥 FREE FIRE MAX — SESIONES</div>
    <div class="big-val">${data.ffSessions.length} Inicializaciones</div>
  </div>

  <div class="card border-blue">
    <div class="label-header" style="color:#00ffff;">🔄 REINICIOS DEL SISTEMA</div>
    ${data.reboots.length > 0 ? data.reboots.slice(0, 2).map(r => `<div style="font-size:12px; color:#eee; margin-top:2px;">🔄 ${new Date(r).toLocaleString('es-AR')}</div>`).join('') : '<div style="font-size:12px;">✓ Sin reinicios</div>'}
  </div>

  <div class="card border-red">
    <div class="label-header" style="color:#ff4444;">👻 APPS ELIMINADAS RECIENTEMENTE</div>
    ${data.deletedRecently.length > 0 ? data.deletedRecently.map(id => `<div style="font-size:13px; color:#eee; margin-top:4px;">• ${id}</div>`).join('') : '<div style="font-size:12px; color:#8b949e;">✓ No se detectaron borrados en batería</div>'}
  </div>

  ${data.ghosts.length > 0 ? `
  <div class="card border-red" style="background:rgba(255,0,204,0.03);">
    <div class="label-header" style="color:#ff00cc;">🕵️ RESIDUOS DE BORRADO (IPS)</div>
    ${data.ghosts.slice(0, 5).map(g => `
      <div style="border-bottom:1px solid #21262d; padding:8px 0;">
        <div style="font-size:13px; color:#fff;">${g.bundleID} <span class="badge-ghost">AUSENTE EN USO</span></div>
        <div style="margin-top:4px;">${Array.from(g.domains).slice(0, 3).map(d => `<span class="tag">${d}</span>`).join('')}</div>
      </div>
    `).join('')}
  </div>` : ''}

  <hr style="border:0; border-top:1px solid #1a202c; margin:20px 0;">

  <div style="font-size:11px; font-weight:bold; color:#ff00cc; margin:10px 0 10px 5px; letter-spacing:1px;">[ APARTADO CRÍTICO - W.O ]</div>
  ${data.critical.length > 0 ? data.critical.map(a => `
    <div class="card border-crit">
      <div class="bundle">${a.bundleID}</div>
      <div class="situa"><b>Status:</b> ${a.isSpoofed ? 'Inyección detectada (Spotify/Apple -> Dominio Cheat)' : 'Cheat confirmado en red.'}</div>
      <div>${Array.from(a.domains).slice(0, 5).map(d => `<span class="tag">${d}</span>`).join('')}</div>
      <div style="font-size:10px; color:#484f58; margin-top:8px;">Última conexión: ${new Date(a.lastSeen).toLocaleString('es-AR')}</div>
    </div>
  `).join('') : '<div style="text-align:center; font-size:12px; color:#4a5568; padding:10px;">Sin hallazgos críticos</div>'}

  <div style="font-size:11px; font-weight:bold; color:#ffbb00; margin:20px 0 10px 5px; letter-spacing:1px;">[ APARTADO SOSPECHOSOS ]</div>
  ${data.suspects.slice(0, 30).map(a => `
    <div class="card" style="border-left:4px solid #ffbb00;">
      <div class="bundle">${a.bundleID}</div>
      <div style="margin-top:5px;">${Array.from(a.domains).slice(0, 5).map(d => `<span class="tag">${d}</span>`).join('')}</div>
      <div style="font-size:10px; color:#484f58; margin-top:8px;">Visto: ${new Date(a.lastSeen).toLocaleString('es-AR')}</div>
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
    Speech.speak("Análisis de Goico finalizado.");
  } catch (e) {
    let err = new Alert(); err.title = "Error"; err.message = "Carga ambos archivos."; err.present();
  }
}
main();
