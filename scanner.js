// GoicoSS V94 - DATABASE INTEGRATION & SUBTITLE
// Autor: @goicofxp

// --- 1. BASE DE DATOS DE DETECCIÓN ---
const VPS_HOSTING_KEYWORDS = ["hostinger", "hstgr", "locaweb", "kinghost", "umbler", "hostgator", "uol host", "uolhost", "bol", "bol.com.br", "redehost", "weblink", "brasileirohost", "br.host", "dialhost", "serverspace", "melhorhospedagem", "ibrcom", "masterweb", "superdomínios", "superdomin", "plankton", "vps.br", "digitalocean", "linode", "akamai", "vultr", "hetzner", "ovh", "ovhcloud", "contabo", "ionos", "godaddy", "siteground", "cloudways", "amazon", "aws", "amazonaws", "google cloud", "googlecloud", "microsoft azure", "azure", "alibaba cloud", "tencent cloud", "tencentcloud", "hstgr.cloud", "srv.umbler", "kinghost.net", "locaweb.com.br", "choopa", "psychz", "m247", "serverius", "frantech", "buyvm", "sharktech", "quadranet", "nexeon", "servermania", "hostwinds", "racknerd", "dedipath", "spartanhost", "cloudie", "tsohost", "wavenet", "fasthosts", "multacom", "telus", "fdcservers", "fdc servers", "leaseweb", "colocation america", "b2 net", "b2net", "path.net", "datacamp", "tzulo", "coresite"];

const CHEAT_PROXY_ASN = {"AS35916": "Multacom Corporation", "AS47583": "Hostinger International", "AS60781": "LeaseWeb Netherlands", "AS28753": "LeaseWeb Deutschland", "AS16276": "OVH SAS", "AS14061": "DigitalOcean", "AS20473": "Choopa / Vultr", "AS8100": "QuadraNet", "AS40065": "Cnservers / FDC Servers", "AS53667": "FranTech Solutions", "AS395954": "Leaseweb USA", "AS13335": "Cloudflare Proxy", "AS209": "CenturyLink / Lumen", "AS7203": "Sharktech"};

const CHEAT_APPS = {"com.touchingapp.potatsolite": "PotatsoLite", "com.touchingapp.potatso": "Potatso", "com.monite.proxyff": "ProxyFF", "com.nssurge.inc.surge-ios": "Surge", "com.luo.quantumultx": "Quantumult X", "group.com.luo.quantumult": "Quantumult", "com.shadowrocket.Shadowrocket": "Shadowrocket", "com.liguangming.Shadowrocket": "Shadowrocket Alt", "com.github.shadowsocks": "Shadowsocks", "com.netease.trojan": "Trojan proxy", "com.hiddify.app": "Hiddify", "com.karing.app": "Karing", "com.metacubex.ClashX": "ClashX", "com.ssrss.Ssrss": "SSR iOS proxy", "com.adguard.ios.AdguardPro": "AdGuard Pro", "com.privateinternetaccess.ios": "PIA VPN", "com.anonymousiphone.detoxme": "Detox", "com.futureland.vpnmaster": "VPN Master", "com.cloudflare.1dot1dot1dot1": "Cloudflare WARP", "com.opa334.dopamine": "Dopamine", "org.coolstar.sileo": "Sileo", "org.coolstar.odyssey": "Odyssey", "com.electrateam.unc0ver": "unc0ver", "com.tihmstar.checkra1n": "checkra1n", "org.taurine.jailbreak": "Taurine", "xyz.palera1n.palera1n": "palera1n", "com.opa334.TrollStore": "TrollStore", "com.rileytestut.AltStore": "AltStore", "com.esign.ios": "ESign", "com.iosgods.iosgods": "iOSGods", "com.tigisoftware.Filza": "Filza", "com.shpion.cleaner": "Spion Cleaner"};

const SUSPICIOUS_TLDS = [".site", ".store", ".netlify.app", ".xyz", ".pw", ".top", ".click", ".bid", ".win", ".monster", ".lol"];
const SUSPICIOUS_DOMAIN_WORDS = ["proxy", "cheat", "hack", "bypass", "mitm", "inject", "spoof", "crack", "payload", "tunnel", "vpn"];

const FF_PROXY_LOGIN_DOMAINS = new Set(["version.ffmax.purplevioleto.com", "version.ggwhitehawk.com", "loginbp.ggpolarbear.com", "gin.freefiremobile.com", "100067.connect.garena.com", "client.us.freefiremobile.com", "sacnetwork.ggblueshark.com", "api.baontq.xyz", "anubisw.online"]);

const PROXY_IPA_BUNDLES = ["com.spotify.client", "com.burbn.instagram", "net.whatsapp.WhatsApp", "com.google.ios.youtube", "com.apple.mobilesafari", "com.facebook.Facebook"];

const FALSE_POSITIVE_IPS = new Set(["104.29.152.79", "104.29.152.107", "92.223.118.254", "23.221.214.168"]);

// --- 2. MOTOR DE ANÁLISIS ---
function smartParse(raw) {
  try {
    let clean = raw.trim();
    if (clean.includes('\n')) return clean.split('\n').map(l => { try { return JSON.parse(l.substring(l.indexOf('{'))); } catch(e) { return null; } }).filter(Boolean);
    let start = clean.indexOf('{');
    let parsed = JSON.parse(clean.substring(start));
    return parsed.usageEntries || parsed.entries || (Array.isArray(parsed) ? parsed : [parsed]);
  } catch(e) { return []; }
}

function runAnalysis(net, usage) {
  let res = { critical: {}, suspicious: {}, system: { files: null, store: null, reboot: null }, restarts: 0 };
  usage.forEach(e => {
    let bid = (e.bundleID || e.bundleId || e.ProcessName || "").toLowerCase();
    let ts = e.lastOpen || e.timestamp || e.TimeStamp || e.date;
    if (bid.includes("freefire")) res.restarts++;
    if (bid.includes("documentsapp") || bid.includes("com.apple.files")) res.system.files = ts;
    if (bid.includes("appstore") || bid.includes("itunesstore")) res.system.store = ts;
    if (bid.includes("springboard") || bid.includes("backboardd")) res.system.reboot = ts;
  });
  net.forEach(e => {
    let dom = e.domain?.toLowerCase() || "";
    let bid = e.bundleID || e.bundleId || "";
    let asn = e.ASN || "";
    let ip = e.remoteAddress || "";
    let ts = e.timeStamp || e.timestamp || e.date;
    if (!bid || !dom || FALSE_POSITIVE_IPS.has(ip)) return;

    let isCrit = FF_PROXY_LOGIN_DOMAINS.has(dom) || (PROXY_IPA_BUNDLES.includes(bid) && SUSPICIOUS_DOMAIN_WORDS.some(w => dom.includes(w)));
    let isSusp = !isCrit && (CHEAT_APPS[bid] || VPS_HOSTING_KEYWORDS.some(k => dom.includes(k)) || CHEAT_PROXY_ASN[asn] || SUSPICIOUS_TLDS.some(t => dom.endsWith(t)) || SUSPICIOUS_DOMAIN_WORDS.some(w => dom.includes(w)));

    if (isCrit) {
      if (!res.critical[bid]) res.critical[bid] = { bid, doms: new Set(), hits: 0, ts: ts, type: "Inyectable / Mod" };
      res.critical[bid].doms.add(dom); res.critical[bid].hits++;
    } else if (isSusp) {
      let type = CHEAT_APPS[bid] ? "Cheat App" : (CHEAT_PROXY_ASN[asn] ? "Proxy ASN" : "Hosting/TLD");
      if (!res.suspicious[bid]) res.suspicious[bid] = { bid, doms: new Set(), hits: 0, ts: ts, type: type };
      res.suspicious[bid].doms.add(dom); res.suspicious[bid].hits++;
    }
  });
  return res;
}

// --- 3. GUI ---
function buildHTML(res) {
  const f = (t) => t ? new Date(t).toLocaleString('es-AR') : "Sin registro";
  const renderCard = (item, type) => {
    const isCrit = type === 'crit';
    const color = isCrit ? '#ff00cc' : '#ffcc00';
    return `
      <div class="card" style="border-left: 4px solid ${color}">
        <span class="label-f" style="color:${color}">⚠️ ${isCrit ? 'CRÍTICO' : 'SOSPECHOSO'}</span>
        <span style="position:absolute; right:18px; top:18px; font-size:11px; color:#8b949e;">${item.hits} hits</span>
        <div class="val">${item.bid}</div>
        <table class="details">
          <tr><td>Situação</td><td style="color:${color}">${isCrit ? 'PROXY' : 'SUSPEITO'}</td></tr>
          <tr><td>Detección</td><td>${item.type}</td></tr>
          <tr><td>Indicador</td><td>${isCrit ? 'Inyectable-Cheat' : 'Filtro de Red'}</td></tr>
          ${isCrit ? '<tr><td>Usado por</td><td style="color:#007aff;">com.dts.freefireth</td></tr>' : ''}
          <tr><td>Modificado o Borrado</td><td>${f(item.ts)}</td></tr>
        </table>
        <div style="margin-top:10px;">${Array.from(item.doms).slice(0, 3).map(d => `<span class="tag">${d}</span>`).join('')}</div>
        ${isCrit ? '<div class="btn-wo">TOME W.O</div>' : ''}
      </div>`;
  };

  return `<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><style>
    body { background:#0a1016; color:#aab2bd; font-family:sans-serif; padding:15px; margin:0; }
    .card { background:#11161d; border-radius:12px; padding:18px; margin-bottom:12px; border:1px solid #1c2128; position:relative; }
    .label-f { background:#1c2128; font-size:9px; font-weight:bold; padding:4px 8px; border-radius:5px; margin-bottom:10px; display:inline-block; }
    .val { color:#fff; font-size:13px; font-weight:bold; font-family:monospace; }
    .details { width:100%; border-collapse:collapse; margin-top:10px; font-size:11px; }
    .details td { padding:5px 0; border-bottom:1px solid #1c2128; }
    .details td:last-child { color:#fff; text-align:right; font-weight:bold; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px; }
    .grid-item { background: #11161d; border-radius: 12px; padding: 12px; border: 1px solid #1c2128; border-left: 3px solid #00ffff; }
    .g-label { font-size: 8px; font-weight: bold; color: #8b949e; text-transform: uppercase; margin-bottom: 4px; }
    .g-val { font-size: 10px; color: #fff; font-weight: bold; }
    .btn-wo { background:#ff00cc; color:#fff; text-align:center; padding:10px; border-radius:8px; margin-top:15px; font-weight:900; }
    .tag { background:#1c2128; border:1px solid #30363d; border-radius:4px; padding:2px 5px; font-size:9px; color:#58a6ff; margin-right:4px; display:inline-block; }
  </style></head><body>
    <div style="text-align:center; margin-bottom:20px;">
      <h2 style="color:#fff; margin:0; padding:0;">Goico<span style="color:#00ffff;">SS</span></h2>
      <div style="color:#00ffff; font-size:10px; font-weight:bold; text-transform:uppercase; letter-spacing:1px;">Scanner iOS</div>
    </div>
    <div class="card" style="border-left: 4px solid #34c759;"><div class="label-f" style="color:#34c759">🔥 SESIONES DE JUEGO</div><div class="val">Total Aperturas: ${res.restarts}</div></div>
    <div class="grid-2">
      <div class="grid-item"><div class="g-label">📂 Archivos</div><div class="g-val">${f(res.system.files)}</div></div>
      <div class="grid-item"><div class="g-label">🏪 App Store</div><div class="g-val">${f(res.system.store)}</div></div>
    </div>
    <div class="grid-2">
      <div class="grid-item" style="border-left-color: #34c759;"><div class="g-label">🔄 Reinicio</div><div class="g-val">${f(res.system.reboot)}</div></div>
      <div class="grid-item" style="border-left-color: #34c759;"><div class="g-label">🔥 System Boot</div><div class="g-val">${res.system.reboot ? "SISTEMA ACTIVO" : "LOG REGISTRADO"}</div></div>
    </div>
    <div class="grid-2" style="margin-top:20px;">
      <div class="grid-item" style="text-align:center; border: 1px solid #1c2128;"><div style="font-size:22px; font-weight:900; color:#ff00cc;">${Object.keys(res.critical).length}</div><div class="g-label">Crítico</div></div>
      <div class="grid-item" style="text-align:center; border: 1px solid #1c2128;"><div style="font-size:22px; font-weight:900; color:#ffcc00;">${Object.keys(res.suspicious).length}</div><div class="g-label">Suspeito</div></div>
    </div>
    <div style="color:#ff00cc; font-size:11px; font-weight:bold; margin:20px 0 10px 5px;">[ HALLAZGOS CRÍTICOS ]</div>
    ${Object.values(res.critical).map(c => renderCard(c, 'crit')).join('') || '<p style="font-size:10px; margin-left:10px;">Limpio</p>'}
    <div style="color:#ffcc00; font-size:11px; font-weight:bold; margin:20px 0 10px 5px;">[ HALLAZGOS SOSPECHOSOS ]</div>
    ${Object.values(res.suspicious).map(s => renderCard(s, 'susp')).join('') || '<p style="font-size:10px; margin-left:10px;">Limpio</p>'}
  </body></html>`;
}

async function main() {
  try {
    let p1 = await DocumentPicker.openFile();
    let net = smartParse(FileManager.local().readString(p1));
    let p2 = await DocumentPicker.openFile();
    let usage = smartParse(FileManager.local().readString(p2));
    let wv = new WebView();
    await wv.loadHTML(buildHTML(runAnalysis(net, usage)));
    await wv.present();
  } catch (e) {
    let a = new Alert(); a.message = "Error: " + e.message; await a.present();
  }
}
main();
