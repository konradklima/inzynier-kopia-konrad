"""Strona centrum sterowania (jeden plik HTML z CSS i JS), wg zrzutów ekranu."""

PAGE = r"""<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>System analizy bezpieczeństwa – Projekt i implementacja systemu analizy bezpieczeństwa aplikacji internetowych z wykorzystaniem architektury wieloagentowej</title>
<style>
:root{--bg:#f5f5f8;--card:#fff;--fg:#1b1b1f;--muted:#6f7280;--line:#e8e8ee;--blue:#0a6cf0;
--red:#e5383b;--redbg:#fde8e8;--orange:#f08a24;--orangebg:#fdeede;--yellow:#a8800f;--yellowbg:#fbf1cf;--green:#2a9d4a;--greenbg:#e6f4ea}
*{box-sizing:border-box}
body{margin:0;font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--fg);display:flex;min-height:100vh}
aside{width:210px;padding:20px 12px;background:#f7f7fa;border-right:1px solid var(--line);flex:none}
.logo{font-weight:700;font-size:15px;line-height:1.3;padding:0 12px 18px;display:flex;gap:8px;align-items:center}
.logo b{color:var(--blue)}
nav a{display:block;padding:9px 12px;margin-bottom:4px;border-radius:9px;color:#333;text-decoration:none;font-weight:500;cursor:pointer}
nav a.on{background:#fff;color:var(--fg);box-shadow:0 1px 3px #0001;font-weight:600}
nav a.on::before{content:"";}
main{flex:1;min-width:0;background:#fff}
header{padding:16px 28px;border-bottom:1px solid var(--line)}
header h1{font-size:17px;margin:0}
.sub{color:var(--muted);font-size:12.5px;margin-top:2px}
.control{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px}
.control input[type=text]{flex:1;min-width:260px;padding:10px 14px;border:1px solid #cfd0d8;border-radius:999px;font-size:14px;outline:none}
.control input[type=text]:focus{border-color:var(--blue);box-shadow:0 0 0 3px #0a6cf022}
select{padding:10px 12px;border:1px solid #cfd0d8;border-radius:999px;background:#fff;font-size:13px}
.btn{background:var(--blue);color:#fff;border:0;border-radius:999px;padding:10px 20px;font-weight:600;font-size:14px;cursor:pointer}
.btn:disabled{opacity:.55;cursor:default}
.btn.ghost{background:#fff;color:var(--fg);border:1px solid #cfd0d8}
.opts{display:none;width:100%;font-size:12.5px;color:var(--muted);gap:16px;flex-wrap:wrap}
.opts label{display:flex;gap:6px;align-items:center}
.opts.show{display:flex}
.msg{margin-top:10px;padding:10px 14px;border-radius:10px;font-size:13px;display:none}
.msg.show{display:block}
.msg.info{background:#eaf2fe;color:#0b4fb3}.msg.err{background:var(--redbg);color:#a31d20}.msg.ok{background:var(--greenbg);color:#1d6e36}
.spin{display:inline-block;width:12px;height:12px;border:2px solid #0b4fb355;border-top-color:#0b4fb3;border-radius:50%;animation:s 1s linear infinite;margin-right:8px;vertical-align:-1px}
@keyframes s{to{transform:rotate(360deg)}}
section{padding:22px 28px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.card{border:1px solid var(--line);border-radius:14px;padding:16px;min-height:130px}
.card h4{margin:0 0 10px;font-size:11px;letter-spacing:.06em;color:var(--muted);font-weight:600}
.big{font-size:34px;font-weight:700;line-height:1}
.risk{display:flex;gap:14px;align-items:center}
.ring{width:62px;height:62px;border-radius:50%;display:grid;place-items:center;font-weight:700;font-size:20px;position:relative}
.ring::after{content:"";position:absolute;inset:7px;background:#fff;border-radius:50%}
.ring span{position:relative;z-index:1}
.bars{display:flex;gap:6px;align-items:flex-end;height:44px}
.bars i{flex:1;background:#e3ecfb;border-radius:3px}.bars i:last-child{background:#ef6b64}
h2{font-size:16px;margin:26px 0 10px;display:flex;justify-content:space-between;align-items:baseline}
h2 small{font-weight:400;color:var(--muted);font-size:13px;margin-left:8px}
h2 a{font-size:13px;color:var(--blue);cursor:pointer;font-weight:500}
.list{border:1px solid var(--line);border-radius:14px;overflow:hidden}
.row{display:flex;gap:14px;align-items:center;padding:14px 16px;border-bottom:1px solid var(--line);cursor:pointer}
.row:last-child{border-bottom:0}.row:hover{background:#fafafc}
.ico{width:10px;height:10px;border-radius:50%;flex:none}
.row .t{flex:1;min-width:0}.row .t b{display:block;font-size:14.5px}
code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--muted);overflow-wrap:anywhere}
.badge{padding:5px 12px;border-radius:8px;font-size:12px;font-weight:700;white-space:nowrap}
.high{background:var(--redbg);color:#a31d20}.medium{background:var(--orangebg);color:#9a4a00}.low{background:var(--yellowbg);color:#6b5100}
.ico.high{background:var(--red)}.ico.medium{background:var(--orange)}.ico.low{background:#d4a72c}
.empty{padding:30px;text-align:center;color:var(--muted)}
.crumb{color:var(--muted);font-size:12.5px;margin-bottom:12px}.crumb b{color:var(--fg)}
.detail{display:grid;grid-template-columns:2fr 1fr;gap:18px;margin-top:16px}
.panel{border:1px solid var(--line);border-radius:14px;padding:6px 16px}
.panel h4{font-size:11px;letter-spacing:.06em;color:var(--muted);margin:12px 0 4px}
.kv{display:flex;justify-content:space-between;gap:14px;padding:9px 0;border-bottom:1px solid var(--line);font-size:13px}
.kv:last-child{border:0}.kv span:last-child{font-family:ui-monospace,Menlo,monospace;text-align:right;overflow-wrap:anywhere}
.fix{background:var(--greenbg);border-radius:14px;padding:16px 18px;margin-top:18px}
.fix small{color:var(--green);font-weight:700;letter-spacing:.06em;font-size:11px}
.fix b{display:block;margin:2px 0 6px;font-size:15px}.fix p{margin:0;white-space:pre-wrap}
.back{background:none;border:0;color:var(--blue);cursor:pointer;font-size:13px;padding:0}
@media(max-width:900px){.cards{grid-template-columns:1fr 1fr}.detail{grid-template-columns:1fr}aside{display:none}}
@media print{aside,.control,.msg{display:none!important}}
</style>
</head>
<body>
<aside>
  <div class="logo"><span title="Projekt i implementacja systemu analizy bezpieczeństwa aplikacji internetowych z wykorzystaniem architektury wieloagentowej">System analizy bezpieczeństwa</span></div>
  <nav>
    <a data-view="dash" class="on">Pulpit</a>
    <a data-view="threats">Zagrożenia</a>
    <a data-view="scans">Skany</a>
  </nav>
</aside>
<main>
  <header>
    <h1 id="title">Pulpit bezpieczeństwa</h1>
    <div class="sub" id="subtitle">Wpisz adres strony i uruchom skan</div>
    <form class="control" id="form" autocomplete="off">
      <input type="text" id="url" placeholder="Adres strony, np. przyklad.pl, https://moja-strona.com albo localhost:3000" spellcheck="false" required>
      <select id="mode" title="Tryb skanu">
        <option value="baseline">Szybki (pasywny, ~2 min)</option>
        <option value="focused">Celowany (aktywny)</option>
        <option value="full">Pełny (aktywny, długi)</option>
      </select>
      <button class="btn" id="go" type="submit">Skanuj</button>
      <div class="opts show">
        <label><input type="checkbox" id="consent" required> Potwierdzam, że ta strona należy do mnie albo mam zgodę jej właściciela na skanowanie</label>
      </div>
      <div class="opts" id="opts">
        <label><input type="checkbox" id="ajax"> Pająk AJAX (aplikacje jednostronicowe)</label>
        <span>Skany aktywne wysyłają prawdziwe ataki testowe i mogą obciążyć stronę.</span>
      </div>
    </form>
    <div class="msg" id="msg"></div>
  </header>
  <section id="view"></section>
</main>
<script>
const fmt=t=>{const d=new Date(t);return isNaN(d)?t:d.toLocaleString("pl-PL",{dateStyle:"medium",timeStyle:"short"})};
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let current=null, view="dash", polling=null;

function setMsg(kind,html){const m=$("#msg");m.className="msg show "+kind;m.innerHTML=html}
function clearMsg(){$("#msg").className="msg"}
async function api(path,opt){const r=await fetch(path,opt);const d=await r.json();if(!r.ok)throw new Error(d.error||"Błąd");return d}

$("#mode").onchange=()=>$("#opts").classList.toggle("show",$("#mode").value!=="baseline");
document.querySelectorAll("nav a").forEach(a=>a.onclick=()=>go(a.dataset.view));
function go(v,extra){view=v;document.querySelectorAll("nav a").forEach(a=>a.classList.toggle("on",a.dataset.view===(v==="detail"?"threats":v)));render(extra)}

$("#form").onsubmit=async e=>{
  e.preventDefault();
  if(!$("#consent").checked){setMsg("err","Zaznacz potwierdzenie, że strona należy do Ciebie albo masz zgodę jej właściciela.");return}
  try{
    await api("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({
      url:$("#url").value,mode:$("#mode").value,consent:$("#consent").checked,ajax:$("#ajax").checked})});
    poll();
  }catch(err){setMsg("err",esc(err.message))}
};

function poll(){
  clearInterval(polling);
  const tick=async()=>{
    const j=await api("/api/job");
    $("#go").disabled=j.state==="running";
    if(j.state==="running"){setMsg("info",`<span class="spin"></span>Skanuję ${esc(j.target)} (tryb: ${({baseline:"szybki",focused:"celowany",full:"pełny"})[j.mode]||esc(j.mode)})… to może potrwać kilka minut.`)}
    else{clearInterval(polling);polling=null;
      if(j.state==="done"){setMsg("ok","Skan zakończony.");await load(j.scan_id);go("dash")}
      else if(j.state==="error"){setMsg("err",esc(j.error))}
      else clearMsg()}
  };
  tick();polling=setInterval(tick,1500);
}

async function load(id){current=await api("/api/scans/"+id)}
async function init(){
  const scans=await api("/api/scans");
  if(scans.length)await load(scans[0].id);
  render();
  const j=await api("/api/job");if(j.state==="running")poll();
}

function threatRow(f,i){return `<div class="row" onclick="go('detail',${i})"><div class="ico ${f.tier}"></div>
<div class="t"><b>${esc(f.title)}</b><code>${esc(f.path)}</code></div><span class="badge ${f.tier}">${esc(f.tier_label)}</span><span style="color:var(--muted)">›</span></div>`}

function render(i){
  const v=$("#view");
  const titles={dash:"Pulpit bezpieczeństwa",threats:"Zagrożenia",scans:"Skany",detail:"Szczegóły zagrożenia"};
  $("#title").textContent=titles[view];
  if(!current&&view!=="scans"){v.innerHTML='<div class="empty">Nie ma jeszcze żadnego skanu.<br>Wpisz adres strony powyżej i kliknij „Skanuj”.</div>';$("#subtitle").textContent="Wpisz adres strony i uruchom skan";return}
  if(current)$("#subtitle").textContent=`${current.target} · ostatni skan: ${fmt(current.created_at)}`;
  if(view==="dash")return dash(v);
  if(view==="threats")return threats(v);
  if(view==="scans")return scans(v);
  if(view==="detail")return detail(v,i);
}

function dash(v){
  const r=current.real,n=r.length,c=t=>r.filter(f=>f.tier===t).length;
  const level=n===0?["Niski","#2a9d4a","brak pilnych spraw"]:c("high")?["Wysoki","#e5383b","wymaga uwagi"]:c("medium")?["Średni","#f08a24","warto zająć się wkrótce"]:["Niski","#2a9d4a","drobne poprawki"];
  const score=Math.min(10,c("high")*3+c("medium")*2+c("low"));
  const h=current.history,max=Math.max(1,...h.map(x=>x.real));
  v.innerHTML=`<div class="cards">
  <div class="card"><h4>POZIOM RYZYKA</h4><div class="risk"><div class="ring" style="background:conic-gradient(${level[1]} ${score*10}%,#eee 0)"><span>${score}</span></div><div><b style="font-size:19px">${level[0]}</b><div class="sub">${level[2]}</div></div></div></div>
  <div class="card"><h4>REALNE ZAGROŻENIA</h4><div class="big" style="color:#c42528">${n}</div><div class="sub" style="margin-top:8px">${c("high")} pilne · ${c("medium")} ważne · ${c("low")} drobne</div></div>
  <div class="card"><h4>ODRZUCONY SZUM</h4><div class="big" style="color:#1f7a3a">${current.noise_count}</div><div class="sub" style="margin-top:8px">fałszywe alarmy</div></div>
  <div class="card"><h4>HISTORIA SKANÓW</h4><div class="bars">${h.map(x=>`<i style="height:${Math.max(12,x.real/max*100)}%" title="#${x.id}: ${x.real}"></i>`).join("")}</div></div></div>
  <h2><span>Zagrożenia do naprawienia <small>${n} ${n===1?"pozycja":"pozycji"}</small></span><a onclick="go('threats')">Pokaż wszystkie</a></h2>
  <div class="list">${n?r.slice(0,3).map(threatRow).join(""):'<div class="empty">Nic do naprawienia.</div>'}</div>`;
}
function threats(v){v.innerHTML=`<div class="list">${current.real.length?current.real.map(threatRow).join(""):'<div class="empty">Nic do naprawienia.</div>'}</div>`}
async function scans(v){
  const list=await api("/api/scans");
  v.innerHTML=`<div class="list">${list.length?list.map(s=>`<div class="row" onclick="openScan(${s.id})"><div class="t"><b>${esc(s.target)}</b><code>skan #${s.id} · ${fmt(s.created_at)}</code></div><span class="badge ${s.real?"high":"low"}">${s.real} do naprawy</span><span style="color:var(--muted)">›</span></div>`).join(""):'<div class="empty">Brak zapisanych skanów.</div>'}</div>`;
}
async function openScan(id){await load(id);go("dash")}
function detail(v,i){
  const f=current.real[i];
  v.innerHTML=`<div class="crumb"><button class="back" onclick="go('threats')">Zagrożenia</button> / <b>${esc(f.title)}</b></div>
  <div style="display:flex;gap:14px;align-items:center"><div class="ico ${f.tier}" style="width:14px;height:14px"></div>
  <div style="flex:1"><h1 style="margin:0;font-size:22px">${esc(f.title)}</h1><code>${esc(f.name)}</code></div><span class="badge ${f.tier}">${esc(f.tier_label)}</span></div>
  <div class="detail"><div><div class="panel"><h4>CO TO ZNACZY</h4><p style="white-space:pre-wrap">${esc(f.description)||"Brak opisu."}</p></div></div>
  <div class="panel"><h4>SZCZEGÓŁY WYKRYCIA</h4>
  <div class="kv"><span>Miejsce</span><span>${esc(f.path)}</span></div>
  <div class="kv"><span>Poziom</span><span>${esc(f.severity)}</span></div>
  <div class="kv"><span>Pewność</span><span>${esc(f.confidence)}</span></div>
  <div class="kv"><span>Wystąpień</span><span>${f.occurrences}</span></div>
  <div class="kv"><span>Kategoria</span><span>${esc(f.owasp)}</span></div>
  ${f.cwe?`<div class="kv"><span>CWE</span><span>${f.cwe}</span></div>`:""}</div></div>
  <div class="fix"><small>ZALECANE DZIAŁANIE</small><b>Jak to naprawić</b><p>${esc(f.solution)||"Brak zaleceń od skanera."}</p></div>
  <p><button class="btn ghost" onclick="window.print()">Eksport PDF</button></p>`;
}
init();
</script>
</body>
</html>
"""
