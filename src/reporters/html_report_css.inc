R"mikto_css(
/* тема отчёта: токены, светлая и тёмная через prefers-color-scheme */
:root{
  --bg:#f7f6f3; --card:#ffffff; --card-2:#f2f0ec; --ink:#1c1917; --muted:#6d6862;
  --line:#e5e1db; --line-strong:#cfc9c0; --accent:#0f766e; --accent-ink:#ffffff;
  --ok:#15803d; --ok-wash:#f0f7f1; --warn-wash:#fdf6ec;
  --critical:#b91c1c; --high:#c2410c; --medium:#a16207; --low:#1d4ed8; --info:#5f6b76;
  --critical-wash:#fbf1f1; --high-wash:#fbf2ec; --medium-wash:#faf5e9; --low-wash:#eef3fc; --info-wash:#eef0f2;
  --shadow:0 1px 2px rgba(28,25,23,.05),0 4px 14px rgba(28,25,23,.05);
  --shadow-raise:0 1px 2px rgba(28,25,23,.06),0 8px 24px rgba(28,25,23,.09);
  --r-lg:14px; --r-md:10px; --r-sm:6px;
  --nav-h:52px;
  --sans:ui-sans-serif,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"SF Mono","Cascadia Mono",Consolas,"Liberation Mono",monospace;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0d1013; --card:#14181d; --card-2:#1a2027; --ink:#e8e6e3; --muted:#98a1aa;
    --line:#262d35; --line-strong:#39424c; --accent:#2dd4bf; --accent-ink:#062a26;
    --ok:#4ade80; --ok-wash:#12251a; --warn-wash:#2a2114;
    --critical:#f87171; --high:#fb923c; --medium:#eab308; --low:#60a5fa; --info:#94a3b8;
    --critical-wash:#2a1517; --high-wash:#2a1a12; --medium-wash:#272113; --low-wash:#15202f; --info-wash:#1a2027;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 4px 14px rgba(0,0,0,.35);
    --shadow-raise:0 1px 2px rgba(0,0,0,.5),0 10px 28px rgba(0,0,0,.5);
    color-scheme:dark;
  }
}
:root[data-theme=light]{--bg:#f7f6f3;--card:#ffffff;--card-2:#f2f0ec;--ink:#1c1917;--muted:#6d6862;--line:#e5e1db;--line-strong:#cfc9c0;--accent:#0f766e;--accent-ink:#ffffff;--ok:#15803d;--ok-wash:#f0f7f1;--warn-wash:#fdf6ec;--critical:#b91c1c;--high:#c2410c;--medium:#a16207;--low:#1d4ed8;--info:#5f6b76;--critical-wash:#fbf1f1;--high-wash:#fbf2ec;--medium-wash:#faf5e9;--low-wash:#eef3fc;--info-wash:#eef0f2;--shadow:0 1px 2px rgba(28,25,23,.05),0 4px 14px rgba(28,25,23,.05);--shadow-raise:0 1px 2px rgba(28,25,23,.06),0 8px 24px rgba(28,25,23,.09);color-scheme:light}
:root[data-theme=dark]{--bg:#0d1013;--card:#14181d;--card-2:#1a2027;--ink:#e8e6e3;--muted:#98a1aa;--line:#262d35;--line-strong:#39424c;--accent:#2dd4bf;--accent-ink:#062a26;--ok:#4ade80;--ok-wash:#12251a;--warn-wash:#2a2114;--critical:#f87171;--high:#fb923c;--medium:#eab308;--low:#60a5fa;--info:#94a3b8;--critical-wash:#2a1517;--high-wash:#2a1a12;--medium-wash:#272113;--low-wash:#15202f;--info-wash:#1a2027;--shadow:0 1px 2px rgba(0,0,0,.4),0 4px 14px rgba(0,0,0,.35);--shadow-raise:0 1px 2px rgba(0,0,0,.5),0 10px 28px rgba(0,0,0,.5);color-scheme:dark}

*{box-sizing:border-box}
html{scroll-behavior:smooth}
@media (prefers-reduced-motion:reduce){
  html{scroll-behavior:auto}
  *,*::before,*::after{animation-duration:.01ms !important;animation-iteration-count:1 !important;transition-duration:.01ms !important}
}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 var(--sans);-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
a{color:var(--accent);text-decoration:none;text-underline-offset:3px}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.skip{position:absolute;left:-9999px;top:0;background:var(--card);color:var(--ink);padding:10px 16px;border-radius:var(--r-sm);box-shadow:var(--shadow);z-index:99}
.skip:focus{left:12px;top:12px}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px 72px}
section{scroll-margin-top:calc(var(--nav-h) + 16px)}
.num{font-variant-numeric:tabular-nums}
code,.mono{font-family:var(--mono);font-size:.92em;background:var(--card-2);border:1px solid var(--line);border-radius:5px;padding:.5px 6px;word-break:break-all}
pre{background:var(--card-2);border:1px solid var(--line);color:var(--ink);padding:12px 14px;border-radius:var(--r-md);overflow:auto;font-size:12.5px;line-height:1.5;margin:8px 0 0;max-height:340px}
pre code{background:none;border:none;padding:0}
h1,h2,h3{line-height:1.25;letter-spacing:-.015em;margin:0}
h2{font-size:21px;display:flex;align-items:baseline;gap:10px;margin:0}
h2 .cnt{color:var(--muted);font-size:14px;font-weight:600;letter-spacing:0}
section>header{margin:44px 0 16px;padding-bottom:10px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:10px;align-items:baseline;justify-content:space-between}
.muted{color:var(--muted)}
.small{font-size:13px}

.masthead{position:relative;padding:40px 0 8px;overflow:hidden}
.masthead .glow{position:absolute;inset:-40% -20% auto;height:340px;background:radial-gradient(560px 200px at 24% 30%,color-mix(in oklab,var(--accent) 16%,transparent),transparent 70%);pointer-events:none}
.masthead-grid{position:relative;display:grid;grid-template-columns:1fr auto;gap:24px;align-items:center}
.brandline{display:flex;align-items:center;gap:10px;color:var(--muted);font-weight:600;font-size:13px;letter-spacing:.08em;text-transform:uppercase}
.brandline .logo{width:22px;height:22px;border-radius:6px;background:var(--accent);color:var(--accent-ink);display:inline-flex;align-items:center;justify-content:center;font-size:12px;font-weight:800;letter-spacing:0}
.masthead h1{font-size:clamp(24px,4vw,32px);margin:10px 0 6px;overflow-wrap:anywhere}
.masthead .sub{color:var(--muted);max-width:62ch;overflow-wrap:anywhere}
.metagrid{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}
.meta{background:var(--card);border:1px solid var(--line);border-radius:var(--r-md);box-shadow:var(--shadow);padding:7px 12px;font-size:12.5px;color:var(--muted)}
.meta b{color:var(--ink);font-weight:650}
.globe{width:168px;height:168px;position:relative}
.globe canvas{width:168px;height:168px;display:block}
@media (max-width:720px){.masthead-grid{grid-template-columns:1fr}.globe{display:none}}

nav.top{position:sticky;top:0;z-index:50;background:color-mix(in oklab,var(--bg) 82%,transparent);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-bottom:1px solid var(--line);margin-top:28px}
nav.top .in{max-width:1080px;margin:0 auto;padding:0 24px;display:flex;gap:4px;align-items:center;height:var(--nav-h);overflow-x:auto;scrollbar-width:none}
nav.top .in::-webkit-scrollbar{display:none}
nav.top a{color:var(--muted);font-weight:600;font-size:13.5px;padding:6px 11px;border-radius:999px;white-space:nowrap}
nav.top a:hover{color:var(--ink);background:var(--card-2);text-decoration:none}
nav.top a[aria-current=true]{color:var(--accent-ink);background:var(--accent)}
nav.top .spacer{flex:1}
.iconbtn{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--muted);cursor:pointer;flex:none}
.iconbtn:hover{color:var(--ink);border-color:var(--line-strong);box-shadow:var(--shadow)}
.iconbtn svg{width:16px;height:16px}

.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:20px 0 0}
.stat{border:1px solid var(--line);border-radius:var(--r-lg);background:var(--card);box-shadow:var(--shadow);padding:14px 16px;text-align:left;cursor:pointer;transition:transform .15s ease-out,box-shadow .15s ease-out,opacity .15s ease-out}
.stat:hover{transform:translateY(-1px);box-shadow:var(--shadow-raise)}
.stat .n{display:block;font-size:30px;font-weight:750;letter-spacing:-.02em;font-variant-numeric:tabular-nums;line-height:1.1}
.stat .l{font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:2px}
.stat.s-critical{border-top:3px solid var(--critical)}.stat.s-critical .n{color:var(--critical)}
.stat.s-high{border-top:3px solid var(--high)}.stat.s-high .n{color:var(--high)}
.stat.s-medium{border-top:3px solid var(--medium)}.stat.s-medium .n{color:var(--medium)}
.stat.s-low{border-top:3px solid var(--low)}.stat.s-low .n{color:var(--low)}
.stat.s-info{border-top:3px solid var(--info)}.stat.s-info .n{color:var(--info)}
@media (max-width:720px){.stats{grid-template-columns:repeat(2,1fr)}.stat:last-child{grid-column:1/-1}}
.panel{border:1px solid var(--line);border-radius:var(--r-lg);background:var(--card);box-shadow:var(--shadow);padding:16px 18px;margin-top:14px}
.panel h3{font-size:15px;margin-bottom:8px}
.verdict{display:flex;gap:18px;align-items:center;flex-wrap:wrap}
.gauge{flex:none}
.gauge text{font-family:var(--sans)}
.tops{margin:0;padding:0;list-style:none;counter-reset:top5}
.tops li{counter-increment:top5;display:flex;gap:12px;padding:9px 2px;border-bottom:1px dashed var(--line);align-items:baseline}
.tops li:last-child{border-bottom:none}
.tops li::before{content:counter(top5);flex:none;width:24px;height:24px;border-radius:8px;background:var(--card-2);border:1px solid var(--line);color:var(--muted);font-weight:700;font-size:12px;display:inline-flex;align-items:center;justify-content:center}
.vis{border-radius:var(--r-md);border:1px solid var(--line);padding:10px 14px;margin-top:14px;font-size:13.5px}
.vis.v-degraded{background:var(--warn-wash);border-color:color-mix(in oklab,var(--medium) 35%,var(--line))}
.vis.v-blocked{background:var(--critical-wash);border-color:color-mix(in oklab,var(--critical) 35%,var(--line))}
.vis b{text-transform:capitalize}
.vis ul{margin:6px 0 0;padding-left:18px}

.toolbar{position:sticky;top:var(--nav-h);z-index:40;background:color-mix(in oklab,var(--bg) 88%,transparent);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:1px solid var(--line);border-radius:var(--r-lg);box-shadow:var(--shadow);padding:10px 12px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:14px 0 16px}
.sevbtn{border:1px solid var(--line);background:var(--card);padding:6px 12px;border-radius:999px;font:inherit;font-size:13px;font-weight:650;cursor:pointer;color:var(--ink);display:inline-flex;gap:6px;align-items:center;transition:background .12s ease-out,color .12s ease-out,border-color .12s ease-out}
.sevbtn .n{font-variant-numeric:tabular-nums;font-weight:700}
.sevbtn:hover{border-color:var(--line-strong)}
.sevbtn.active{background:var(--ink);border-color:var(--ink);color:#fff}
.sevbtn.active.f-critical{background:var(--critical);border-color:var(--critical)}
.sevbtn.active.f-high{background:var(--high);border-color:var(--high)}
.sevbtn.active.f-medium{background:var(--medium);border-color:var(--medium)}
.sevbtn.active.f-low{background:var(--low);border-color:var(--low)}
.sevbtn.active.f-info{background:var(--info);border-color:var(--info)}
.toolbar select,.toolbar input[type=search]{font:inherit;font-size:13.5px;padding:7px 10px;border-radius:var(--r-sm);border:1px solid var(--line);background:var(--card);color:var(--ink);min-width:0}
.toolbar input[type=search]{flex:1 1 180px}
.toolbar .cnt{color:var(--muted);font-size:12.5px;white-space:nowrap}
.toolbtn{border:1px solid var(--line);background:var(--card);border-radius:var(--r-sm);font:inherit;font-size:12.5px;font-weight:600;color:var(--muted);padding:6px 10px;cursor:pointer}
.toolbtn:hover{color:var(--ink);border-color:var(--line-strong)}
.finding{border:1px solid var(--line);border-left-width:4px;border-radius:var(--r-lg);background:var(--card);box-shadow:var(--shadow);padding:14px 18px;margin:10px 0;break-inside:avoid}
.finding:hover{box-shadow:var(--shadow-raise)}
.finding.f-critical{border-left-color:var(--critical)}
.finding.f-high{border-left-color:var(--high)}
.finding.f-medium{border-left-color:var(--medium)}
.finding.f-low{border-left-color:var(--low)}
.finding.f-info{border-left-color:var(--info)}
.finding .head{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.finding .title{font-weight:700;font-size:15.5px;letter-spacing:-.01em}
.chip{display:inline-flex;align-items:center;font-size:10.5px;font-weight:800;letter-spacing:.07em;text-transform:uppercase;padding:2px 9px;border-radius:999px;color:#fff;background:var(--info);flex:none}
.chip.ch-critical{background:var(--critical)}.chip.ch-high{background:var(--high)}.chip.ch-medium{background:var(--medium)}.chip.ch-low{background:var(--low)}.chip.ch-info{background:var(--info)}
.fmeta{display:flex;flex-wrap:wrap;gap:4px 14px;color:var(--muted);font-size:12.5px;margin-top:7px}
.fmeta b{color:var(--ink);font-weight:600}
.finding .body{margin-top:8px}
.rec{background:var(--ok-wash);border:1px solid color-mix(in oklab,var(--ok) 30%,var(--line));border-radius:var(--r-md);padding:9px 13px;margin-top:10px;font-size:13.5px}
.rec b{color:var(--ok)}
.finding details{margin-top:10px}
.finding summary,.block summary{cursor:pointer;color:var(--muted);font-size:12.5px;font-weight:650;list-style:none;display:inline-flex;align-items:center;gap:6px;border-radius:var(--r-sm);padding:2px 4px}
.finding summary::-webkit-details-marker,.block summary::-webkit-details-marker{display:none}
.finding summary::before,.block summary::before{content:"";width:0;height:0;border-left:5px solid currentColor;border-top:4px solid transparent;border-bottom:4px solid transparent;transition:transform .12s ease-out}
details[open]>summary::before{transform:rotate(90deg)}
.finding summary:hover,.block summary:hover{color:var(--ink)}
.refs{display:flex;flex-wrap:wrap;gap:4px 10px;margin-top:10px;font-size:12.5px;color:var(--muted);align-items:baseline}
.noresults{border:1px dashed var(--line-strong);border-radius:var(--r-lg);padding:28px;text-align:center;color:var(--muted);background:var(--card)}
.allclean{border:1px solid color-mix(in oklab,var(--ok) 35%,var(--line));background:var(--ok-wash);border-radius:var(--r-lg);padding:22px;text-align:center;color:var(--ink)}
.allclean .big{font-size:20px;font-weight:750;margin-bottom:4px}

.host{border:1px solid var(--line);border-radius:var(--r-lg);background:var(--card);box-shadow:var(--shadow);margin:14px 0;overflow:hidden}
.host>summary{list-style:none;cursor:pointer;display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;padding:14px 18px;background:var(--card-2);border-radius:var(--r-lg)}
.host>summary::-webkit-details-marker{display:none}
.host>summary:hover{background:color-mix(in oklab,var(--card-2) 70%,var(--line))}
.host>summary .hname{font-weight:750;font-size:16.5px;font-family:var(--mono);letter-spacing:-.01em;overflow-wrap:anywhere}
.host>summary .chev{color:var(--muted);transition:transform .12s ease-out;transform-origin:center}
.host[open]>summary .chev{transform:rotate(90deg)}
.hostbody{padding:6px 18px 18px}
.block{border:1px solid var(--line);border-radius:var(--r-md);margin-top:12px;background:var(--card)}
.block>summary{padding:10px 14px;border-radius:var(--r-md);display:flex;gap:8px;align-items:center}
.block[open]>summary{border-bottom:1px solid var(--line)}
.block>summary .btitle{font-weight:700;font-size:13.5px;color:var(--ink)}
.block>summary .bcount{color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}
.block>summary .bopen{margin-left:auto;font-size:12px;color:var(--accent);font-weight:650}
.block .bbody{padding:12px 14px}
.block .bbody>*:last-child{margin-bottom:0}
.kv{display:grid;grid-template-columns:minmax(90px,max-content) 1fr;gap:4px 14px;font-size:13.5px}
.kv dt{color:var(--muted);font-weight:600;white-space:nowrap}
.kv dd{margin:0;overflow-wrap:anywhere}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r-md)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 11px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--card-2);font-weight:650;font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);white-space:nowrap;position:sticky;top:0;z-index:2}
tbody tr:hover td{background:color-mix(in oklab,var(--card-2) 55%,transparent)}
tr:last-child td{border-bottom:none}
td.mono,td .m{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}
td>.tag{white-space:nowrap}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.tag{display:inline-block;font-family:var(--mono);font-size:12px;padding:3px 9px;border-radius:999px;background:var(--card-2);border:1px solid var(--line);max-width:100%;overflow-wrap:anywhere}
.tag.hot{border-color:color-mix(in oklab,var(--high) 45%,var(--line));color:var(--high);font-weight:650}
.pathsrc{font-size:11px;padding:2px 8px;color:var(--muted)}
.copybtn{border:1px solid var(--line);background:var(--card);border-radius:var(--r-sm);font:inherit;font-size:11.5px;font-weight:650;color:var(--muted);padding:3px 9px;cursor:pointer}
.copybtn:hover{color:var(--ink);border-color:var(--line-strong)}
.brow{display:inline-flex;align-items:center;gap:6px}
.dot{width:8px;height:8px;border-radius:50%;flex:none;background:var(--info)}
.dot.d-critical{background:var(--critical)}.dot.d-high{background:var(--high)}.dot.d-medium{background:var(--medium)}.dot.d-low{background:var(--low)}
.conf{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.03em;padding:1px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.conf.c3{color:var(--accent);border-color:color-mix(in oklab,var(--accent) 40%,var(--line))}
.conf.c2{color:var(--ink)}
.conf.c0{font-style:italic}

/* граф */
.imapwrap{position:relative;border:1px solid var(--line);border-radius:var(--r-lg);background:var(--card);box-shadow:var(--shadow);margin-top:14px}
.imapwrap canvas{display:block;width:100%;height:520px;border-radius:var(--r-lg);cursor:grab;user-select:none;-webkit-user-select:none;touch-action:none}
.imapwrap canvas.panning{cursor:grabbing}
.imapctrl{position:absolute;left:10px;top:10px;display:flex;flex-direction:column;gap:6px;z-index:5}
.imapctrl button{width:30px;height:30px;border-radius:8px;border:1px solid var(--line);background:color-mix(in oklab,var(--card) 92%,transparent);color:var(--muted);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;padding:0}
.imapctrl button:hover{color:var(--ink);border-color:var(--line-strong);box-shadow:var(--shadow)}
.imapctrl svg{width:15px;height:15px}
.imap-hint{position:absolute;left:10px;bottom:10px;font-size:11.5px;color:var(--muted);background:color-mix(in oklab,var(--card) 88%,transparent);border:1px solid var(--line);border-radius:999px;padding:2px 10px;pointer-events:none}
.imap-cap{position:absolute;right:10px;top:10px;font-size:11.5px;color:var(--muted);background:color-mix(in oklab,var(--card) 88%,transparent);border:1px solid var(--line);border-radius:999px;padding:2px 10px;pointer-events:none}
.imap-tip{position:absolute;pointer-events:none;display:none;max-width:360px;background:var(--card);border:1px solid var(--line-strong);border-radius:var(--r-md);box-shadow:var(--shadow-raise);padding:9px 12px;font-size:12.5px;z-index:20;color:var(--ink)}
.imap-tip b{font-family:var(--mono);overflow-wrap:anywhere}
.imap-tip .tmeta{color:var(--muted);font-size:11.5px;margin-top:3px}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:10px;font-size:12px;color:var(--muted);align-items:center}
.legend .sw{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:5px;vertical-align:-1px}
.legend .sw.st-confirmed{background:var(--ok)}
.legend .sw.st-probable{background:var(--accent)}
.legend .sw.st-possible{background:var(--medium)}
.legend .sw.st-unverified{background:var(--muted);opacity:.6}
.stchip{display:inline-block;font-size:11px;font-weight:700;padding:1px 9px;border-radius:999px;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.stchip.st-confirmed{color:var(--ok);border-color:color-mix(in oklab,var(--ok) 45%,var(--line))}
.stchip.st-probable{color:var(--accent);border-color:color-mix(in oklab,var(--accent) 45%,var(--line))}
.stchip.st-possible{color:var(--medium);border-color:color-mix(in oklab,var(--medium) 45%,var(--line))}
.stchip.st-unverified{color:var(--muted);border-style:dashed}
.confbar{display:inline-block;width:54px;height:6px;border-radius:999px;background:var(--card-2);vertical-align:middle;position:relative;overflow:hidden;margin-right:7px}
.confbar i{position:absolute;top:0;bottom:0;left:0;border-radius:999px;background:var(--accent)}
tr[data-map]{cursor:pointer}
tr[data-map]:hover td{background:color-mix(in oklab,var(--accent) 8%,transparent)}

.tchips{display:flex;flex-wrap:wrap;gap:6px;margin:2px 0 12px}
.tchip{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);background:var(--card);border-radius:999px;padding:3px 12px 3px 6px;font:inherit;font-size:12.5px;font-weight:600;color:var(--muted);cursor:pointer}
.tchip canvas{display:block}
.tchip b{color:var(--ink);font-weight:700;font-variant-numeric:tabular-nums}
.tchip:hover{border-color:var(--line-strong);color:var(--ink)}
.tchip.on{border-color:var(--accent);color:var(--accent);background:color-mix(in oklab,var(--accent) 8%,var(--card))}
.tchip.on b{color:var(--accent)}

.tag.own{color:var(--accent);border-color:color-mix(in oklab,var(--accent) 45%,var(--line));font-weight:650}
.tag.nb{border-style:dashed;color:var(--muted)}
.asncards{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px}
.asncard{border:1px solid var(--line);border-radius:var(--r-md);padding:12px 14px;background:var(--card)}
.asncard h4{font-size:14px;margin:0 0 4px;font-family:var(--mono);letter-spacing:-.01em;overflow-wrap:anywhere}
.asncard .chips{margin-top:6px}

.modbars{display:flex;flex-direction:column;gap:7px;margin-top:6px}
.modbar{display:grid;grid-template-columns:120px 1fr 44px;gap:12px;align-items:center;border:none;background:none;padding:3px 6px;font:inherit;cursor:pointer;border-radius:var(--r-sm);text-align:left;width:100%}
.modbar:hover{background:var(--card-2)}
.modbar .mname{font-family:var(--mono);font-size:12.5px;color:var(--ink);overflow-wrap:anywhere}
.modbar .mtrack{height:11px;border-radius:999px;background:var(--card-2);position:relative;overflow:hidden;border:1px solid var(--line)}
.modbar .mtrack i{position:absolute;top:0;bottom:0;display:block}
.modbar .mnum{font-variant-numeric:tabular-nums;font-weight:700;font-size:13px;text-align:right;color:var(--ink)}
.riskbar{display:flex;height:10px;border-radius:999px;overflow:hidden;background:var(--card-2);margin-top:12px;border:1px solid var(--line);max-width:420px}
.riskbar i{display:block;height:100%}
.risklegend{display:flex;flex-wrap:wrap;gap:4px 12px;margin-top:8px;font-size:11.5px;color:var(--muted)}
.risklegend b{font-variant-numeric:tabular-nums}

.hok{color:var(--ok);font-weight:800}
.hmiss{color:var(--high);font-weight:800}
.matrix th:not(:first-child){text-align:center}
.matrix td:not(:first-child):not(:last-child){text-align:center;white-space:nowrap}

.fbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:12px 0 10px}
.fbar select,.fbar input[type=search]{font:inherit;font-size:13px;padding:6px 10px;border-radius:var(--r-sm);border:1px solid var(--line);background:var(--card);color:var(--ink);min-width:0}
.fbar input[type=search]{flex:1 1 160px}
.fbar .cnt{color:var(--muted);font-size:12.5px;white-space:nowrap}

.statuscode{display:inline-block;font-variant-numeric:tabular-nums;font-weight:700;font-size:12px;padding:1px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.statuscode.s2{color:var(--ok);border-color:color-mix(in oklab,var(--ok) 40%,var(--line))}
.statuscode.s3{color:var(--low);border-color:color-mix(in oklab,var(--low) 40%,var(--line))}
.statuscode.s4,.statuscode.s5{color:var(--high);border-color:color-mix(in oklab,var(--high) 40%,var(--line))}

.cv-auto{content-visibility:auto;contain-intrinsic-size:auto 480px}

footer{margin-top:52px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px;line-height:1.7}
footer b{color:var(--ink)}

/* печать */
@media print{
  :root{--bg:#fff;--card:#fff;--shadow:none;--shadow-raise:none}
  nav.top,.toolbar .toolbtn,.globe,.skip,.copybtn,.iconbtn,.imapwrap,.imap-tip,.fbar,.imapctrl,.imap-hint,.tchips{display:none !important}
  body{font-size:11px;background:#fff}
  .wrap{max-width:none;padding:0}
  .finding,.panel,.host,.block,.tablewrap{box-shadow:none;break-inside:avoid}
  details{display:block}
  details>*{display:block}
  a{color:inherit}
  th{position:static;background:#f2f2f2 !important;color:#000 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .cv-auto{content-visibility:visible}
}

/* язык: текстовая кнопка вместо иконки */
#lang-toggle{width:auto;min-width:32px;padding:0 9px;font-size:11px;font-weight:800;letter-spacing:.06em}

/* узкие экраны: телефон; палитра и структура прежние, только плотность */
body{-webkit-text-size-adjust:100%;text-size-adjust:100%;overflow-x:hidden}
@media (max-width:720px){
  .wrap{padding:0 14px 56px}
  nav.top .in{padding:0 12px}
  .masthead{padding:28px 0 4px}
  section>header{margin:34px 0 12px}
  .stat{padding:12px}
  .stat .n{font-size:23px}
  .toolbar{padding:8px;gap:6px}
  .finding{padding:12px 13px}
  .finding .title{font-size:15px}
  .host>summary{padding:12px 13px}
  .hostbody{padding:4px 13px 14px}
  .block .bbody{padding:10px 12px}
  th,td{padding:6px 8px}
  table{font-size:12.5px}
  code,.mono{word-break:break-word}
  .panel{padding:13px 14px}
  .modbar{grid-template-columns:minmax(84px,auto) 1fr 40px;gap:8px}
  .kv{grid-template-columns:minmax(76px,max-content) 1fr;gap:3px 10px}
  .asncards{grid-template-columns:1fr}
  .imapwrap canvas{height:380px}
  .riskbar{max-width:none}
  .toolbar input[type=search]{flex:1 1 120px}
  .masthead h1{font-size:22px}
}
@media (max-width:400px){
  h2{font-size:19px}
  .stats{gap:8px}
}
/* сенсорный ввод: крупнее цели нажатия */
@media (pointer:coarse){
  nav.top a{padding:8px 13px}
  .sevbtn{padding:9px 14px}
  .iconbtn{width:38px;height:38px}
  .toolbtn{padding:9px 12px}
  .copybtn{padding:6px 11px}
  .host>summary{padding-top:13px;padding-bottom:13px}
  .finding summary,.block summary{padding:6px 4px}
  .tchip{padding:5px 14px 5px 8px}
}
)mikto_css";