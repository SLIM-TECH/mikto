R"mikto_js(
/* интерактив отчёта, без зависимостей */
(function(){
"use strict";
var doc=document;doc.documentElement.classList.add("js");
var reduce=window.matchMedia&&window.matchMedia("(prefers-reduced-motion: reduce)").matches;

var root=doc.documentElement;
function themeIcon(){var b=doc.getElementById("theme-toggle");if(!b)return;
  var dark=root.getAttribute("data-theme")==="dark";
  b.setAttribute("aria-label",dark?"Switch to light theme":"Switch to dark theme");
  b.innerHTML=dark?'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4m11.4-11.4 1.4-1.4"/></svg>'
                  :'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z"/></svg>';}
try{var saved=localStorage.getItem("mikto-theme");if(saved==="light"||saved==="dark")root.setAttribute("data-theme",saved);}catch(e){}
themeIcon();
var tt=doc.getElementById("theme-toggle");
if(tt)tt.addEventListener("click",function(){
  var dark=root.getAttribute("data-theme")==="dark"||!root.hasAttribute("data-theme")&&window.matchMedia("(prefers-color-scheme: dark)").matches;
  var next=dark?"light":"dark";root.setAttribute("data-theme",next);
  try{localStorage.setItem("mikto-theme",next);}catch(e){}
  themeIcon();drawGlobe(true);drawIntelMap();drawTIcons();
});

var links=[].slice.call(doc.querySelectorAll("nav.top a[href^='#']"));
var secs=links.map(function(a){return doc.getElementById(a.getAttribute("href").slice(1));}).filter(Boolean);
if(!reduce&&"IntersectionObserver" in window&&secs.length){
  var so=new IntersectionObserver(function(es){
    es.forEach(function(en){if(en.isIntersecting){
      links.forEach(function(a){a.setAttribute("aria-current",a.getAttribute("href")==="#"+en.target.id?"true":"false");});
    }});
  },{rootMargin:"-45% 0px -50% 0px"});
  secs.forEach(function(s){so.observe(s);});
}

var sev=new Set();
var cards=[].slice.call(doc.querySelectorAll("#findings .finding"));
var mods=doc.getElementById("f-mod"),hosts=doc.getElementById("f-host"),q=doc.getElementById("f-q");
function sevBtns(){return [].slice.call(doc.querySelectorAll(".sevbtn"));}
function setSev(k,on){
  if(k==="all"){sev.clear();}else if(on){sev.add(k);}else{sev.delete(k);}
  sevBtns().forEach(function(b){
    var f=b.getAttribute("data-f")||"";
    if(f==="all"){var onAll=sev.size===0;b.classList.toggle("active",onAll);b.setAttribute("aria-pressed",onAll);}
    else if(f){var isOn=sev.has(f);b.classList.toggle("active",isOn);b.setAttribute("aria-pressed",isOn);}
  });
  apply();
}
function apply(){
  var n=0,needle=q&&q.value?q.value.toLowerCase():"";
  cards.forEach(function(c){
    var okS=sev.size===0||sev.has(c.getAttribute("data-sev"));
    var okM=!mods||!mods.value||c.getAttribute("data-mod")===mods.value;
    var okH=!hosts||!hosts.value||c.getAttribute("data-host")===hosts.value;
    var okQ=!needle||c.textContent.toLowerCase().indexOf(needle)!==-1;
    var ok=okS&&okM&&okH&&okQ;
    c.style.display=ok?"":"none";if(ok)n++;
  });
  var cnt=doc.getElementById("f-cnt");if(cnt)cnt.textContent=n+" of "+cards.length+" shown";
  var none=doc.getElementById("f-none");if(none)none.style.display=n===0&&cards.length?"":"none";
}
[].slice.call(doc.querySelectorAll(".sevbtn")).forEach(function(b){
  b.addEventListener("click",function(){
    var f=b.getAttribute("data-f");
    if(f==="all")setSev("all");
    else setSev(f,!sev.has(f));
  });
});
if(mods)mods.addEventListener("change",apply);
if(hosts)hosts.addEventListener("change",apply);
if(q)q.addEventListener("input",apply);
[].slice.call(doc.querySelectorAll("[data-goto-sev]")).forEach(function(b){
  b.addEventListener("click",function(){
    setSev(b.getAttribute("data-goto-sev")==="all"?"all":b.getAttribute("data-goto-sev"));
    var f=doc.getElementById("findings");if(f)f.scrollIntoView({behavior:reduce?"auto":"smooth",block:"start"});
  });
});

[].slice.call(doc.querySelectorAll("[data-fold]")).forEach(function(b){
  b.addEventListener("click",function(){
    var scope=b.getAttribute("data-scope");
    var rootEl=scope?doc.getElementById(scope):doc;
    if(!rootEl)return;
    var open=b.getAttribute("data-fold")==="open";
    [].slice.call(rootEl.querySelectorAll("details")).forEach(function(d){
      if(d.hasAttribute("data-keep"))d.open=d.hasAttribute("open")?d.open:open;else d.open=open;
    });
  });
});

[].slice.call(doc.querySelectorAll("[data-copy]")).forEach(function(b){
  b.addEventListener("click",function(){
    var sel=b.getAttribute("data-copy"),txt="";
    if(sel==="."){var items=[].slice.call(doc.querySelectorAll(b.getAttribute("data-copy-items")||""));txt=items.map(function(i){return i.textContent.trim();}).join("\n");}
    else{var el=doc.querySelector(sel);txt=el?el.textContent.trim():"";}
    function done(){b.textContent="Copied ✓";setTimeout(function(){b.textContent=b.getAttribute("data-label")||b.textContent;},1200);}
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(done,function(){fallback();});}else fallback();
    function fallback(){var ta=doc.createElement("textarea");ta.value=txt;doc.body.appendChild(ta);ta.select();try{doc.execCommand("copy");done();}catch(e){}doc.body.removeChild(ta);}
  });
});

var savedState=[];
window.addEventListener("beforeprint",function(){
  savedState=[].slice.call(doc.querySelectorAll("details")).map(function(d){return d.open;});
  [].slice.call(doc.querySelectorAll("details")).forEach(function(d){d.open=true;});
});
window.addEventListener("afterprint",function(){
  [].slice.call(doc.querySelectorAll("details")).forEach(function(d,i){if(savedState.length>d)try{d.open=savedState[i];}catch(e){}});
});

/* глобус в шапке */
var cv=doc.getElementById("globe");
var phi=0,raf=0,hidden=false;
function drawGlobe(force){
  if(!cv)return;
  var ctx=cv.getContext("2d");if(!ctx)return;
  var dpr=Math.min(window.devicePixelRatio||1,2);
  var W=168,H=168;
  if(cv.width!==W*dpr){cv.width=W*dpr;cv.height=H*dpr;}
  ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,W,H);
  var st=getComputedStyle(root);
  var accent=(st.getPropertyValue("--accent")||"#0f766e").trim();
  var line=(st.getPropertyValue("--line-strong")||"#cfc9c0").trim();
  var cx=W/2,cy=H/2,R=64,N=420;
  ctx.strokeStyle=line;ctx.globalAlpha=.7;ctx.lineWidth=1;
  ctx.beginPath();ctx.arc(cx,cy,R,0,Math.PI*2);ctx.stroke();
  ctx.globalAlpha=1;
  var ga=Math.PI*(3-Math.sqrt(5));
  for(var i=0;i<N;i++){
    var y=1-(i/(N-1))*2,rad=Math.sqrt(1-y*y),th=ga*i+phi;
    var x=Math.cos(th)*rad,z=Math.sin(th)*rad;
    if(z<-0.15)continue;               // задняя полусфера тусклее
    var px=cx+x*R,py=cy+y*R;
    var s=1.1+z*0.9;
    ctx.globalAlpha=.28+Math.max(0,z)*.72;
    ctx.fillStyle=accent;
    ctx.beginPath();ctx.arc(px,py,s,0,Math.PI*2);ctx.fill();
  }
  ctx.globalAlpha=1;
}
function loop(){if(!hidden){phi+=0.0028;drawGlobe();}raf=window.requestAnimationFrame(loop);}
if(cv){
  if(reduce){drawGlobe();}
  else{
    drawGlobe();
    raf=window.requestAnimationFrame(loop);
    doc.addEventListener("visibilitychange",function(){hidden=doc.hidden;});
    window.addEventListener("beforeprint",function(){hidden=true;});
    window.addEventListener("afterprint",function(){hidden=false;});
  }
}
/* карта графа: форс-лейаут + пн/зум, лейаут кешируется по размеру */
var intelNodes=[],intelEdges=[],intelCv=doc.getElementById("intel-map"),intelHover=-1;
var intelV={x:0,y:0,k:1};                 // view: screen = world*k + (x,y)
var intelLaid=false,intelW=0,intelH=0,typeFocus=null,intelDrag=null;
function intelVar(name,fallback){
  var st=getComputedStyle(root);var v=(st.getPropertyValue(name)||"").trim();return v||fallback;
}
function buildIntelData(){
  intelNodes=[];intelEdges=[];intelLaid=false;intelHover=-1;
  if(!intelCv)return;
  var trows=[].slice.call(doc.querySelectorAll("#intel-nodes tbody tr[data-node][data-map]"));
  var erows=[].slice.call(doc.querySelectorAll("#intel-edges tbody tr[data-edge][data-map]"));
  var byId={};
  trows.forEach(function(tr){
    var n={id:tr.getAttribute("data-node"),type:tr.getAttribute("data-type"),
      value:tr.getAttribute("data-value")||"",status:tr.getAttribute("data-status")||"unverified",
      deg:parseInt(tr.getAttribute("data-deg")||"0",10),x:0,y:0,cells:tr.cells,label:null,i:0};
    n.r=n.type==="domain"||n.type==="ip"?7+Math.min(6,1+n.deg*0.35):7+Math.min(4,n.deg*0.3);
    n.i=intelNodes.length;intelNodes.push(n);byId[n.id]=n;
  });
  erows.forEach(function(tr){
    var src=byId[tr.getAttribute("data-src")],dst=byId[tr.getAttribute("data-dst")];
    if(!src||!dst)return;
    intelEdges.push({src:src,dst:dst,status:tr.getAttribute("data-status")||""});
  });
}
/* глифы типов чистым canvas */
function typeGlyph(ctx,type,x,y,u,color){
  if(u<=1)return;
  ctx.save();ctx.translate(x,y);
  ctx.strokeStyle=color;ctx.fillStyle=color;
  ctx.lineWidth=Math.max(1,u*0.26);ctx.lineCap="round";ctx.lineJoin="round";
  ctx.beginPath();
  if(type==="domain"){
    ctx.arc(0,0,u,0,Math.PI*2);
    ctx.moveTo(0,-u);ctx.lineTo(0,u);
    ctx.moveTo(u*0.45,0);
    ctx.ellipse(0,0,u*0.45,u,0,0,Math.PI*2);
    ctx.stroke();
  }else if(type==="ip"){
    ctx.moveTo(-u*0.8,-u*0.4);ctx.lineTo(u*0.8,-u*0.4);
    ctx.moveTo(-u*0.8,u*0.4);ctx.lineTo(u*0.8,u*0.4);
    ctx.moveTo(-u*0.4,-u);ctx.lineTo(-u*0.4,u);
    ctx.moveTo(u*0.4,-u);ctx.lineTo(u*0.4,u);
    ctx.stroke();
  }else if(type==="asn"){         // signal: dot + two arcs
    ctx.arc(0,u*0.6,u*0.3,0,Math.PI*2);ctx.fill();
    ctx.beginPath();ctx.arc(0,u*0.6,u*0.65,-Math.PI*0.8,-Math.PI*0.2);ctx.stroke();
    ctx.beginPath();ctx.arc(0,u*0.6,u,-Math.PI*0.75,-Math.PI*0.25);ctx.stroke();
  }else if(type==="service"){     // gear: hub + spokes
    ctx.arc(0,0,u*0.42,0,Math.PI*2);
    for(var a=0;a<6;a++){var ang=a*Math.PI/3+Math.PI/6;
      ctx.moveTo(Math.cos(ang)*u*0.55,Math.sin(ang)*u*0.55);
      ctx.lineTo(Math.cos(ang)*u,Math.sin(ang)*u);}
    ctx.stroke();
  }else if(type==="technology"){
    ctx.rect(-u*0.62,-u*0.62,u*1.24,u*1.24);
    ctx.moveTo(0,-u*0.62);ctx.lineTo(0,-u);
    ctx.moveTo(0,u*0.62);ctx.lineTo(0,u);
    ctx.moveTo(-u*0.62,0);ctx.lineTo(-u,0);
    ctx.moveTo(u*0.62,0);ctx.lineTo(u,0);
    ctx.stroke();
  }else if(type==="endpoint"){
    ctx.rect(-u*0.72,-u*0.95,u*1.44,u*1.9);
    ctx.moveTo(-u*0.42,-u*0.42);ctx.lineTo(u*0.42,-u*0.42);
    ctx.moveTo(-u*0.42,0);ctx.lineTo(u*0.42,0);
    ctx.moveTo(-u*0.42,u*0.42);ctx.lineTo(u*0.16,u*0.42);
    ctx.stroke();
  }else if(type==="email"){
    ctx.font="700 "+(u*2.05)+"px "+intelVar("--sans","sans-serif");
    ctx.textAlign="center";ctx.textBaseline="middle";
    ctx.fillText("@",0,u*0.1);
  }else if(type==="certificate"){
    ctx.arc(0,-u*0.3,u*0.42,Math.PI,0);
    ctx.stroke();
    ctx.beginPath();ctx.rect(-u*0.72,-u*0.3,u*1.44,u*1.2);ctx.stroke();
    ctx.beginPath();ctx.arc(0,u*0.3,u*0.17,0,Math.PI*2);ctx.fill();
  }else if(type==="mail_exchanger"){
    ctx.rect(-u,-u*0.62,u*2,u*1.24);
    ctx.moveTo(-u,-u*0.62);ctx.lineTo(0,u*0.16);ctx.lineTo(u,-u*0.62);
    ctx.stroke();
  }else if(type==="nameserver"){
    ctx.rect(-u*0.82,-u*0.95,u*1.64,u*0.85);
    ctx.rect(-u*0.82,u*0.1,u*1.64,u*0.85);
    ctx.stroke();
    ctx.beginPath();ctx.arc(u*0.52,-u*0.52,u*0.13,0,Math.PI*2);ctx.fill();
    ctx.beginPath();ctx.arc(u*0.52,u*0.52,u*0.13,0,Math.PI*2);ctx.fill();
  }else if(type==="cve"){
    ctx.ellipse(0,0,u*0.62,u*0.92,0,0,Math.PI*2);
    ctx.moveTo(-u*0.62,-u*0.3);ctx.lineTo(-u*1.02,-u*0.5);
    ctx.moveTo(-u*0.62,u*0.3);ctx.lineTo(-u*1.02,u*0.5);
    ctx.moveTo(u*0.62,-u*0.3);ctx.lineTo(u*1.02,-u*0.5);
    ctx.moveTo(u*0.62,u*0.3);ctx.lineTo(u*1.02,u*0.5);
    ctx.moveTo(0,-u*0.92);ctx.lineTo(0,-u*1.3);
    ctx.moveTo(-u*0.3,-u*0.75);ctx.lineTo(-u*0.5,-u*1.15);
    ctx.moveTo(u*0.3,-u*0.75);ctx.lineTo(u*0.5,-u*1.15);
    ctx.stroke();
  }else{                          // provider: cloud
    ctx.moveTo(-u,u*0.55);
    ctx.arc(-u*0.5,u*0.55,u*0.5,Math.PI,Math.PI*1.5);
    ctx.arc(-u*0.02,u*0.02,u*0.58,Math.PI*1.15,Math.PI*1.9);
    ctx.arc(u*0.52,u*0.42,u*0.46,Math.PI*1.5,Math.PI*0.4);
    ctx.lineTo(u,u*0.55);
    ctx.lineTo(-u,u*0.55);
    ctx.stroke();
  }
  ctx.restore();
}
function drawTIcons(){
  [].slice.call(doc.querySelectorAll("canvas.ticon")).forEach(function(c2){
    var t=c2.getAttribute("data-type")||"";
    var x=c2.getContext("2d");if(!x)return;
    var dpr=Math.min(window.devicePixelRatio||1,2);
    c2.width=20*dpr;c2.height=20*dpr;
    x.setTransform(dpr,0,0,dpr,0,0);x.clearRect(0,0,20,20);
    typeGlyph(x,t,10,10,6.5,intelVar("--ink","#1c1917"));
  });
}
function rectHit(r,rects,pad){
  for(var i=0;i<rects.length;i++){var qq=rects[i];
    if(r.x1-pad<qq.x2&&r.x2+pad>qq.x1&&r.y1-pad<qq.y2&&r.y2+pad>qq.y1)return true;}
  return false;
}
function layoutIntel(W,H){
  if(intelLaid&&intelW===W&&intelH===H)return;
  intelW=W;intelH=H;intelLaid=true;
  var n=intelNodes.length;if(!n)return;
  /* сидированный prng */
  var seed=42;function rnd(){seed=(seed*1103515245+12345)&0x7fffffff;return seed/0x7fffffff;}
  /* старт: кольцо на каждый тип */
  var order=["domain","ip","asn","service","technology","endpoint","certificate","email","mail_exchanger","nameserver","cve","provider"];
  var groups={},rings=[];
  intelNodes.forEach(function(nn){(groups[nn.type]=groups[nn.type]||[]).push(nn);});
  order.forEach(function(t){if(groups[t])rings.push(groups[t]);});
  Object.keys(groups).forEach(function(t){if(order.indexOf(t)<0)rings.push(groups[t]);});
  var cx=W/2,cy=H/2;
  var r0=Math.min(W,H)*0.12,rMax=Math.max(r0+30,Math.min(W,H)/2-44);
  var step=rings.length>1?(rMax-r0)/(rings.length-1):0;
  rings.forEach(function(ring,i){
    var R=r0+i*step,rot=i*0.45;
    ring.forEach(function(nn,j){
      var a=rot+(j/ring.length)*Math.PI*2;
      nn.x=cx+Math.cos(a)*R+(rnd()-0.5)*8;
      nn.y=cy+Math.sin(a)*R+(rnd()-0.5)*8;
    });
  });
  var cent={};
  Object.keys(groups).forEach(function(t){
    var sx=0,sy=0;groups[t].forEach(function(nn){sx+=nn.x;sy+=nn.y;});
    cent[t]={x:sx/groups[t].length,y:sy/groups[t].length};
  });
  /* силы: отталкивание + пружины рёбер + гравитация */
  var k=Math.sqrt(W*H/Math.max(1,n))*0.85;
  var iters=reduce?90:260,disp=[];
  for(var i=0;i<n;i++)disp.push({x:0,y:0});
  for(var it=0;it<iters;it++){
    var temp=Math.max(1.5,(1-it/iters)*Math.min(W,H)*0.11);
    for(var q0=0;q0<n;q0++){disp[q0].x=0;disp[q0].y=0;}
    for(var a1=0;a1<n;a1++)for(var b1=a1+1;b1<n;b1++){
      var na=intelNodes[a1],nb=intelNodes[b1];
      var dx=na.x-nb.x,dy=na.y-nb.y,d2=dx*dx+dy*dy;
      if(d2<0.01){dx=rnd()-0.5;dy=rnd()-0.5;d2=0.25;}
      var d=Math.sqrt(d2),f=Math.min(k*k/d2,k*1.6)/d;
      var fx=dx*f,fy=dy*f;
      disp[a1].x+=fx;disp[a1].y+=fy;disp[b1].x-=fx;disp[b1].y-=fy;
    }
    intelEdges.forEach(function(e){
      var dx=e.dst.x-e.src.x,dy=e.dst.y-e.src.y;
      var d=Math.sqrt(dx*dx+dy*dy)||0.5,f=d*d/k*0.055/d;
      disp[e.src.i].x+=dx*f;disp[e.src.i].y+=dy*f;
      disp[e.dst.i].x-=dx*f;disp[e.dst.i].y-=dy*f;
    });
    for(var c1=0;c1<n;c1++){var nn=intelNodes[c1];
      disp[c1].x+=(cx-nn.x)*0.012;disp[c1].y+=(cy-nn.y)*0.012;
      var ct=cent[nn.type];if(ct){disp[c1].x+=(ct.x-nn.x)*0.03;disp[c1].y+=(ct.y-nn.y)*0.03;}
    }
    for(var m1=0;m1<n;m1++){var nn=intelNodes[m1];
      var dx=disp[m1].x,dy=disp[m1].y,d=Math.sqrt(dx*dx+dy*dy)||1;
      var lim=Math.min(d,temp);
      nn.x=Math.max(30,Math.min(W-30,nn.x+dx/d*lim));
      nn.y=Math.max(30,Math.min(H-30,nn.y+dy/d*lim));
    }
  }
  /* разведение дисков */
  for(var p=0;p<90;p++){
    var moved=false;
    for(var a2=0;a2<n;a2++)for(var b2=a2+1;b2<n;b2++){
      var na=intelNodes[a2],nb=intelNodes[b2];
      var dx=nb.x-na.x,dy=nb.y-na.y,min=na.r+nb.r+6,d2=dx*dx+dy*dy;
      if(d2>0&&d2<min*min){
        var d=Math.sqrt(d2),push=(min-d)*0.5,ux=dx/d,uy=dy/d;
        na.x-=ux*push;na.y-=uy*push;nb.x+=ux*push;nb.y+=uy*push;moved=true;
      }else if(d2===0){na.x-=1;nb.x+=1;moved=true;}
    }
    for(var q2=0;q2<n;q2++){var nn=intelNodes[q2];
      nn.x=Math.max(26,Math.min(W-26,nn.x));nn.y=Math.max(26,Math.min(H-26,nn.y));}
    if(!moved)break;
  }
  /* вписываем граф в канвас */
  var bx1=1e9,by1=1e9,bx2=-1e9,by2=-1e9;
  intelNodes.forEach(function(nn){
    bx1=Math.min(bx1,nn.x-nn.r);by1=Math.min(by1,nn.y-nn.r);
    bx2=Math.max(bx2,nn.x+nn.r);by2=Math.max(by2,nn.y+nn.r);
  });
  var sc=Math.min((W-64)/Math.max(1,bx2-bx1),(H-64)/Math.max(1,by2-by1),1.3);
  intelNodes.forEach(function(nn){
    nn.x=(nn.x-(bx1+bx2)/2)*sc+W/2;nn.y=(nn.y-(by1+by2)/2)*sc+H/2;
  });
  /* лейблы: хабы первыми, без наложений */
  var blockers=intelNodes.map(function(nn){
    return {x1:nn.x-nn.r-2,y1:nn.y-nn.r-2,x2:nn.x+nn.r+2,y2:nn.y+nn.r+2};
  });
  var placed=[];
  intelNodes.forEach(function(nn){nn.label=null;});
  var cand=intelNodes.slice().sort(function(a,b){return b.deg-a.deg;});
  var maxLab=n<=30?n:26;
  for(var li=0;li<Math.min(maxLab,cand.length);li++){
    var nn=cand[li];
    if(nn.deg<2&&n>30)break;
    var txt=nn.value.length>26?nn.value.slice(0,25)+"…":nn.value;
    var w=txt.length*5.9+4,h=13;
    var bl=blockers.slice();bl.splice(nn.i,1);
    var spots=[nn.y-nn.r-9,nn.y+nn.r+10,nn.y-nn.r-22,nn.y+nn.r+23];
    for(var si=0;si<spots.length;si++){
      var r={x1:nn.x-w/2,y1:spots[si]-h/2,x2:nn.x+w/2,y2:spots[si]+h/2};
      if(!rectHit(r,placed,2)&&!rectHit(r,bl,0)){
        nn.label={t:txt,x:nn.x,y:spots[si]};placed.push(r);break;
      }
    }
  }
}
function drawIntelMap(){
  if(!intelCv)return;
  var ctx=intelCv.getContext("2d");if(!ctx)return;
  if(!intelNodes.length)buildIntelData();
  var dpr=Math.min(window.devicePixelRatio||1,2);
  var W=intelCv.parentNode.clientWidth||900,H=520;
  if(intelCv.width!==Math.round(W*dpr)||intelCv.height!==Math.round(H*dpr)){
    intelCv.width=Math.round(W*dpr);intelCv.height=Math.round(H*dpr);
    intelCv.style.height=H+"px";
  }
  ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,W,H);
  if(!intelNodes.length)return;
  layoutIntel(W,H);
  var accent=intelVar("--accent","#0f766e"),lineC=intelVar("--line-strong","#cfc9c0"),
      okC=intelVar("--ok","#15803d"),medC=intelVar("--medium","#a16207"),
      mutC=intelVar("--muted","#6d6862"),inkC=intelVar("--ink","#1c1917"),
      cardC=intelVar("--card","#ffffff"),ink2C=intelVar("--accent-ink","#ffffff");
  var statusColor={confirmed:okC,probable:accent,possible:medC,unverified:mutC};
  var hoverId=intelHover>=0?intelNodes[intelHover].id:null,hoverSet=null;
  if(hoverId){
    hoverSet={};hoverSet[hoverId]=1;
    intelEdges.forEach(function(e){
      if(e.src.id===hoverId)hoverSet[e.dst.id]=1;
      if(e.dst.id===hoverId)hoverSet[e.src.id]=1;
    });
  }
  ctx.save();
  ctx.translate(intelV.x,intelV.y);ctx.scale(intelV.k,intelV.k);
  intelEdges.forEach(function(e){
    var hot=intelHover>=0&&(e.src.i===intelHover||e.dst.i===intelHover);
    var dim=intelHover>=0&&!hot;
    ctx.lineWidth=hot?2/intelV.k:1/intelV.k;
    ctx.strokeStyle=hot?accent:(e.status==="confirmed"?accent:lineC);
    ctx.globalAlpha=dim?0.06:(hot?0.9:(e.status==="confirmed"?0.42:0.3));
    if(e.status==="unverified")ctx.setLineDash([4/intelV.k,3/intelV.k]);else ctx.setLineDash([]);
    ctx.beginPath();ctx.moveTo(e.src.x,e.src.y);ctx.lineTo(e.dst.x,e.dst.y);ctx.stroke();
  });
  ctx.setLineDash([]);
  intelNodes.forEach(function(nn){
    var dim=(intelHover>=0&&!hoverSet[nn.id])||(typeFocus&&nn.type!==typeFocus);
    ctx.globalAlpha=dim?0.13:1;
    ctx.beginPath();ctx.arc(nn.x,nn.y,nn.r,0,Math.PI*2);
    ctx.fillStyle=statusColor[nn.status]||mutC;ctx.fill();
    ctx.lineWidth=(nn.i===intelHover?2.5:1.5)/intelV.k;
    ctx.strokeStyle=nn.i===intelHover?inkC:cardC;ctx.stroke();
    typeGlyph(ctx,nn.type,nn.x,nn.y,nn.r*0.5,ink2C);
  });
  ctx.font="10.5px "+intelVar("--sans","sans-serif");
  ctx.textAlign="center";ctx.textBaseline="middle";
  intelNodes.forEach(function(nn){
    if(!nn.label)return;
    var dim=(intelHover>=0&&!hoverSet[nn.id])||(typeFocus&&nn.type!==typeFocus);
    ctx.globalAlpha=dim?0.08:0.9;
    ctx.fillStyle=inkC;
    ctx.fillText(nn.label.t,nn.label.x,nn.label.y);
  });
  ctx.globalAlpha=1;
  ctx.restore();
}
function filterRelationsFor(nn){
  if(!nn)return;
  var q=doc.getElementById("e-q");
  if(!q)return;
  q.value=nn.value;q.dispatchEvent(new Event("input"));
  var blk=doc.getElementById("intel-edges-block");
  if(blk)blk.open=true;
}
if(intelCv){
  buildIntelData();
  drawIntelMap();
  drawTIcons();
  function toWorld(mx,my){return {x:(mx-intelV.x)/intelV.k,y:(my-intelV.y)/intelV.k};}
  function hitNode(mx,my){
    var p=toWorld(mx,my),best=-1,bd=1e9;
    intelNodes.forEach(function(nn,i){
      var d=(nn.x-p.x)*(nn.x-p.x)+(nn.y-p.y)*(nn.y-p.y);
      if(d<bd){bd=d;best=i;}
    });
    if(best>=0&&bd>Math.pow(intelNodes[best].r+6,2))best=-1;
    return best;
  }
  function intelZoom(f,mx,my){
    var k2=Math.min(3.2,Math.max(0.4,intelV.k*f));
    if(mx===undefined){mx=intelCv.clientWidth/2;my=intelCv.clientHeight/2;}
    intelV.x=mx-(mx-intelV.x)*(k2/intelV.k);
    intelV.y=my-(my-intelV.y)*(k2/intelV.k);
    intelV.k=k2;drawIntelMap();
  }
  function intelReset(){intelV={x:0,y:0,k:1};drawIntelMap();}
  if(!reduce){
    var intelResizeTimer=0;
    window.addEventListener("resize",function(){
      clearTimeout(intelResizeTimer);intelResizeTimer=setTimeout(function(){intelLaid=false;drawIntelMap();},140);
    });
    intelCv.addEventListener("wheel",function(ev){
      ev.preventDefault();
      var rect=intelCv.getBoundingClientRect();
      intelZoom(Math.exp(-ev.deltaY*0.0013),ev.clientX-rect.left,ev.clientY-rect.top);
    },{passive:false});
    intelCv.addEventListener("mousedown",function(ev){
      intelDrag={mx:ev.clientX,my:ev.clientY,vx:intelV.x,vy:intelV.y,moved:false};
      intelCv.classList.add("panning");
      ev.preventDefault();
    });
    window.addEventListener("mousemove",function(ev){
      if(!intelDrag)return;
      var dx=ev.clientX-intelDrag.mx,dy=ev.clientY-intelDrag.my;
      if(Math.abs(dx)+Math.abs(dy)>4)intelDrag.moved=true;
      intelV.x=intelDrag.vx+dx;intelV.y=intelDrag.vy+dy;drawIntelMap();
    });
    window.addEventListener("mouseup",function(ev){
      if(!intelDrag)return;
      var wasMoved=intelDrag.moved;intelDrag=null;
      intelCv.classList.remove("panning");
      if(!wasMoved){
        var rect=intelCv.getBoundingClientRect();
        var best=hitNode(ev.clientX-rect.left,ev.clientY-rect.top);
        if(best>=0)filterRelationsFor(intelNodes[best]);
      }
    });
    intelCv.addEventListener("dblclick",function(){intelReset();});
    intelCv.addEventListener("mousemove",function(ev){
      if(intelDrag)return;
      var rect=intelCv.getBoundingClientRect();
      var mx=ev.clientX-rect.left,my=ev.clientY-rect.top;
      var best=hitNode(mx,my);
      if(best!==intelHover){intelHover=best;drawIntelMap();}
      var tip=doc.getElementById("imap-tip");
      if(tip){
        if(best<0){tip.style.display="none";}
        else{
          var nn=intelNodes[best],c=nn.cells;
          tip.innerHTML="<b>"+nn.value.replace(/&/g,"&amp;").replace(/</g,"&lt;")+"</b>"+
            '<div class="tmeta">'+c[1].textContent+" · "+c[2].textContent+
            " · "+(reportLang==="ru"?"уверенность ":"confidence ")+c[3].textContent.replace(/\s+/g," ").trim()+
            (nn.deg?" · "+nn.deg+(reportLang==="ru"?" связ.":" relation"+(nn.deg===1?"":"s")):"")+"</div>";
          tip.style.display="block";
          var tx=mx+14,ty=my+12;
          if(tx+tip.offsetWidth>rect.width-8)tx=mx-tip.offsetWidth-10;
          if(ty+tip.offsetHeight>rect.height-8)ty=my-tip.offsetHeight-10;
          tip.style.left=tx+"px";tip.style.top=ty+"px";
        }
      }
    });
    intelCv.addEventListener("mouseleave",function(){
      intelHover=-1;drawIntelMap();
      var tip=doc.getElementById("imap-tip");if(tip)tip.style.display="none";
    });
    /* тач: пан одним пальцем */
    intelCv.addEventListener("touchstart",function(ev){
      if(ev.touches.length!==1)return;
      var t=ev.touches[0];
      intelDrag={mx:t.clientX,my:t.clientY,vx:intelV.x,vy:intelV.y,moved:false};
    },{passive:true});
    intelCv.addEventListener("touchmove",function(ev){
      if(!intelDrag||ev.touches.length!==1)return;
      ev.preventDefault();
      var t=ev.touches[0];
      var dx=t.clientX-intelDrag.mx,dy=t.clientY-intelDrag.my;
      if(Math.abs(dx)+Math.abs(dy)>4)intelDrag.moved=true;
      intelV.x=intelDrag.vx+dx;intelV.y=intelDrag.vy+dy;drawIntelMap();
    },{passive:false});
    intelCv.addEventListener("touchend",function(ev){
      if(!intelDrag)return;
      var wasMoved=intelDrag.moved;intelDrag=null;
      intelCv.classList.remove("panning");
      if(!wasMoved&&ev.changedTouches.length){
        var rect=intelCv.getBoundingClientRect();
        var t=ev.changedTouches[0];
        var best=hitNode(t.clientX-rect.left,t.clientY-rect.top);
        if(best>=0)filterRelationsFor(intelNodes[best]);
      }
    });
  }
  [].slice.call(doc.querySelectorAll("[data-imap]")).forEach(function(b){
    b.addEventListener("click",function(){
      var a=b.getAttribute("data-imap");
      if(a==="in")intelZoom(1.35);
      else if(a==="out")intelZoom(1/1.35);
      else intelReset();
    });
  });
  [].slice.call(doc.querySelectorAll(".tchip")).forEach(function(ch){
    ch.addEventListener("click",function(){
      var t=ch.getAttribute("data-type")||"";
      typeFocus=typeFocus===t?null:t;
      [].slice.call(doc.querySelectorAll(".tchip")).forEach(function(c2){
        var on=c2.getAttribute("data-type")===typeFocus;
        c2.classList.toggle("on",on);c2.setAttribute("aria-pressed",on?"true":"false");
      });
      drawIntelMap();
    });
  });
}
/* entity row -> filter the relations table */
[].slice.call(doc.querySelectorAll("#intel-nodes tbody tr[data-node]")).forEach(function(tr){
  tr.addEventListener("click",function(){
    filterRelationsFor({value:tr.getAttribute("data-value")||""});
    var cnt=doc.getElementById("e-cnt");
    if(cnt)cnt.scrollIntoView({behavior:reduce?"auto":"smooth",block:"nearest"});
  });
});
drawTIcons();
function bindIntelFilter(tbodyId,ctlIds,cntId,noneId){
  var rows=[].slice.call(doc.querySelectorAll("#"+tbodyId+" tbody tr"));
  if(!rows.length)return;
  var ctls=ctlIds.map(function(id){return doc.getElementById(id);});
  var cnt=doc.getElementById(cntId),none=doc.getElementById(noneId);
  function one(tr){
    for(var i=0;i<ctls.length;i++){
      var c=ctls[i];if(!c||!c.value)continue;
      var key=c.getAttribute("data-k");
      if(key==="text"){
        if(tr.textContent.toLowerCase().indexOf(c.value.toLowerCase())===-1)return false;
      }else{
        if(tr.getAttribute("data-"+key)!==c.value)return false;
      }
    }
    return true;
  }
  function applyF(){
    var n=0;rows.forEach(function(tr){var ok=one(tr);tr.style.display=ok?"":"none";if(ok)n++;});
    if(cnt)cnt.textContent=n+" of "+rows.length+" shown";
    if(none)none.style.display=(n===0&&rows.length)?"":"none";
  }
  ctls.forEach(function(c){if(c)c.addEventListener(c.tagName==="SELECT"?"change":"input",applyF);});
  applyF();
}
bindIntelFilter("intel-nodes",["n-type","n-status","n-q"],"n-cnt","n-none");
bindIntelFilter("intel-edges",["e-rel","e-q"],"e-cnt","e-none");

/* бары модулей -> фильтр находок */
[].slice.call(doc.querySelectorAll(".modbar[data-mod]")).forEach(function(b){
  b.addEventListener("click",function(){
    var sel=doc.getElementById("f-mod");if(!sel)return;
    sel.value=b.getAttribute("data-mod");
    sel.dispatchEvent(new Event("change"));
    var f=doc.getElementById("findings");
    if(f)f.scrollIntoView({behavior:reduce?"auto":"smooth",block:"start"});
  });
});

apply();

/* язык отчёта: en/ru, переводим только интерфейс, данные не трогаем.
   словарь: точные совпадения + пара паттернов для чисел */
var reportLang="en";
var origNodes=null;
var I18N={
"mikto audit report":"отчёт аудита mikto","Skip to content":"К содержимому",
"Overview":"Обзор","Findings":"Находки","Hosts":"Хосты","Infrastructure":"Инфраструктура",
"Web":"Веб","Correlations":"Корреляции","Traffic":"Трафик","Scan info":"Сведения о скане",
"executive summary":"сводка для руководства","sorted by severity":"сортировка по серьёзности",
"correlated intelligence graph — every node carries its status and provenance":
  "коррелированный граф разведки — у каждой вершины статус и источник",
"Critical":"Критический","High":"Высокий","Medium":"Средний","Low":"Низкий","Info":"Инфо",
"confirmed":"подтверждено","probable":"вероятно","possible":"возможно","unverified":"не проверено",
"module: all":"модуль: все","host: all":"хост: все","type: all":"тип: все",
"status: all":"статус: все","relation: all":"связь: все",
"All":"Все","Expand all":"Развернуть всё","Collapse all":"Свернуть всё",
"copy all":"копировать всё","toggle":"разворот",
"Mode":"Режим","Safe mode":"Безопасный режим","mode":"режим","Started":"Начат","Finished":"Завершён",
"enabled — destructive checks skipped":"включена — деструктивные проверки пропущены","disabled":"выключена",
"Duration":"Длительность","Scan visibility":"Видимость скана",
"Scan visibility: full.":"Видимость скана: полная.",
"started":"старт","duration":"длительность","modules":"модули","IPs":"IP",
"entities":"сущности","events":"события",
"Priority actions":"Приоритетные действия","Findings by module":"Находки по модулям",
"Coverage":"Покрытие","Server IPs":"Серверные IP","Networks & providers":"Сети и провайдеры",
"Same-network proximity":"Соседство в одной сети","Co-hosted domains":"Домены на том же IP",
"Shared DNS infrastructure":"Общая DNS-инфраструктура","Slowest round-trips":"Самые медленные запросы",
"Targets":"Цели","Modules run":"Запущенные модули","External providers":"Внешние источники",
"Settings":"Настройки","Security headers matrix":"Матрица заголовков безопасности",
"Neighbors on same IP":"Соседи на том же IP","Reputation & infrastructure":"Репутация и инфраструктура",
"DNS records":"DNS-записи","Emails":"E-mail'ы","Entities":"Сущности","Ports":"Порты",
"TLS certificate":"TLS-сертификат","Technologies":"Технологии","Web paths":"Веб-пути",
"Subdomains":"Субдомены","Relations":"Связи",
"OS guess":"ОС (догадка)","open ports":"открытых портов","Wildcard DNS":"Wildcard DNS",
"duplicate findings suppressed":"дубликаты подавлены","external provider requests":"запросов к внешним источникам",
"nameservers":"неймсерверы","mail exchangers":"mail-серверы","networks / ASNs":"сети / ASN",
"shared subnets":"общие подсети","server IPs":"серверных IP",
"Accounting:":"Учёт:",
"Bar length = share of the noisiest module; segments are severities. Click a row to filter the findings list.":
  "Длина полосы = доля самого шумного модуля; сегменты — серьёзности. Клик по строке фильтрует список находок.",
"Every address the target's DNS answers pointed to. Solid chips are in-scope names; dashed chips are co-hosted neighbours from passive reverse-IP sources.":
  "Все адреса, куда указывали DNS-ответы цели. Сплошные плашки — имена из scope; пунктирные — соседи по IP из пассивных reverse-IP источников.",
"Everything below is rendered in full further down — nothing is sampled or truncated.":
  "Всё собранное отрисовано целиком дальше по отчёту — ничего не сэмплировано и не обрезано.",
"No co-hosted domains were reported for these IPs.":"Для этих IP ко-хостинг домены не найдены.",
"No two server IPs share a /24 or /64 segment — no same-segment neighbours were observed for these addresses.":
  "Ни одна пара серверных IP не делит /24 или /64 сегмент — соседей по сети для этих адресов нет.",
"Per-source request accounting and circuit-breaker state at scan end — a degraded provider means the affected sections may be incomplete.":
  "Учёт запросов по каждому источнику и состояние предохранителя на конец скана — деградация источника значит, что затронутые разделы могут быть неполными.",
"Who owns the address space the targets sit in (ASN from the network-ownership lookup — probable, third-party data).":
  "Кому принадлежит адресное пространство цели (ASN из lookup'а владельца сети — вероятные сторонние данные).",
"Server IPs sharing one segment (IPv4: same /24, IPv6: same /64) — likely the same provider block or hosting cage; they typically share provider-level fate.":
  "Серверные IP в одном сегменте (IPv4: тот же /24, IPv6: тот же /64) — скорее всего один блок провайдера или стойка; обычно делят судьбу на уровне провайдера.",
"Other names served from the same IP as the target (passive reverse-IP sources — possible, not confirmed). On shared hosting a compromise of any neighbour can spill over: same kernel, same network, sometimes the same panel.":
  "Другие имена на том же IP, что и цель (пассивные reverse-IP источники — возможно, не подтверждено). На shared-хостинге компрометация соседа может перелиться и на вас: то же ядро, та же сеть, иногда та же панель.",
"Nameservers and mail exchangers serving more than one in-scope name hint at shared or provider-hosted DNS/mail infrastructure.":
  "Неймсерверы и mail-серверы, обслуживающие несколько имён из scope, намекают на общую или провайдерскую DNS/почтовую инфраструктуру.",
"No data. The scan could not reach the target — check the console output and the Traffic section.":
  "Нет данных. Скан не смог достучаться до цели — смотрите вывод консоли и раздел Трафик.",
"No findings match the current filters. Clear a filter or extend the search text.":
  "Под фильтры ничего не подошло. Сбросьте фильтр или расширьте текст поиска.",
"No host data was collected.":"Данные по хостам не собраны.",
"No infrastructure data was collected — the scan produced no DNS answers and no resolved server IPs.":
  "Данные инфраструктуры не собраны — скан не получил DNS-ответов и разрешённых серверных IP.",
"No web responses recorded.":"Веб-ответы не записаны.",
"No intelligence graph for this scan — the scan produced no correlatable entities.":
  "Графа разведки для этого скана нет — скан не дал коррелируемых сущностей.",
"No entities match the filters.":"Под фильтры сущностей не нашлось.",
"No relations match the filters.":"Под фильтры связей не нашлось.",
"No WAF, anti-bot challenge or rate limiter interfered with the scan — results reflect the complete view mikto could obtain.":
  "Ни WAF, ни анти-бот, ни rate limiter не мешали скану — результат отражает полную картину, которую mikto смог получить.",
"A blocker stood between mikto and the target. mikto did NOT try to evade it; results below may be incomplete for these hosts.":
  "Между mikto и целью стоял блокер. mikto НЕ пытался его обходить; результаты ниже могут быть неполными для этих хостов.",
"· hover a node for provenance · click an entity row below to filter its relations":
  "· наведите курсор на вершину для провенанса · клик по строке сущности фильтрует её связи",
"Module":"Модуль","Kind":"Тип","Target":"Цель","Request":"Запрос","Response":"Ответ",
"Status":"Статус","Bytes":"Байт","ms":"мс","From":"Из","To":"В","Title":"Название",
"Location":"Где","Evidence":"Доказательство","Server":"Сервер","Server IP":"IP сервера",
"Network":"Сеть","Subnet":"Подсеть","Tags":"Теги","Provider":"Провайдер","Requests":"Запросы",
"OK":"ОК","Failed":"Ошибки","Blocked":"Блокировок","Breaker trips":"Срабатывания защиты",
"End state":"Итоговое состояние","Entity":"Сущность","Type":"Тип","Relation":"Связь",
"Confidence":"Уверенность","Sources":"Источники","Sources (provenance)":"Источники (провенанс)",
"Points to":"Указывают","Content-Type":"Content-Type","Segment":"Сегмент",
"Names on the segment":"Имена в сегменте","Count":"Кол-во","Serves":"Обслуживает","Shared":"Общих",
"Port":"Порт","Service":"Сервис","Probe":"Проба","Banner":"Баннер","Version":"Версия",
"Path":"Путь","Found via":"Найдено через","Registrar":"Регистратор","Created":"Создан",
"Expires":"Истекает","Updated":"Обновлён","Value":"Значение","Name":"Имя","Address":"Адрес",
"authorized":"авторизованных",
"evidence":"улики","Print":"Печать",
"Product / version":"Продукт / версия","OS clue":"подсказка об ОС",
"Extra versions":"другие версии","Detected via":"обнаружено через","Size":"размер",
"Score":"счёт","Header":"заголовок",
"Web responses":"Веб-ответы","every response, every header":"каждый ответ, каждый заголовок",
"what mikto sent, what came back — complete log":"что mikto отправил и что вернулось — полный журнал",
"configuration and module timings":"конфигурация и тайминги модулей",
"server IPs, ASN / network ownership, same-segment neighbours and shared DNS — derived from DNS answers, the network-ownership lookup and passive reverse-IP sources":
  "серверные IP, ASN / владелец сети, соседи по сегменту и общая DNS — из DNS-ответов, lookup'а владельца сети и пассивных reverse-IP источников",
"scroll = zoom · drag = pan · double-click = reset":
  "колесо = зум · перетаскивание = панорама · двойной клик = сброс",
"A/AAAA answer via system resolvers":"ответ A/AAAA через системный резолвер",
"same banner/header evidence":"та же улика в баннере/заголовках",
"Content-Security-Policy — constrains what the page may load/execute":
  "Content-Security-Policy — ограничивает, что страница может загружать/исполнять",
"Strict-Transport-Security — forces HTTPS for future visits":
  "Strict-Transport-Security — принудительный HTTPS для будущих визитов",
"X-Frame-Options — anti-clickjacking framing control":
  "X-Frame-Options — защита от кликджекинга",
"X-Content-Type-Options: nosniff — stops MIME sniffing":
  "X-Content-Type-Options: nosniff — запрещает MIME-снифинг",
"Referrer-Policy — controls how much referrer data leaks":
  "Referrer-Policy — управляет объёмом утечки referrer-данных",
"Permissions-Policy — restricts powerful browser features":
  "Permissions-Policy — ограничивает возможности браузера",
"Filter findings… (text search)":"Фильтр находок… (текстовый поиск)",
"Filter entities…":"Фильтр сущностей…",
"Filter relations… (click an entity above)":"Фильтр связей… (кликните по сущности выше)",
"Zoom in":"Приблизить","Zoom out":"Отдалить",
"Reset view (double-click the map works too)":"Сброс вида (двойной клик по карте тоже работает)",
"— external audit tool for":"— инструмент внешнего аудита для",
"targets only. Findings are observations, not proofs of exploitability: verify before acting. Every value in this file is complete — nothing was sampled or cut. This report makes no network requests: it is a standalone document.":
  "целей. Находки — наблюдения, а не доказательства эксплуатируемости: проверяйте перед действием. Каждое значение в файле полное — ничего не обрезано и не сэмплировано. Отчёт не делает сетевых запросов: это самодостаточный документ."
};
var I18NP=[
[/^External security audit\. (Deep mode|Safe mode \(default: passive, non-destructive\)) · (\d+) finding(?:s)? across (\d+) hosts? · risk (\d+)\/100 \(grade (\w), (\w+)\)\.$/,
 function(m,mode,nf,nh,sc,gr,wd){
   var ruwd={clean:"чисто",low:"низкий",moderate:"умеренный",elevated:"повышенный",high:"высокий"}[wd]||wd;
   var rumode=mode.charAt(0)==="D"?"Глубокий режим":"Безопасный режим (по умолчанию: пассивный, без деструктива)";
   return "Внешний аудит безопасности. "+rumode+" · находок: "+nf+" на "+nh+" хост(ах) · риск "+sc+"/100 (оценка "+gr+", "+ruwd+").";}],
[/^([A-Za-z]+) risk: (.+) \((\d+) total\)$/,
 function(m,wd,body,tot){
   var ruwd={Clean:"Чисто",Low:"Низкий",Moderate:"Умеренный",Elevated:"Повышенный",High:"Высокий"}[wd]||wd;
   var gen={Critical:["критичный","критичных"],High:["высокий","высоких"],Medium:["средний","средних"],Low:["низкий","низких"],Info:["инфо","инфо"]};
   var items=body.split(", ").map(function(it){
     var pm=it.match(/^(\d+) (Critical|High|Medium|Low|Info)$/);
     if(pm)return pm[1]+" "+gen[pm[2]][pm[1]==="1"?0:1];
     if(it==="only low/medium severity observations")return "только наблюдения низкой/средней серьёзности";
     return it;});
   return ruwd+" риск: "+items.join(", ")+" (всего "+tot+")";}],
[/^mikto enumerated (\d+) hosts? with (\d+) modules and observed (\d+) open ports?\. Counts include every check across every module\.(?: Grade (\w) \((\w+)\) on a 0–100 scale where critical=25, high=10, medium=4, low=1\.)?$/,
 function(m,nh,nm,np,gr,wd){
   var s="mikto собрал данные по "+nh+" хост(у/ам) с "+nm+" модул(ем/ями); открытых портов: "+np+
     ". Счётчики включают все проверки всех модулей.";
   if(gr){var ruwd={clean:"чисто",low:"низкий",moderate:"умеренный",elevated:"повышенный",high:"высокий"}[wd]||wd;
     s+=" Оценка "+gr+" ("+ruwd+") по шкале 0–100, где критический=25, высокий=10, средний=4, низкий=1.";}
   return s;}],
[/^mikto ran (\d+) modules and observed no issues to report\. This is an observation, not a guarantee — see the full inventory below\.$/,
 "mikto выполнил $1 модул(ей) и не нашёл проблем для отчёта. Это наблюдение, а не гарантия — полный инвентарь ниже."],
[/^Generated by mikto v(.+)$/,"Сгенерировано mikto v$1"],
[/^Scan visibility (blocked|degraded) on (\d+) of (\d+) hosts\.$/,
 function(m,vis,a,b){return "Видимость скана "+(vis==="blocked"?"заблокирована":"ограничена")+" на "+a+" из "+b+" хост(ах).";}],
[/^visibility: (full|degraded|blocked)$/,
 function(m,v){return "видимость: "+({full:"полная",degraded:"ограничена",blocked:"заблокирована"}[v]||v);}],
[/^(\d+) open$/,"открыто: $1"],
[/^(\d+) findings?$/,"находок: $1"],
[/^map: (\d+) of (\d+) entities \(hubs first\)$/,"карта: $1 из $2 сущностей (хабы первыми)"],
[/^map: all (\d+) entities$/,"карта: все $1 сущностей"],
[/^(\d+) entities · (\d+) relations$/,"$1 сущностей · $2 связей"],
[/^(\d+) of (\d+) shown$/,"$1 из $2 показано"],
[/^of 100 · (\w)$/,"из 100 · $1"],
[/^Headers: (.+)$/,"Заголовки: $1"],
[/^Top (\d+) by response time — useful for spotting rate limiting or overloaded services\.$/,
 "Топ-$1 по времени ответа — помогает заметить rate limiting или перегруженные сервисы."],
[/^(\d+) IPs? · (\d+) names?$/,"$1 IP · имён: $2"],
[/^mode (\w+) · (\w+)$/,"режим $1 · $2"],
[/^Click to highlight (\w+) entities on the map$/,
 "клик подсвечивает сущности «$1» на карте"],
[/^detected via header:(.+)$/,"обнаружено через заголовок:$1"],
[/^detected via ports$/,"обнаружено через порты"],
[/^HTTP (\d+) \(found via (\w+)\)$/,
 function(m,code,via){return "HTTP "+code+" (найдено через "+
   ({wordlist:"словарь",combo:"комбо-лист",js:"js",robots:"robots.txt"}[via]||via)+")";}],
[/^([\w-]+) not sent$/,"$1 не отправлен"],
[/^matched by (\w+): (.+)$/,"совпадение по $1: $2"],
[/^Recommendation[\s\u00A0]*·$/,"Рекомендация ·"],
[/^Upgrade (.+) to a release that fixes ([A-Za-z0-9-]+) per the vendor advisory, then re-scan to confirm\.$/,
 "Обновите $1 до версии, исправляющей $2, по рекомендации вендора, затем пересканируйте для подтверждения."],
[/^Verify the surface must be public; restrict or remove it if not, and keep the underlying software updated\.$/,
 "Проверьте, что поверхность действительно должна быть публичной; ограничьте или уберите её, если нет, и поддерживайте ПО обновлённым."],
[/^port open; probe: (.+)$/,"порт открыт; проба: $1"],
[/^([\d.]+) \((confirmed|probable|possible|unverified)\)$/,
 function(m,v,st){return v+" ("+({confirmed:"подтверждено",probable:"вероятно",possible:"возможно",unverified:"не проверено"}[st]||st)+")";}],
[/^(\d+) of (\d+) entities \(report cap\) — the full set is in the JSON report\.$/,
 "$1 из $2 сущностей (лимит отчёта) — полный набор в JSON-отчёте."],
[/^(\d+) server IP · (\d+) networks · (\d+) co-hosted$/,
 function(m,ips,nets,ch){
   var ru=function(n,one,few,many){var a=n%10,b=n%100;
     if(a===1&&b!==11)return one;if(a>=2&&a<=4&&(b<12||b>14))return few;return many;};
   return ips+" серверн"+(ips==="1"?"ый":"ых")+" IP · "+nets+" "+ru(+nets,"сеть","сети","сетей")+
     " · "+ch+" ко-хостинг";}]
];
var I18SEL="nav.top a,nav.top button,a.skip,p.sub,.brandline,.masthead .meta,"+
  "main h2,main h3,main h4,main th,main dt,main summary,main b,"+
  "main button,main option,main .cnt,main .small,main .muted,main .btitle,main .meta,main .tag,main .rec,"+
  "main .legend span,main .noresults,main .imap-cap,main .imap-hint,main .asncard p,"+
  "main .vis,main .risklegend,main .l";
function trText(t){
  if(!t)return null;
  if(I18N.hasOwnProperty(t))return I18N[t];
  if(/·$/.test(t)){var base=t.replace(/\s*·\s*$/,"");if(I18N.hasOwnProperty(base))return I18N[base]+" ·";}
  for(var i=0;i<I18NP.length;i++){var p=I18NP[i];if(p[0].test(t)){
    var out=t.replace(p[0],p[1]);if(out!==t)return out;}}
  return null;
}
function applyLang(lang){
  reportLang=lang;
  if(!origNodes){
    origNodes=[];
    var roots=doc.querySelectorAll(I18SEL);
    for(var i=0;i<roots.length;i++){
      var kids=roots[i].childNodes;
      for(var k=0;k<kids.length;k++){
        if(kids[k].nodeType===3&&kids[k].nodeValue.trim())origNodes.push([kids[k],kids[k].nodeValue]);
      }
    }
    var ft=doc.querySelector("footer .wrap")||doc.querySelector("footer");
    if(ft){var fnodes=ft.querySelectorAll("*");
      for(var f2=0;f2<fnodes.length;f2++){
        var fk=fnodes[f2].childNodes;
        for(var j=0;j<fk.length;j++)if(fk[j].nodeType===3&&fk[j].nodeValue.trim())origNodes.push([fk[j],fk[j].nodeValue]);
      }
      var fk2=ft.childNodes;
      for(var j2=0;j2<fk2.length;j2++)if(fk2[j2].nodeType===3&&fk2[j2].nodeValue.trim())origNodes.push([fk2[j2],fk2[j2].nodeValue]);
    }
  }
  for(var m=0;m<origNodes.length;m++){
    var nd=origNodes[m][0],ov=origNodes[m][1];
    if(lang==="en"){nd.nodeValue=ov;continue;}
    var idx=ov.indexOf(ov.trim());
    var t=ov.trim(),ru=trText(t);
    nd.nodeValue=ru==null?ov:ov.slice(0,idx)+ru+ov.slice(idx+t.length);
  }
  /* атрибуты (title/placeholder) — тоже переводим, оригинал запоминаем один раз */
  var attrs=doc.querySelectorAll("main [title],nav [title],footer [title],input[placeholder]");
  for(var a=0;a<attrs.length;a++){
    var el=attrs[a],which=el.hasAttribute("placeholder")?"placeholder":"title";
    var key="orig-"+which;
    if(!el.getAttribute(key))el.setAttribute(key,el.getAttribute(which)||"");
    var a0=el.getAttribute(key);
    if(lang==="en"){el.setAttribute(which,a0);continue;}
    var ar=trText(a0);
    if(ar!=null)el.setAttribute(which,ar);
  }
  root.setAttribute("lang",lang==="ru"?"ru":"en");
  var btn=doc.getElementById("lang-toggle");
  if(btn)btn.textContent=lang==="ru"?"EN":"RU";
  try{localStorage.setItem("mikto-lang",lang);}catch(e){}
}
(function(){
  var saved=null;try{saved=localStorage.getItem("mikto-lang");}catch(e){}
  var init=(saved==="ru"||saved==="en")?saved:(((navigator.language||"en").toLowerCase().indexOf("ru")===0)?"ru":"en");
  var lb=doc.getElementById("lang-toggle");
  if(lb)lb.addEventListener("click",function(){applyLang(reportLang==="ru"?"en":"ru");});
  if(init==="ru")applyLang("ru");
})();
})();
)mikto_js";