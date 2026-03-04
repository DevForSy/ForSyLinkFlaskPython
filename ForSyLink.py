import os, re, io, time, base64, sqlite3, secrets, functools, urllib.parse
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g, abort
from werkzeug.middleware.proxy_fix import ProxyFix
from jinja2 import DictLoader, ChoiceLoader
from PIL import Image, ImageDraw

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

DB_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forsy_link.db")
QR_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forsy_qrcodes")
os.makedirs(QR_DIR, exist_ok=True)

_rate_store = defaultdict(list)

def is_rate_limited(ip):
    now = time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < 60]
    if len(_rate_store[ip]) >= 20: return True
    _rate_store[ip].append(now)
    return False

def rate_limit(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if is_rate_limited(request.remote_addr or "unknown"):
            if request.path.startswith("/api/"): return jsonify({"error":"Rate limit exceeded."}), 429
            flash("Too many requests — please slow down.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper

def generate_csrf_token():
    if "csrf_token" not in session: session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def validate_csrf(token):
    return secrets.compare_digest(session.get("csrf_token",""), token or "")

app.jinja_env.globals["csrf_token"] = generate_csrf_token

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    with app.app_context():
        get_db().execute("""CREATE TABLE IF NOT EXISTS links(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_url TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            click_count INTEGER NOT NULL DEFAULT 0,
            qr_filename TEXT)""")
        get_db().commit()

BLOCKED_RE = re.compile(r"^(javascript|vbscript|data|file|ftp|blob|about)", re.I)
ALLOWED_SCHEMES = {"http","https"}

def validate_url(url):
    try: parsed = urllib.parse.urlparse(url)
    except: return False, "Could not parse URL."
    if parsed.scheme not in ALLOWED_SCHEMES: return False, f"Scheme '{parsed.scheme}' is not allowed."
    if not parsed.netloc: return False, "URL is missing a domain."
    if not re.match(r"^[a-zA-Z0-9._\-]+$", parsed.netloc.split(":")[0]): return False, "Invalid domain characters."
    return True, url

SLUG_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def unique_slug(db):
    for _ in range(10):
        slug = "".join(secrets.choice(SLUG_CHARS) for _ in range(7))
        if not db.execute("SELECT id FROM links WHERE slug=?", (slug,)).fetchone(): return slug
    raise RuntimeError("Could not generate unique slug.")

def make_qr_image(url):
    try:
        import qrcode as _qr
        q = _qr.QRCode(version=None, error_correction=_qr.constants.ERROR_CORRECT_M, box_size=10, border=4)
        q.add_data(url); q.make(fit=True)
        return q.make_image(fill_color="#0f0f0f", back_color="#ffffff").get_image()
    except ImportError: pass
    sz = 21; mods = [[False]*sz for _ in range(sz)]
    def sm(r,c,v=True):
        if 0<=r<sz and 0<=c<sz: mods[r][c]=v
    def fp(ro,co):
        for dr in range(7):
            for dc in range(7): sm(ro+dr,co+dc,(dr in(0,6))or(dc in(0,6))or(1<dr<5 and 1<dc<5))
    fp(0,0); fp(0,sz-7); fp(sz-7,0)
    for i in range(8,sz-8): sm(6,i,i%2==0); sm(i,6,i%2==0)
    data = url.encode("iso-8859-1","replace")[:17]
    bits = [0,1,0,0]+[(len(data)>>i)&1 for i in range(7,-1,-1)]
    for b in data: bits+=[(b>>i)&1 for i in range(7,-1,-1)]
    bits+=[0]*4
    while len(bits)%8: bits.append(0)
    col=sz-1; up=True; bi=0
    def ifn(r,c): return(r<9 and c<9)or(r<9 and c>=sz-8)or(r>=sz-8 and c<9)or r==6 or c==6
    placed=[[False]*sz for _ in range(sz)]
    while col>=1 and bi<len(bits):
        if col==6: col-=1; continue
        rows=range(sz-1,-1,-1) if up else range(sz)
        for row in rows:
            for dc in(0,-1):
                c=col+dc
                if 0<=c<sz and not ifn(row,c) and not placed[row][c]:
                    mods[row][c]=bool(bits[bi]) if bi<len(bits) else False
                    placed[row][c]=True; bi+=1
        col-=2; up=not up
    px=(sz+8)*10; img=Image.new("RGB",(px,px),"white"); draw=ImageDraw.Draw(img)
    for r in range(sz):
        for c in range(sz):
            if mods[r][c]:
                x0=(c+4)*10; y0=(r+4)*10
                draw.rectangle([x0,y0,x0+9,y0+9],fill="#0f0f0f")
    return img

def save_qr(url, slug):
    fn = f"{slug}.png"; make_qr_image(url).save(os.path.join(QR_DIR,fn),"PNG"); return fn

def qr_b64(slug):
    p = os.path.join(QR_DIR, f"{slug}.png")
    if not os.path.exists(p): return ""
    with open(p,"rb") as f: return base64.b64encode(f.read()).decode()

CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#07070e;--surf:#0d0d1a;--surf2:#11111f;--b1:#1a1a2e;--b2:#242438;
  --text:#ededf5;--muted:#64648a;--dim:#28283d;
  --gold:#d4a843;--gold2:#e8bf6b;--glow:rgba(212,168,67,.18);
  --green:#2ecc80;--red:#e05568;--blue:#4a8fff;
  --r:8px;--rl:14px;
  --mono:'Geist Mono','Courier New',monospace;
  --serif:'Instrument Serif',Georgia,serif;
  --sans:'Geist',system-ui,sans-serif;
}
html{font-size:16px;scroll-behavior:smooth}
body{
  background:var(--bg);color:var(--text);font-family:var(--sans);
  min-height:100vh;display:flex;flex-direction:column;
  background-image:
    radial-gradient(ellipse 120% 40% at 50% -5%,rgba(212,168,67,.05) 0%,transparent 55%),
    radial-gradient(ellipse 50% 30% at 90% 90%,rgba(46,204,128,.03) 0%,transparent 50%);
}
a{color:var(--gold);text-decoration:none;transition:opacity .15s}
a:hover{opacity:.7}
img{display:block;max-width:100%}
code{font-family:var(--mono)}
.site-header{border-bottom:1px solid var(--b1);background:rgba(7,7,14,.85);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);position:sticky;top:0;z-index:100}
.nav{max-width:1060px;margin:0 auto;padding:0 24px;height:58px;display:flex;align-items:center;justify-content:space-between}
.logo{font-family:var(--serif);font-size:1.25rem;color:var(--text);display:flex;align-items:center;gap:10px;letter-spacing:-.01em}
.logo-gem{width:8px;height:8px;background:var(--gold);border-radius:2px;transform:rotate(45deg);box-shadow:0 0 12px var(--gold);animation:gempulse 3s ease-in-out infinite}
@keyframes gempulse{0%,100%{box-shadow:0 0 8px var(--gold);opacity:1}50%{box-shadow:0 0 20px var(--gold2);opacity:.7}}
.nav-r{display:flex;align-items:center;gap:6px}
.nav-link{font-family:var(--mono);font-size:.73rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding:7px 12px;border-radius:6px;transition:color .15s,background .15s}
.nav-link:hover{color:var(--text);background:rgba(255,255,255,.04);opacity:1}
.flash-wrap{max-width:1060px;margin:18px auto 0;padding:0 24px;display:flex;flex-direction:column;gap:8px}
.flash{display:flex;align-items:center;gap:10px;padding:12px 16px;border-radius:var(--r);font-size:.875rem;border:1px solid;animation:fin .2s ease}
@keyframes fin{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:translateY(0)}}
.flash--error{background:rgba(224,85,104,.07);border-color:rgba(224,85,104,.2);color:#f09aa8}
.flash--info{background:rgba(212,168,67,.07);border-color:rgba(212,168,67,.2);color:var(--gold2)}
.flash--success{background:rgba(46,204,128,.07);border-color:rgba(46,204,128,.2);color:var(--green)}
.flash-x{margin-left:auto;background:none;border:none;color:inherit;cursor:pointer;opacity:.35;font-size:1rem;line-height:1;padding:0 2px}
.flash-x:hover{opacity:.9}
.wrap{flex:1;max-width:1060px;margin:0 auto;padding:0 24px 100px;width:100%}
.hero{padding:80px 0 52px;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;top:-60px;left:-100px;width:400px;height:400px;background:radial-gradient(circle,rgba(212,168,67,.06) 0%,transparent 65%);pointer-events:none}
.badge{display:inline-flex;align-items:center;gap:7px;font-family:var(--mono);font-size:.7rem;letter-spacing:.1em;text-transform:uppercase;color:var(--gold);border:1px solid rgba(212,168,67,.22);padding:5px 13px;border-radius:100px;margin-bottom:26px}
.badge-dot{width:5px;height:5px;background:var(--gold);border-radius:50%;box-shadow:0 0 5px var(--gold)}
.h1{font-family:var(--serif);font-size:clamp(2.8rem,7.5vw,5.5rem);line-height:1.02;letter-spacing:-.025em;margin-bottom:18px}
.h1 em{font-style:italic;color:var(--gold)}
.hero-sub{font-size:1rem;color:var(--muted);max-width:500px;line-height:1.75}
.card{background:var(--surf);border:1px solid var(--b1);border-radius:var(--rl);padding:28px}
.card--g{box-shadow:0 0 0 1px rgba(212,168,67,.04),0 24px 64px rgba(0,0,0,.55)}
.form-sec{margin-bottom:60px}
.lbl{display:block;font-family:var(--mono);font-size:.68rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:13px}
.irow{display:flex;gap:9px;align-items:center}
.iwrap{position:relative;flex:1}
.urlinput{width:100%;background:#080814;border:1px solid var(--b2);border-radius:var(--r);color:var(--text);font-family:var(--mono);font-size:.86rem;padding:14px 14px 14px 42px;outline:none;transition:border-color .15s,box-shadow .15s}
.urlinput::placeholder{color:var(--dim)}
.urlinput:focus{border-color:rgba(212,168,67,.4);box-shadow:0 0 0 3px rgba(212,168,67,.06)}
.iicon{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--dim);font-family:var(--mono);font-size:.82rem;pointer-events:none}
.hint{margin-top:9px;font-size:.73rem;color:var(--dim);font-family:var(--mono)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:13px 22px;border-radius:var(--r);font-family:var(--mono);font-size:.8rem;font-weight:500;letter-spacing:.04em;cursor:pointer;border:none;text-decoration:none;transition:all .15s;white-space:nowrap}
.btn--gold{background:var(--gold);color:#07070e}
.btn--gold:hover{background:var(--gold2);opacity:1;transform:translateY(-1px);box-shadow:0 6px 20px rgba(212,168,67,.28)}
.btn--out{background:transparent;border:1px solid var(--b2);color:var(--muted)}
.btn--out:hover{border-color:var(--gold);color:var(--gold);opacity:1}
.btn--ghost{background:transparent;color:var(--muted);padding:13px 14px}
.btn--ghost:hover{color:var(--text);opacity:1}
.sec-head{display:flex;align-items:baseline;gap:12px;margin-bottom:20px}
.sec-title{font-family:var(--serif);font-size:1.35rem;letter-spacing:-.01em}
.sec-tag{font-family:var(--mono);font-size:.67rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border:1px solid var(--b2);padding:3px 9px;border-radius:100px}
.twrap{overflow-x:auto;border:1px solid var(--b1);border-radius:var(--rl)}
.tbl{width:100%;border-collapse:collapse;font-size:.84rem}
.tbl th{background:#090914;padding:10px 15px;text-align:left;font-family:var(--mono);font-size:.65rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--b1)}
.tbl td{padding:12px 15px;border-bottom:1px solid rgba(26,26,46,.7);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:rgba(255,255,255,.012)}
.tcell-link{font-family:var(--mono);font-size:.79rem;color:var(--gold)}
.tcell-orig{max-width:270px;font-size:.79rem;color:var(--muted);font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
.tbadge{display:inline-block;background:rgba(74,143,255,.1);color:#79b0ff;border:1px solid rgba(74,143,255,.2);border-radius:100px;padding:2px 9px;font-family:var(--mono);font-size:.73rem;font-weight:600}
.tdate{color:var(--muted);font-family:var(--mono);font-size:.73rem}
.tact{font-family:var(--mono);font-size:.76rem;color:var(--muted)}
.tact:hover{color:var(--gold);opacity:1}
.api-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.api-card{background:var(--surf);border:1px solid var(--b1);border-radius:var(--rl);padding:22px}
.api-head{display:flex;align-items:center;gap:9px;margin-bottom:11px}
.api-head code{font-size:.86rem;color:var(--text)}
.mth{font-family:var(--mono);font-size:.67rem;font-weight:600;padding:3px 8px;border-radius:4px;letter-spacing:.05em;text-transform:uppercase}
.mth--post{background:rgba(224,85,104,.1);color:#f09aa8;border:1px solid rgba(224,85,104,.2)}
.mth--get{background:rgba(46,204,128,.08);color:var(--green);border:1px solid rgba(46,204,128,.18)}
.api-desc{font-size:.81rem;color:var(--muted);margin-bottom:13px;line-height:1.65}
.pre{background:#050509;border:1px solid var(--b1);border-radius:7px;padding:13px;font-family:var(--mono);font-size:.73rem;color:var(--muted);white-space:pre-wrap;word-break:break-all;margin-bottom:9px;line-height:1.7}
.pre--r{color:#5effc0}
.res-sec{padding:50px 0}
.res-top{text-align:center;margin-bottom:40px}
.check{display:inline-flex;align-items:center;justify-content:center;width:58px;height:58px;background:rgba(46,204,128,.07);border:1px solid rgba(46,204,128,.22);border-radius:50%;font-size:1.3rem;color:var(--green);margin-bottom:16px;animation:pop .4s cubic-bezier(.175,.885,.32,1.275)}
@keyframes pop{from{opacity:0;transform:scale(.3)}to{opacity:1;transform:scale(1)}}
.res-h{font-family:var(--serif);font-size:2.1rem;margin-bottom:7px}
.res-sub{color:var(--muted);font-size:.93rem}
.res-grid{display:grid;grid-template-columns:1fr 290px;gap:20px;margin-bottom:24px}
.clbl{font-family:var(--mono);font-size:.66rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:13px}
.sbox{background:#050509;border:1px solid rgba(212,168,67,.18);border-radius:var(--r);padding:15px 17px;margin-bottom:15px}
.slink{font-family:var(--mono);font-size:.97rem;font-weight:500;color:var(--gold);word-break:break-all}
.brow{display:flex;gap:9px;margin-bottom:18px}
.origb{border-top:1px solid var(--b1);padding-top:15px;display:flex;flex-direction:column;gap:4px}
.origlbl{font-family:var(--mono);font-size:.64rem;letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}
.origurl{font-size:.8rem;color:var(--muted);word-break:break-all;font-family:var(--mono)}
.mgrid{display:flex;gap:22px;flex-wrap:wrap;border-top:1px solid var(--b1);padding-top:15px}
.mi{display:flex;flex-direction:column;gap:3px}
.mk{font-family:var(--mono);font-size:.64rem;letter-spacing:.1em;text-transform:uppercase;color:var(--dim)}
.mv{font-family:var(--mono);font-size:.83rem;color:var(--text)}
.qcard{display:flex;flex-direction:column;align-items:center;gap:15px;text-align:center}
.qwrap{padding:13px;background:#fff;border-radius:var(--r)}
.qimg{image-rendering:pixelated;display:block}
.qhint{font-size:.76rem;color:var(--muted);font-family:var(--mono)}
.resfoot{display:flex;gap:11px;justify-content:center;margin-top:6px}
.st-sec{padding:50px 0}
.st-top{text-align:center;margin-bottom:40px}
.st-ico{font-family:var(--serif);font-style:italic;font-size:2.8rem;color:var(--gold);margin-bottom:11px;animation:spin 10s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
.st-h{font-family:var(--serif);font-size:1.9rem;margin-bottom:6px}
.st-slug{font-family:var(--mono);font-size:.97rem;color:var(--gold)}
.st-grid{display:grid;grid-template-columns:175px 1fr 255px;gap:18px;align-items:start;margin-bottom:18px}
.spot{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;gap:7px;padding:34px 14px;background:linear-gradient(135deg,rgba(212,168,67,.07),rgba(46,204,128,.03));border-color:rgba(212,168,67,.12)}
.bignum{font-family:var(--serif);font-size:3.3rem;color:var(--gold);line-height:1}
.biglbl{font-family:var(--mono);font-size:.64rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.dlist{display:flex;flex-direction:column;gap:15px}
.drow{display:flex;flex-direction:column;gap:3px}
.dk{font-family:var(--mono);font-size:.64rem;letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}
.dv{font-family:var(--mono);font-size:.83rem;color:var(--text)}
.dlink{color:var(--gold)}
.dorig{word-break:break-all}
.apitip{display:flex;align-items:center;gap:13px;padding:13px 17px;margin-bottom:22px;flex-wrap:wrap}
.apitip-lbl{font-family:var(--mono);font-size:.64rem;letter-spacing:.1em;text-transform:uppercase;color:var(--gold);border:1px solid rgba(212,168,67,.22);padding:3px 8px;border-radius:4px}
.apitip-code{flex:1;font-size:.79rem;color:var(--muted);word-break:break-all;font-family:var(--mono)}
.stfoot{display:flex;gap:11px}
.err-sec{padding:100px 0;text-align:center;display:flex;flex-direction:column;align-items:center;gap:16px}
.errnum{font-family:var(--serif);font-size:clamp(5.5rem,16vw,9.5rem);color:var(--dim);line-height:1;letter-spacing:-.04em;animation:glitch 5s infinite}
@keyframes glitch{0%,88%,100%{text-shadow:none}90%{text-shadow:-3px 0 var(--red),3px 0 var(--blue)}92%{text-shadow:3px 0 var(--red),-3px 0 var(--blue)}94%{text-shadow:none}}
.err-h{font-family:var(--serif);font-size:1.75rem}
.err-sub{color:var(--muted);max-width:360px}
.site-footer{border-top:1px solid var(--b1);background:var(--surf);padding:16px 0;margin-top:auto}
.foot{max-width:1060px;margin:0 auto;padding:0 24px;display:flex;align-items:center;gap:18px}
.foot-logo{font-family:var(--serif);font-size:.88rem;color:var(--dim)}
.sep{width:1px;height:11px;background:var(--b2)}
.foot-copy{font-size:.76rem;color:var(--dim);font-family:var(--mono)}
.foot-v{margin-left:auto;font-family:var(--mono);font-size:.69rem;color:var(--dim);letter-spacing:.08em}
@media(max-width:840px){.api-grid,.res-grid,.st-grid{grid-template-columns:1fr}.qcard{min-width:unset}}
@media(max-width:580px){.irow{flex-direction:column}.btn--gold{width:100%}.h1{font-size:2.6rem}.wrap,.nav,.foot{padding-left:16px;padding-right:16px}.resfoot,.stfoot{flex-direction:column}}
"""

BASE_T = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>{% block title %}ForSy Link{% endblock %}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Geist+Mono:wght@300;400;500;600;700&family=Geist:wght@300;400;500;600&display=swap" rel="stylesheet"/>
<style>""" + CSS + """</style>
</head>
<body>
<header class="site-header">
  <nav class="nav">
    <a href="{{ url_for('index') }}" class="logo"><span class="logo-gem"></span>ForSy Link</a>
    <div class="nav-r">
      <a href="{{ url_for('index') }}" class="nav-link">Home</a>
      <a href="#api" class="nav-link">API</a>
    </div>
  </nav>
</header>
{% with messages = get_flashed_messages(with_categories=true) %}{% if messages %}
<div class="flash-wrap">{% for cat,msg in messages %}
<div class="flash flash--{{ cat }}">{% if cat=='error' %}✕{% elif cat=='info' %}◆{% else %}✓{% endif %} <span>{{ msg }}</span><button class="flash-x" onclick="this.parentElement.remove()">×</button></div>
{% endfor %}</div>{% endif %}{% endwith %}
<main class="wrap">{% block content %}{% endblock %}</main>
<footer class="site-footer"><div class="foot">
  <span class="foot-logo">ForSy Link</span><span class="sep"></span>
  <span class="foot-copy">Flask · Python · SQLite</span>
  <span class="foot-v">v1.0</span>
</div></footer>
<script>
document.querySelectorAll(".copy-btn").forEach(b=>{
  b.addEventListener("click",()=>{
    navigator.clipboard.writeText(b.dataset.copy).then(()=>{
      const o=b.textContent;b.textContent="Copied!";
      setTimeout(()=>b.textContent=o,2000);
    });
  });
});
</script>
</body></html>"""

INDEX_T = """{% extends "base.html" %}
{% block content %}
<section class="hero">
  <div class="badge"><span class="badge-dot"></span>URL Shortener &amp; QR Generator</div>
  <h1 class="h1">Short links.<br><em>Instant</em> QR codes.</h1>
  <p class="hero-sub">Paste any URL below — get a permanent short link, a scannable QR code, and live click analytics.</p>
</section>
<section class="form-sec">
  <div class="card card--g">
    <form method="POST" action="{{ url_for('index') }}" novalidate>
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
      <label for="u" class="lbl">Paste your URL</label>
      <div class="irow">
        <div class="iwrap">
          <span class="iicon">⌁</span>
          <input id="u" type="url" name="url" class="urlinput" placeholder="https://example.com/very/long/path" autocomplete="url" spellcheck="false" maxlength="2048" required/>
        </div>
        <button type="submit" class="btn btn--gold">Shorten →</button>
      </div>
      <p class="hint">https:// and http:// · max 2048 chars</p>
    </form>
  </div>
</section>
{% if links %}
<section style="margin-bottom:60px">
  <div class="sec-head"><h2 class="sec-title">Recent Links</h2><span class="sec-tag">{{ links|length }} entries</span></div>
  <div class="twrap">
    <table class="tbl">
      <thead><tr><th>Short Link</th><th>Original URL</th><th>Clicks</th><th>Created</th><th></th></tr></thead>
      <tbody>{% for l in links %}
      <tr>
        <td><a class="tcell-link" href="{{ url_for('redir', slug=l.slug, _external=True) }}" target="_blank" rel="noopener">{{ url_for('redir', slug=l.slug, _external=True) }}</a></td>
        <td><span class="tcell-orig" title="{{ l.original_url|e }}">{{ l.original_url|e|truncate(52) }}</span></td>
        <td><span class="tbadge">{{ l.click_count }}</span></td>
        <td class="tdate">{{ l.created_at }}</td>
        <td><a class="tact" href="{{ url_for('stats', slug=l.slug) }}">Stats ↗</a></td>
      </tr>{% endfor %}
      </tbody>
    </table>
  </div>
</section>
{% endif %}
<section id="api" style="margin-bottom:60px">
  <div class="sec-head"><h2 class="sec-title">API Reference</h2><span class="sec-tag">JSON</span></div>
  <div class="api-grid">
    <div class="api-card">
      <div class="api-head"><span class="mth mth--post">POST</span><code>/api/create</code></div>
      <p class="api-desc">Create a short link. Accepts JSON or form data with a <code>url</code> field.</p>
      <pre class="pre">curl -X POST {{ request.url_root }}api/create \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'</pre>
      <pre class="pre pre--r">{
  "slug":       "aB3xY9z",
  "short_url":  "{{ request.url_root }}aB3xY9z",
  "created_at": "2025-01-01 12:00:00",
  "reused":     false
}</pre>
    </div>
    <div class="api-card">
      <div class="api-head"><span class="mth mth--get">GET</span><code>/api/stats/&lt;slug&gt;</code></div>
      <p class="api-desc">Retrieve stats for a slug — click count, original URL, creation time.</p>
      <pre class="pre">curl {{ request.url_root }}api/stats/aB3xY9z</pre>
      <pre class="pre pre--r">{
  "slug":         "aB3xY9z",
  "original_url": "https://example.com",
  "short_url":    "{{ request.url_root }}aB3xY9z",
  "click_count":  42,
  "created_at":   "2025-01-01 12:00:00"
}</pre>
    </div>
  </div>
</section>
{% endblock %}"""

RESULT_T = """{% extends "base.html" %}
{% block title %}Link Created – ForSy Link{% endblock %}
{% block content %}
<section class="res-sec">
  <div class="res-top">
    <div class="check">✓</div>
    <h1 class="res-h">Your link is ready</h1>
    <p class="res-sub">Short link and QR code generated successfully.</p>
  </div>
  <div class="res-grid">
    <div class="card card--g" style="display:flex;flex-direction:column;gap:16px">
      <div>
        <div class="clbl">Short URL</div>
        <div class="sbox"><a href="{{ short_url }}" target="_blank" rel="noopener" class="slink">{{ short_url }}</a></div>
        <div class="brow">
          <button class="btn btn--gold copy-btn" data-copy="{{ short_url }}">Copy Link</button>
          <a href="{{ url_for('stats', slug=link.slug) }}" class="btn btn--out">View Stats</a>
        </div>
      </div>
      <div class="origb">
        <span class="origlbl">Original URL</span>
        <a href="{{ link.original_url|e }}" class="origurl" target="_blank" rel="noopener nofollow">{{ link.original_url|e|truncate(80) }}</a>
      </div>
      <div class="mgrid">
        <div class="mi"><span class="mk">Slug</span><code class="mv">{{ link.slug }}</code></div>
        <div class="mi"><span class="mk">Created</span><span class="mv">{{ link.created_at }}</span></div>
        <div class="mi"><span class="mk">Clicks</span><span class="mv" style="color:var(--blue)">{{ link.click_count }}</span></div>
      </div>
    </div>
    <div class="card qcard">
      <div class="clbl">QR Code</div>
      <div class="qwrap"><img class="qimg" src="data:image/png;base64,{{ qrb64 }}" alt="QR Code" width="220" height="220"/></div>
      <p class="qhint">Scan to open short link</p>
      <a href="data:image/png;base64,{{ qrb64 }}" download="forsy-{{ link.slug }}.png" class="btn btn--out" style="width:100%">↓ Download PNG</a>
    </div>
  </div>
  <div class="resfoot"><a href="{{ url_for('index') }}" class="btn btn--out">← Shorten Another</a></div>
</section>
{% endblock %}"""

STATS_T = """{% extends "base.html" %}
{% block title %}Stats /{{ link.slug }} – ForSy Link{% endblock %}
{% block content %}
<section class="st-sec">
  <div class="st-top">
    <div class="st-ico">◉</div>
    <h1 class="st-h">Link Analytics</h1>
    <code class="st-slug">/{{ link.slug }}</code>
  </div>
  <div class="st-grid">
    <div class="card spot">
      <span class="bignum">{{ link.click_count }}</span>
      <span class="biglbl">Total Clicks</span>
    </div>
    <div class="card">
      <div class="clbl">Link Details</div>
      <div class="dlist">
        <div class="drow"><span class="dk">Short URL</span><a href="{{ short_url }}" class="dv dlink" target="_blank" rel="noopener">{{ short_url }}</a></div>
        <div class="drow"><span class="dk">Original URL</span><a href="{{ link.original_url|e }}" class="dv dlink dorig" target="_blank" rel="noopener nofollow" title="{{ link.original_url|e }}">{{ link.original_url|e|truncate(68) }}</a></div>
        <div class="drow"><span class="dk">Slug</span><code class="dv">{{ link.slug }}</code></div>
        <div class="drow"><span class="dk">Created</span><span class="dv">{{ link.created_at }} UTC</span></div>
      </div>
    </div>
    <div class="card qcard">
      <div class="clbl">QR Code</div>
      <div class="qwrap"><img class="qimg" src="data:image/png;base64,{{ qrb64 }}" alt="QR Code" width="200" height="200"/></div>
      <a href="data:image/png;base64,{{ qrb64 }}" download="forsy-{{ link.slug }}.png" class="btn btn--out" style="width:100%">↓ Download</a>
    </div>
  </div>
  <div class="card apitip">
    <span class="apitip-lbl">API</span>
    <code class="apitip-code">GET {{ request.host_url }}api/stats/{{ link.slug }}</code>
    <button class="btn btn--ghost copy-btn" data-copy="{{ request.host_url }}api/stats/{{ link.slug }}">Copy</button>
  </div>
  <div class="stfoot">
    <a href="{{ url_for('index') }}" class="btn btn--gold">← Home</a>
    <a href="{{ short_url }}" class="btn btn--out" target="_blank" rel="noopener">Open Short Link ↗</a>
  </div>
</section>
{% endblock %}"""

E404_T = """{% extends "base.html" %}
{% block title %}404 – ForSy Link{% endblock %}
{% block content %}
<section class="err-sec">
  <div class="errnum">404</div>
  <h1 class="err-h">Link not found</h1>
  <p class="err-sub">This short link doesn't exist or may have been removed.</p>
  <a href="{{ url_for('index') }}" class="btn btn--gold">← Back to Home</a>
</section>
{% endblock %}"""

E429_T = """{% extends "base.html" %}
{% block title %}429 – ForSy Link{% endblock %}
{% block content %}
<section class="err-sec">
  <div class="errnum">429</div>
  <h1 class="err-h">Too many requests</h1>
  <p class="err-sub">Rate limit reached. Please wait a moment before trying again.</p>
  <a href="{{ url_for('index') }}" class="btn btn--gold">← Back to Home</a>
</section>
{% endblock %}"""

app.jinja_loader = ChoiceLoader([DictLoader({
    "base.html":   BASE_T,
    "index.html":  INDEX_T,
    "result.html": RESULT_T,
    "stats.html":  STATS_T,
    "404.html":    E404_T,
    "429.html":    E429_T,
}), app.jinja_loader])

@app.route("/", methods=["GET","POST"])
@rate_limit
def index():
    db = get_db()
    links = db.execute("SELECT slug,original_url,click_count,created_at FROM links ORDER BY id DESC LIMIT 12").fetchall()
    if request.method == "POST":
        if not validate_csrf(request.form.get("csrf_token","")):
            flash("Invalid request token.", "error"); return redirect(url_for("index"))
        raw = request.form.get("url","").strip()
        if not raw:
            flash("Please enter a URL.", "error"); return redirect(url_for("index"))
        if BLOCKED_RE.match(raw):
            flash("URL scheme not allowed.", "error"); return redirect(url_for("index"))
        if "://" not in raw: raw = "https://" + raw
        ok, result = validate_url(raw)
        if not ok:
            flash(f"Invalid URL: {result}", "error"); return redirect(url_for("index"))
        existing = db.execute("SELECT slug FROM links WHERE original_url=?", (result,)).fetchone()
        if existing:
            flash("URL already shortened — showing existing link.", "info")
            return redirect(url_for("result", slug=existing["slug"]))
        try:
            slug = unique_slug(db); qr = save_qr(url_for("redir", slug=slug, _external=True), slug)
            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            db.execute("INSERT INTO links (original_url,slug,created_at,qr_filename) VALUES (?,?,?,?)", (result,slug,now,qr))
            db.commit()
        except Exception as e:
            flash(f"Something went wrong: {e}", "error"); return redirect(url_for("index"))
        return redirect(url_for("result", slug=slug))
    return render_template("index.html", links=links)

@app.route("/result/<slug>")
def result(slug):
    db = get_db(); link = db.execute("SELECT * FROM links WHERE slug=?", (slug,)).fetchone()
    if not link: abort(404)
    return render_template("result.html", link=link, short_url=url_for("redir", slug=slug, _external=True), qrb64=qr_b64(slug))

@app.route("/<slug>")
@rate_limit
def redir(slug):
    if not re.match(r"^[a-zA-Z0-9]{1,20}$", slug): abort(404)
    db = get_db(); link = db.execute("SELECT * FROM links WHERE slug=?", (slug,)).fetchone()
    if not link: abort(404)
    db.execute("UPDATE links SET click_count=click_count+1 WHERE slug=?", (slug,)); db.commit()
    return redirect(link["original_url"], 302)

@app.route("/stats/<slug>")
def stats(slug):
    db = get_db(); link = db.execute("SELECT * FROM links WHERE slug=?", (slug,)).fetchone()
    if not link: abort(404)
    return render_template("stats.html", link=link, short_url=url_for("redir", slug=slug, _external=True), qrb64=qr_b64(slug))

@app.route("/api/create", methods=["POST"])
@rate_limit
def api_create():
    data = request.get_json(silent=True) or request.form
    raw = (data.get("url") or "").strip()
    if not raw: return jsonify({"error":"Missing 'url'."}), 400
    if BLOCKED_RE.match(raw): return jsonify({"error":"URL scheme not allowed."}), 400
    if "://" not in raw: raw = "https://" + raw
    ok, result = validate_url(raw)
    if not ok: return jsonify({"error":result}), 400
    db = get_db()
    existing = db.execute("SELECT slug FROM links WHERE original_url=?", (result,)).fetchone()
    if existing: return jsonify({"slug":existing["slug"],"short_url":url_for("redir", slug=existing["slug"], _external=True),"reused":True})
    try:
        slug = unique_slug(db); qr = save_qr(url_for("redir", slug=slug, _external=True), slug)
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        db.execute("INSERT INTO links (original_url,slug,created_at,qr_filename) VALUES (?,?,?,?)", (result,slug,now,qr))
        db.commit()
    except Exception as e: return jsonify({"error":str(e)}), 500
    return jsonify({"slug":slug,"short_url":url_for("redir", slug=slug, _external=True),"created_at":now,"reused":False}), 201

@app.route("/api/stats/<slug>")
@rate_limit
def api_stats(slug):
    if not re.match(r"^[a-zA-Z0-9]{1,20}$", slug): return jsonify({"error":"Invalid slug."}), 400
    db = get_db(); link = db.execute("SELECT * FROM links WHERE slug=?", (slug,)).fetchone()
    if not link: return jsonify({"error":"Not found."}), 404
    return jsonify({"slug":link["slug"],"original_url":link["original_url"],"short_url":url_for("redir", slug=link["slug"], _external=True),"click_count":link["click_count"],"created_at":link["created_at"]})

@app.errorhandler(404)
def e404(e):
    if request.path.startswith("/api/"): return jsonify({"error":"Not found."}), 404
    return render_template("404.html"), 404

@app.errorhandler(429)
def e429(e):
    if request.path.startswith("/api/"): return jsonify({"error":"Rate limit exceeded."}), 429
    return render_template("429.html"), 429

@app.after_request
def sec(r):
    r.headers.update({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","X-XSS-Protection":"1; mode=block","Referrer-Policy":"strict-origin-when-cross-origin","Content-Security-Policy":"default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline';"})
    return r

if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)