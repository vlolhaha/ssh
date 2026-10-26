#!/usr/bin/env python3
# pip install flask paramiko
# Chạy: WEB_USER=admin WEB_PASS=matkhau python3 app.py   (mở http://localhost:5000)
import io, json, os, secrets, threading, time
import paramiko
from flask import Flask, jsonify, request, Response

DATA = "servers.json"
WEB_USER = os.environ.get("WEB_USER", "admin")
WEB_PASS = os.environ.get("WEB_PASS") or secrets.token_urlsafe(8)
lock = threading.Lock()
workers = {}
app = Flask(__name__)


def load():
    try:
        with open(DATA) as f:
            return json.load(f)
    except Exception:
        return []


def save(items):
    with open(DATA, "w") as f:
        json.dump(items, f, indent=2)
    os.chmod(DATA, 0o600)


def load_key(text, passphrase):
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase or None)
        except Exception:
            pass
    raise ValueError("Private key không hợp lệ hoặc sai passphrase")


class Worker(threading.Thread):
    def __init__(self, cfg):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.stop = threading.Event()
        self.status = "Đang kết nối..."
        self.since = None
        self.retries = 0

    def run(self):
        c = self.cfg
        while not self.stop.is_set():
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                self.status = "Đang kết nối..."
                kw = dict(hostname=c["host"], port=int(c["port"]), username=c["user"],
                          timeout=15, banner_timeout=15, auth_timeout=15,
                          allow_agent=False, look_for_keys=False)
                if c.get("key"):
                    kw["pkey"] = load_key(c["key"], c.get("password"))
                else:
                    kw["password"] = c.get("password", "")
                client.connect(**kw)
                t = client.get_transport()
                t.set_keepalive(15)
                self.status, self.since = "Online", time.time()
                while not self.stop.is_set() and t.is_active():
                    try:
                        t.send_ignore()
                    except Exception:
                        break
                    self.stop.wait(15)
                if not self.stop.is_set():
                    self.status = "Mất kết nối"
            except Exception as e:
                self.status = "Lỗi: " + str(e)[:120]
            finally:
                self.since = None
                try:
                    client.close()
                except Exception:
                    pass
            self.retries += 1
            self.stop.wait(10)  # chờ rồi tự kết nối lại


def start(cfg):
    w = Worker(cfg)
    workers[cfg["id"]] = w
    w.start()


@app.before_request
def auth():
    a = request.authorization
    if not a or a.username != WEB_USER or a.password != WEB_PASS:
        return Response("Cần đăng nhập", 401, {"WWW-Authenticate": 'Basic realm="SSH Keeper"'})


@app.get("/api/list")
def api_list():
    out = []
    for c in load():
        w = workers.get(c["id"])
        up = int(time.time() - w.since) if w and w.since else 0
        out.append(dict(id=c["id"], name=c["name"], host=c["host"], port=c["port"], user=c["user"],
                        status=w.status if w else "Đã dừng", online=bool(w and w.since),
                        uptime=up, retries=w.retries if w else 0))
    return jsonify(out)


@app.post("/api/add")
def api_add():
    d = request.get_json(force=True)
    host, user = d.get("host", "").strip(), d.get("user", "").strip()
    if not host or not user:
        return jsonify(error="Thiếu host hoặc user"), 400
    if not d.get("password") and not d.get("key"):
        return jsonify(error="Cần mật khẩu hoặc private key"), 400
    cfg = dict(id=secrets.token_hex(4), name=d.get("name", "").strip() or host, host=host,
               port=int(d.get("port") or 22), user=user, password=d.get("password", ""),
               key=d.get("key", "").strip())
    with lock:
        items = load()
        items.append(cfg)
        save(items)
    start(cfg)
    return jsonify(ok=True)


@app.post("/api/delete/<sid>")
def api_delete(sid):
    with lock:
        save([c for c in load() if c["id"] != sid])
    w = workers.pop(sid, None)
    if w:
        w.stop.set()
    return jsonify(ok=True)


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SSH Keeper</title>
<style>
body{font-family:sans-serif;max-width:720px;margin:0 auto;padding:12px;background:#f4f4f6;color:#222}
.box{background:#fff;border-radius:10px;padding:12px;margin-bottom:14px;box-shadow:0 1px 3px #0002}
input,textarea{width:100%;box-sizing:border-box;padding:9px;margin:4px 0;border:1px solid #bbb;border-radius:6px;font-size:15px}
button{padding:9px 14px;border:0;border-radius:6px;background:#2563eb;color:#fff;font-size:15px;cursor:pointer}
button.del{background:#dc2626}.row{display:flex;gap:8px}.row>*{flex:1}
.item{display:flex;justify-content:space-between;align-items:center;gap:8px;border-top:1px solid #eee;padding:10px 0}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
small{color:#666}#msg{color:#dc2626}
</style></head><body>
<h2>SSH Keeper</h2>
<div class="box"><b>Thêm SSH</b>
<input id="name" placeholder="Tên (tuỳ chọn)">
<div class="row"><input id="host" placeholder="Host / IP"><input id="port" placeholder="Port" value="22"></div>
<input id="user" placeholder="User">
<input id="password" type="password" placeholder="Mật khẩu (hoặc passphrase của key)">
<textarea id="key" rows="4" placeholder="Private key (để trống nếu dùng mật khẩu)"></textarea>
<button onclick="add()">Thêm</button> <span id="msg"></span></div>
<div class="box"><b>Danh sách</b><div id="list">Đang tải...</div></div>
<script>
const $=id=>document.getElementById(id);
function fmt(s){const h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h+"h "+m+"m"}
async function load(){
  const r=await fetch("/api/list");const items=await r.json();const L=$("list");L.textContent="";
  if(!items.length){L.textContent="Chưa có SSH nào";return}
  for(const s of items){
    const div=document.createElement("div");div.className="item";
    const info=document.createElement("div");
    const t=document.createElement("b");t.textContent=s.name;
    const dot=document.createElement("span");dot.className="dot";dot.style.background=s.online?"#16a34a":"#dc2626";
    const sm=document.createElement("small");
    sm.textContent=s.user+"@"+s.host+":"+s.port+" | "+s.status+(s.online?" | "+fmt(s.uptime):"")+" | reconnect: "+s.retries;
    info.append(dot,t,document.createElement("br"),sm);
    const b=document.createElement("button");b.className="del";b.textContent="Xoá";
    b.onclick=async()=>{if(confirm("Xoá "+s.name+"?")){await fetch("/api/delete/"+s.id,{method:"POST"});load()}};
    div.append(info,b);L.append(div);
  }
}
async function add(){
  const body={};for(const k of ["name","host","port","user","password","key"])body[k]=$(k).value;
  const r=await fetch("/api/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const j=await r.json();$("msg").textContent=j.error||"";
  if(r.ok){for(const k of ["name","host","user","password","key"])$(k).value="";load()}
}
load();setInterval(load,3000);
</script></body></html>"""


@app.get("/")
def index():
    return PAGE


if __name__ == "__main__":
    for cfg in load():
        start(cfg)
    print(f"\n>>> Đăng nhập web: {WEB_USER} / {WEB_PASS}\n")
    app.run(host="0.0.0.0", port=5000, threaded=True)
