"""
web_client.py
-------------
Interface web do Secure Chat.

Roda um mini servidor HTTP no seu PC e serve uma pagina de chat. Ao
executar este arquivo, a pagina abre automaticamente no navegador padrao
do PC. A mesma pagina tambem pode ser acessada de outro dispositivo (ex.:
celular) na mesma rede Wi-Fi, apontando o navegador para o IP do PC.

Cada aba/navegador que acessa a pagina recebe uma SESSAO propria (via
cookie), com seu proprio ChatClient (login, par de chaves RSA, fila de
mensagens). Isso permite abrir varias abas no mesmo PC (ex.: uma para
"alice" e outra para "bob"), ou uma aba no PC e outra no celular, sem que
uma sessao interfira na outra.

Toda a criptografia (RSA + AES) continua acontecendo em Python, exatamente
como no client.py / client_gui.py — a pagina so envia o texto puro para
este servidor local, que cifra/decifra e fala com o servidor de roteamento
(server.py) via socket TCP. O protocolo de seguranca do desafio nao muda;
so ganhamos mais uma interface (que funciona tanto no PC quanto no celular).

Como rodar:
    python web_client.py

No PC: a pagina abre sozinha em http://127.0.0.1:8080
No celular (mesma Wi-Fi do PC): acesse http://<IP-do-PC>:8080
Para descobrir o IP do PC no Windows: rode "ipconfig" em outro terminal e
procure "Endereco IPv4" da sua rede Wi-Fi (ex: 192.168.0.15).
"""

import json
import threading
import uuid
import webbrowser
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from client import ChatClient, HOST, PORT

WEB_PORT = 8080
COOKIE_NAME = "secure_chat_session"

# session_id -> {"client": ChatClient|None, "messages": [...], "lock": threading.Lock()}
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


def new_session():
    return {"client": None, "messages": [], "lock": threading.Lock()}


HTML_PAGE = """<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure Chat</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:16px; }
  .wrap { max-width: 480px; margin: 0 auto; }
  h1 { font-size: 1.3rem; margin: 0 0 4px; }
  .sub { color:#94a3b8; font-size:0.85rem; margin-bottom:16px; }
  .card { background:#1e293b; border-radius:12px; padding:16px; margin-bottom:14px; }
  input, button { font-size:1rem; padding:10px; border-radius:8px; border:1px solid #334155; width:100%; margin-top:6px; }
  input { background:#0f172a; color:#e2e8f0; }
  button { background:#10b981; color:#052e21; font-weight:700; border:none; margin-top:10px; cursor:pointer; }
  button.secondary { background:#334155; color:#e2e8f0; }
  label { font-size:0.85rem; color:#94a3b8; }
  #status { font-size:0.85rem; margin-top:8px; color:#f59e0b; }
  #users { display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; }
  .user-tag { background:#334155; padding:6px 12px; border-radius:20px; font-size:0.85rem; cursor:pointer; }
  .user-tag.active { background:#10b981; color:#052e21; font-weight:700; }
  #log { height: 280px; overflow-y:auto; background:#0f172a; border-radius:8px; padding:10px; font-size:0.9rem; }
  .msg-me { color:#60a5fa; margin:4px 0; }
  .msg-other { color:#34d399; margin:4px 0; }
  #chatSection { display:none; }
</style>
</head>
<body>
<div class="wrap">
  <h1>🔐 Secure Chat</h1>
  <div class="sub">RSA-2048 + AES-256-CBC | Hash SHA-256 | Sockets TCP</div>

  <div class="card" id="authSection">
    <label>Usuário</label>
    <input id="username" placeholder="ex: alice">
    <label>Senha</label>
    <input id="password" type="password" placeholder="senha">
    <button onclick="doLogin()">Entrar (Login)</button>
    <button class="secondary" onclick="doRegister()">Registrar novo usuário</button>
    <div id="status"></div>
  </div>

  <div class="card" id="chatSection">
    <div><b>Logado como:</b> <span id="meLabel"></span></div>
    <label>Usuários online (toque para escolher destinatário)</label>
    <div id="users"></div>
    <button class="secondary" onclick="refreshUsers()">Atualizar lista</button>

    <div style="margin-top:14px;">
      <label>Conversando com: <span id="targetLabel">(ninguém selecionado)</span></label>
      <div id="log"></div>
      <input id="msgInput" placeholder="Digite a mensagem...">
      <button onclick="sendMsg()">Enviar</button>
    </div>
  </div>
</div>

<script>
let target = null;
let me = null;

async function post(path, body) {
  const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body||{}), credentials:'same-origin'});
  return r.json();
}
async function get(path) {
  const r = await fetch(path, {credentials:'same-origin'});
  return r.json();
}

async function doRegister() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const res = await post('/register', {username, password});
  document.getElementById('status').innerText = res.ok ? 'Registrado! Agora clique em Entrar.' : 'Falha ao registrar (usuário já existe?).';
}

async function doLogin() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const res = await post('/login', {username, password});
  if (res.ok) {
    me = res.username;
    document.getElementById('meLabel').innerText = me;
    document.getElementById('authSection').style.display = 'none';
    document.getElementById('chatSection').style.display = 'block';
    refreshUsers();
    pollMessages();
  } else {
    document.getElementById('status').innerText = 'Usuário ou senha incorretos.';
  }
}

async function refreshUsers() {
  const res = await get('/users');
  if (!res.ok) return;
  const box = document.getElementById('users');
  box.innerHTML = '';
  res.users.forEach(u => {
    const el = document.createElement('div');
    el.className = 'user-tag' + (u === target ? ' active' : '');
    el.innerText = u;
    el.onclick = () => { target = u; document.getElementById('targetLabel').innerText = u; refreshUsers(); };
    box.appendChild(el);
  });
}

function appendLog(who, text, mine) {
  const log = document.getElementById('log');
  const div = document.createElement('div');
  div.className = mine ? 'msg-me' : 'msg-other';
  div.innerText = (mine ? 'Eu: ' : who + ': ') + text;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

async function sendMsg() {
  const input = document.getElementById('msgInput');
  const text = input.value.trim();
  if (!text) return;
  if (!target) { alert('Escolha um usuário na lista acima primeiro.'); return; }
  await post('/send', {to: target, text});
  appendLog(me, text, true);
  input.value = '';
}

async function pollMessages() {
  try {
    const res = await get('/messages');
    if (res.ok && res.messages.length) {
      res.messages.forEach(m => appendLog(m.from, m.text, false));
    }
  } catch (e) {}
  setTimeout(pollMessages, 1500);
}

document.getElementById('msgInput')?.addEventListener('keydown', e => { if (e.key === 'Enter') sendMsg(); });
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    # -----------------------------------------------------------------
    # Sessao por cookie: cada aba/navegador ganha seu proprio ChatClient
    # -----------------------------------------------------------------
    def _get_session(self):
        """Retorna (session_id, session_dict, is_new)."""
        raw_cookie = self.headers.get("Cookie")
        sid = None
        if raw_cookie:
            jar = cookies.SimpleCookie()
            jar.load(raw_cookie)
            if COOKIE_NAME in jar:
                candidate = jar[COOKIE_NAME].value
                with SESSIONS_LOCK:
                    if candidate in SESSIONS:
                        sid = candidate

        if sid:
            with SESSIONS_LOCK:
                return sid, SESSIONS[sid], False

        sid = uuid.uuid4().hex
        with SESSIONS_LOCK:
            SESSIONS[sid] = new_session()
            return sid, SESSIONS[sid], True

    def _set_session_cookie(self, sid):
        self.send_header("Set-Cookie", f"{COOKIE_NAME}={sid}; Path=/; HttpOnly")

    def _send_json(self, obj, status=200, sid=None, is_new=False):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if is_new and sid:
            self._set_session_cookie(sid)
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(body or b"{}")
        except json.JSONDecodeError:
            return {}

    def _ensure_client(self, session):
        if session["client"] is None:
            client = ChatClient(HOST, PORT)
            client.on_message = lambda sender, text, s=session: (
                s["messages"].append({"from": sender, "text": text})
            )
            session["client"] = client
        return session["client"]

    # ----------------------------------------------------------------- GET
    def do_GET(self):
        sid, session, is_new = self._get_session()

        if self.path == "/":
            html = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            if is_new:
                self._set_session_cookie(sid)
            self.end_headers()
            self.wfile.write(html)

        elif self.path == "/users":
            client = session["client"]
            if client is None:
                return self._send_json({"ok": False, "message": "Faça login primeiro."}, 400, sid, is_new)
            self._send_json({"ok": True, "users": client.list_users()}, 200, sid, is_new)

        elif self.path == "/messages":
            with session["lock"]:
                msgs = list(session["messages"])
                session["messages"].clear()
            self._send_json({"ok": True, "messages": msgs}, 200, sid, is_new)

        else:
            self.send_response(404)
            self.end_headers()

    # ---------------------------------------------------------------- POST
    def do_POST(self):
        sid, session, is_new = self._get_session()
        body = self._read_json()

        if self.path == "/register":
            client = self._ensure_client(session)
            ok = client.register(body.get("username", ""), body.get("password", ""))
            self._send_json({"ok": ok}, 200, sid, is_new)

        elif self.path == "/login":
            client = self._ensure_client(session)
            ok = client.login(body.get("username", ""), body.get("password", ""))
            if ok:
                client.setup_keys()
            self._send_json({"ok": ok, "username": client.username}, 200, sid, is_new)

        elif self.path == "/send":
            client = session["client"]
            if client is None or not client.username:
                return self._send_json({"ok": False, "message": "Faça login primeiro."}, 400, sid, is_new)
            client.send_message(body.get("to", ""), body.get("text", ""))
            self._send_json({"ok": True}, 200, sid, is_new)

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Log simplificado (evita poluir o terminal com toda requisicao HTTP)
        print(f"[WEB] {self.address_string()} - {format % args}")


def main():
    server = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), Handler)
    local_url = f"http://127.0.0.1:{WEB_PORT}"

    print(f"[WEB] Secure Chat rodando na porta {WEB_PORT}.")
    print(f"[WEB] Abrindo no navegador do PC: {local_url}")
    print(f"[WEB] De outro dispositivo na mesma Wi-Fi (ex.: celular), acesse: http://<IP-DO-SEU-PC>:{WEB_PORT}")
    print("[WEB] Para descobrir o IP do PC no Windows, rode 'ipconfig' em outro terminal.")
    print("[WEB] Cada aba/navegador vira uma sessao independente (pode abrir varias abas no PC).")

    # Abre a pagina automaticamente no navegador padrao do PC.
    threading.Timer(0.6, lambda: webbrowser.open(local_url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
