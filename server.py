"""
server.py
---------
Servidor de roteamento do sistema de mensagens seguras.

Responsabilidades do servidor (NAO le o conteudo das mensagens):
1. Autenticar usuarios (registro/login) comparando hashes (auth.py + database.py).
2. Guardar a chave publica RSA de cada cliente conectado.
3. Rotear chaves publicas entre os clientes (troca de chaves).
4. Rotear mensagens ja criptografadas (AES) e a chave AES ja criptografada
   (RSA) entre remetente e destinatario, sem nunca ter acesso as chaves
   privadas nem ao conteudo em texto claro.

Protocolo: mensagens JSON, uma por linha (delimitadas por '\\n'), via TCP.
"""

import socket
import threading
import json
import sys

import auth
import database

HOST = "0.0.0.0"
PORT = 5050

# username -> {"conn": socket, "pubkey": str(PEM em base64/texto)}
clients = {}
clients_lock = threading.Lock()


def log(msg: str) -> None:
    print(f"[SERVIDOR] {msg}")


def send_json(conn: socket.socket, obj: dict) -> None:
    data = (json.dumps(obj) + "\n").encode("utf-8")
    conn.sendall(data)


def recv_lines(conn: socket.socket):
    """Generator que le do socket e produz uma mensagem JSON por vez."""
    buffer = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if line.strip():
                try:
                    yield json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    log("Mensagem invalida recebida (JSON malformado). Ignorando.")


def handle_client(conn: socket.socket, addr) -> None:
    username = None
    log(f"Nova conexao de {addr}")

    try:
        for msg in recv_lines(conn):
            msg_type = msg.get("type")

            # ---------------- REGISTRO ----------------
            if msg_type == "register":
                uname = msg.get("username", "").strip()
                pwd = msg.get("password", "")

                if not uname or not pwd:
                    send_json(conn, {"type": "register_result", "ok": False,
                                      "message": "Usuario/senha invalidos."})
                elif database.user_exists(uname):
                    send_json(conn, {"type": "register_result", "ok": False,
                                      "message": "Usuario ja existe."})
                else:
                    stored_hash = auth.hash_password(pwd)
                    database.add_user(uname, stored_hash)
                    log(f"Usuario registrado: {uname} (hash={stored_hash[:20]}...)")
                    send_json(conn, {"type": "register_result", "ok": True,
                                      "message": "Registrado com sucesso."})

            # ---------------- LOGIN ----------------
            elif msg_type == "login":
                uname = msg.get("username", "").strip()
                pwd = msg.get("password", "")
                stored_hash = database.get_user_hash(uname)

                if stored_hash and auth.verify_password(pwd, stored_hash):
                    with clients_lock:
                        if uname in clients:
                            send_json(conn, {"type": "login_result", "ok": False,
                                              "message": "Usuario ja esta logado."})
                            continue
                        clients[uname] = {"conn": conn, "pubkey": None}
                    username = uname
                    log(f"Login bem-sucedido: {uname}")
                    send_json(conn, {"type": "login_result", "ok": True,
                                      "message": "Login efetuado."})
                else:
                    log(f"Falha de login para usuario '{uname}'")
                    send_json(conn, {"type": "login_result", "ok": False,
                                      "message": "Usuario ou senha incorretos."})

            # ---------------- ENVIO DE CHAVE PUBLICA ----------------
            elif msg_type == "pubkey":
                if username is None:
                    continue
                with clients_lock:
                    clients[username]["pubkey"] = msg.get("key")
                log(f"Chave publica RSA recebida de {username}")
                send_json(conn, {"type": "pubkey_ack", "ok": True})

            # ---------------- LISTAR USUARIOS ONLINE ----------------
            elif msg_type == "list_users":
                with clients_lock:
                    online = [u for u in clients if u != username]
                send_json(conn, {"type": "list_users_result", "users": online})

            # ---------------- PEDIR CHAVE PUBLICA DE OUTRO USUARIO ----------------
            elif msg_type == "get_pubkey":
                target = msg.get("target")
                with clients_lock:
                    target_info = clients.get(target)
                if target_info and target_info["pubkey"]:
                    send_json(conn, {"type": "pubkey_result", "ok": True,
                                      "target": target, "key": target_info["pubkey"]})
                else:
                    send_json(conn, {"type": "pubkey_result", "ok": False,
                                      "target": target,
                                      "message": "Usuario offline ou sem chave publica."})

            # ---------------- ENVIO DE MENSAGEM CRIPTOGRAFADA ----------------
            elif msg_type == "message":
                target = msg.get("to")
                with clients_lock:
                    target_info = clients.get(target)

                if not target_info:
                    send_json(conn, {"type": "message_sent", "ok": False,
                                      "message": f"Usuario '{target}' offline."})
                    continue

                # O servidor apenas repassa os dados JA criptografados.
                # Ele nunca ve a mensagem em texto claro nem a chave AES em claro.
                forward = {
                    "type": "message",
                    "from": username,
                    "enc_key": msg.get("enc_key"),   # chave AES cifrada com RSA
                    "iv": msg.get("iv"),
                    "ciphertext": msg.get("ciphertext"),
                }
                send_json(target_info["conn"], forward)
                log(f"Mensagem roteada: {username} -> {target} "
                    f"({len(msg.get('ciphertext',''))} bytes cifrados em base64)")
                send_json(conn, {"type": "message_sent", "ok": True})

            else:
                send_json(conn, {"type": "error", "message": "Tipo de mensagem desconhecido."})

    except ConnectionResetError:
        pass
    finally:
        if username:
            with clients_lock:
                clients.pop(username, None)
            log(f"Usuario desconectado: {username}")
        conn.close()


def main() -> None:
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen()
    log(f"Servidor escutando em {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("Encerrando servidor...")
        server_sock.close()
        sys.exit(0)


if __name__ == "__main__":
    main()
