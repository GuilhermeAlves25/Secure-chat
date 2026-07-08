"""
client.py
---------
Cliente de linha de comando do sistema de mensagens seguras.

Fluxo:
1. Conecta ao servidor via TCP.
2. Usuario registra-se ou faz login (senha nunca sai em texto claro do
   ponto de vista de armazenamento: o servidor guarda apenas o hash).
3. Apos autenticar, o cliente gera seu proprio par de chaves RSA-2048
   e envia a chave PUBLICA ao servidor (a privada nunca sai da maquina).
4. Para conversar com outro usuario, o cliente pede ao servidor a chave
   publica do destinatario.
5. Ao enviar uma mensagem:
   a. Gera uma chave AES-256 aleatoria (nova a cada mensagem).
   b. Criptografa a mensagem com AES-256-CBC.
   c. Criptografa a chave AES com a chave publica RSA do destinatario.
   d. Envia tudo (mensagem cifrada + chave cifrada + IV) ao servidor,
      que apenas roteia para o destinatario.
6. Ao receber, decifra a chave AES com sua chave privada RSA e depois
   decifra a mensagem com essa chave AES.
"""

import socket
import threading
import json
import queue
import sys

import crypto_utils as cu

HOST = "127.0.0.1"
PORT = 5050


def send_json(sock: socket.socket, obj: dict) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def recv_lines(sock: socket.socket):
    buffer = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if line.strip():
                try:
                    yield json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    continue


class ChatClient:
    def __init__(self, host: str, port: int):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.username = None
        self.private_key = None
        self.public_key = None
        self.response_queue = queue.Queue()

        # Callback opcional usado pela interface grafica (client_gui.py):
        # on_message(sender: str, plaintext: str) -> None
        self.on_message = None

        self._listener_thread = threading.Thread(target=self._listen, daemon=True)
        self._listener_thread.start()

    # ---------------------------------------------------------------
    # Thread de escuta: mensagens de chat sao tratadas na hora,
    # respostas a comandos vao para a fila (response_queue).
    # ---------------------------------------------------------------
    def _listen(self):
        try:
            for msg in recv_lines(self.sock):
                if msg.get("type") == "message":
                    self._handle_incoming_message(msg)
                else:
                    self.response_queue.put(msg)
        except OSError:
            pass

    def _handle_incoming_message(self, msg):
        sender = msg.get("from")
        try:
            enc_key = cu.unb64(msg["enc_key"])
            iv = cu.unb64(msg["iv"])
            ciphertext = cu.unb64(msg["ciphertext"])

            # 1) Decifra a chave AES usando NOSSA chave privada RSA
            aes_key = cu.rsa_decrypt(self.private_key, enc_key)
            # 2) Usa a chave AES para decifrar a mensagem
            plaintext = cu.aes_decrypt(aes_key, iv, ciphertext)
            text = plaintext.decode("utf-8")

            if self.on_message:
                # Interface grafica trata a exibicao (thread-safe via queue).
                self.on_message(sender, text)
            else:
                print(f"\n[{sender}] {text}")
                print("> ", end="", flush=True)
        except Exception as e:
            if self.on_message:
                self.on_message(sender, f"[!] Erro ao decifrar mensagem: {e}")
            else:
                print(f"\n[!] Erro ao decifrar mensagem de {sender}: {e}")
                print("> ", end="", flush=True)

    def _request(self, payload, timeout=10.0):
        send_json(self.sock, payload)
        try:
            return self.response_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    # ---------------------------------------------------------------
    # Autenticacao
    # ---------------------------------------------------------------
    def register(self, username, password):
        resp = self._request({"type": "register", "username": username, "password": password})
        if not resp:
            print("[!] Sem resposta do servidor.")
            return False
        print(f"[Servidor] {resp.get('message')}")
        return resp.get("ok", False)

    def login(self, username, password):
        resp = self._request({"type": "login", "username": username, "password": password})
        if not resp:
            print("[!] Sem resposta do servidor.")
            return False
        print(f"[Servidor] {resp.get('message')}")
        if resp.get("ok"):
            self.username = username
            return True
        return False

    # ---------------------------------------------------------------
    # Troca de chaves RSA
    # ---------------------------------------------------------------
    def setup_keys(self):
        print("[*] Gerando par de chaves RSA-2048...")
        self.private_key, self.public_key = cu.generate_rsa_keypair()
        pem = cu.serialize_public_key(self.public_key)
        resp = self._request({"type": "pubkey", "key": pem.decode("utf-8")})
        if resp and resp.get("ok"):
            print("[*] Chave publica enviada ao servidor.")

    def list_users(self):
        resp = self._request({"type": "list_users"})
        return resp.get("users", []) if resp else []

    def get_peer_public_key(self, target):
        resp = self._request({"type": "get_pubkey", "target": target})
        if resp and resp.get("ok"):
            return cu.load_public_key(resp["key"].encode("utf-8"))
        print(f"[!] {resp.get('message') if resp else 'Sem resposta.'}")
        return None

    # ---------------------------------------------------------------
    # Envio de mensagens (criptografia hibrida RSA + AES)
    # ---------------------------------------------------------------
    def send_message(self, target, text):
        peer_pubkey = self.get_peer_public_key(target)
        if peer_pubkey is None:
            return

        aes_key = cu.generate_aes_key()
        iv, ciphertext = cu.aes_encrypt(aes_key, text.encode("utf-8"))
        enc_key = cu.rsa_encrypt(peer_pubkey, aes_key)

        payload = {
            "type": "message",
            "to": target,
            "enc_key": cu.b64(enc_key),
            "iv": cu.b64(iv),
            "ciphertext": cu.b64(ciphertext),
        }
        resp = self._request(payload)
        if resp and resp.get("ok"):
            print("[*] Mensagem enviada com sucesso (AES-256-CBC + RSA-OAEP).")
        else:
            print(f"[!] Falha ao enviar: {resp.get('message') if resp else 'sem resposta'}")


def prompt(text):
    return input(text).strip()


def main():
    print("=== Cliente - Sistema de Mensagens Seguras ===")
    host = prompt(f"Servidor [{HOST}]: ") or HOST
    port_str = prompt(f"Porta [{PORT}]: ") or str(PORT)

    client = ChatClient(host, int(port_str))

    # ----- Autenticacao -----
    while client.username is None:
        print("\n1) Login\n2) Registrar\n3) Sair")
        choice = prompt("> ")
        username = prompt("Usuario: ")
        password = prompt("Senha: ")

        if choice == "1":
            client.login(username, password)
        elif choice == "2":
            client.register(username, password)
        elif choice == "3":
            sys.exit(0)

    # ----- Geracao/envio de chave RSA -----
    client.setup_keys()

    print(f"\nBem-vindo(a), {client.username}! Digite /ajuda para ver os comandos.\n")

    target = None
    while True:
        try:
            line = input("> ")
        except (EOFError, KeyboardInterrupt):
            break

        if line == "/ajuda":
            print("/usuarios         - lista usuarios online")
            print("/falarcom <nome>  - define o destinatario atual")
            print("/sair             - encerra o cliente")
            print("(qualquer outro texto e enviado ao destinatario atual)")
        elif line == "/usuarios":
            users = client.list_users()
            print("Usuarios online:", ", ".join(users) if users else "(nenhum)")
        elif line.startswith("/falarcom "):
            target = line.split(" ", 1)[1].strip()
            print(f"[*] Destinatario definido: {target}")
        elif line == "/sair":
            break
        else:
            if not target:
                print("[!] Defina um destinatario primeiro com /falarcom <nome>")
                continue
            if line.strip():
                client.send_message(target, line)

    client.sock.close()


if __name__ == "__main__":
    main()
