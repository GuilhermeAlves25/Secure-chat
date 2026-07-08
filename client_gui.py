"""
client_gui.py
-------------
Interface grafica (Tkinter) para o cliente do sistema de mensagens
seguras. Reaproveita toda a logica de rede/criptografia da classe
ChatClient definida em client.py — esta tela e apenas a "casca" visual
(login/registro + janela de chat com lista de usuarios online).

Usa somente a biblioteca padrao do Python (tkinter), entao nao exige
nenhuma dependencia extra alem do requirements.txt existente.

Como rodar:
    python client_gui.py
"""

import queue
import tkinter as tk
from tkinter import messagebox, scrolledtext

from client import ChatClient, HOST, PORT


# =============================================================================
# Tela de Login / Registro
# =============================================================================
class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Chat — Login")
        self.geometry("380x320")
        self.resizable(False, False)
        self.client = None

        pad = {"padx": 10, "pady": 6}

        tk.Label(self, text="Sistema de Mensagens Seguras", font=("Segoe UI", 13, "bold")).pack(pady=(18, 4))
        tk.Label(self, text="RSA + AES  |  Hash SHA-256", fg="#666").pack(pady=(0, 14))

        form = tk.Frame(self)
        form.pack(**pad)

        tk.Label(form, text="Servidor:").grid(row=0, column=0, sticky="e")
        self.host_var = tk.StringVar(value=HOST)
        tk.Entry(form, textvariable=self.host_var, width=22).grid(row=0, column=1, pady=3)

        tk.Label(form, text="Porta:").grid(row=1, column=0, sticky="e")
        self.port_var = tk.StringVar(value=str(PORT))
        tk.Entry(form, textvariable=self.port_var, width=22).grid(row=1, column=1, pady=3)

        tk.Label(form, text="Usuário:").grid(row=2, column=0, sticky="e")
        self.user_var = tk.StringVar()
        tk.Entry(form, textvariable=self.user_var, width=22).grid(row=2, column=1, pady=3)

        tk.Label(form, text="Senha:").grid(row=3, column=0, sticky="e")
        self.pass_var = tk.StringVar()
        tk.Entry(form, textvariable=self.pass_var, show="*", width=22).grid(row=3, column=1, pady=3)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=16)
        tk.Button(btn_frame, text="Entrar (Login)", width=15, command=self.do_login).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Registrar", width=15, command=self.do_register).grid(row=0, column=1, padx=5)

        self.status_var = tk.StringVar(value="")
        tk.Label(self, textvariable=self.status_var, fg="#a00").pack()

    def _connect(self):
        if self.client is not None:
            return True
        try:
            host = self.host_var.get().strip() or HOST
            port = int(self.port_var.get().strip() or PORT)
            self.client = ChatClient(host, port)
            return True
        except Exception as e:
            messagebox.showerror("Erro de conexão", f"Não foi possível conectar ao servidor:\n{e}")
            self.client = None
            return False

    def do_register(self):
        if not self._connect():
            return
        username = self.user_var.get().strip()
        password = self.pass_var.get()
        if not username or not password:
            self.status_var.set("Preencha usuário e senha.")
            return
        ok = self.client.register(username, password)
        self.status_var.set("Registrado! Agora clique em Entrar." if ok else "Falha ao registrar (usuário já existe?).")

    def do_login(self):
        if not self._connect():
            return
        username = self.user_var.get().strip()
        password = self.pass_var.get()
        if not username or not password:
            self.status_var.set("Preencha usuário e senha.")
            return

        ok = self.client.login(username, password)
        if not ok:
            self.status_var.set("Usuário ou senha incorretos.")
            return

        self.client.setup_keys()
        self.withdraw()  # esconde a janela de login
        chat = ChatWindow(self, self.client)
        chat.protocol("WM_DELETE_WINDOW", lambda: self._on_chat_close(chat))

    def _on_chat_close(self, chat_window):
        chat_window.destroy()
        self.destroy()


# =============================================================================
# Janela principal de chat
# =============================================================================
class ChatWindow(tk.Toplevel):
    def __init__(self, master, client):
        super().__init__(master)
        self.client = client
        self.title(f"Secure Chat — logado como {client.username}")
        self.geometry("700x480")

        # Fila para receber mensagens vindas da thread de rede (thread-safe)
        self.incoming_queue = queue.Queue()
        self.client.on_message = lambda sender, text: self.incoming_queue.put((sender, text))

        # Historico de conversa por usuario: {username: [(quem, texto), ...]}
        self.history = {}
        self.current_target = None

        self._build_layout()
        self.refresh_users()
        self.after(200, self._poll_incoming)

    # --------------------------------------------------------------- layout
    def _build_layout(self):
        root = tk.Frame(self)
        root.pack(fill="both", expand=True)

        # ---- painel esquerdo: usuarios online ----
        left = tk.Frame(root, width=180, bg="#f1f5f9")
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        tk.Label(left, text="Usuários online", bg="#f1f5f9", font=("Segoe UI", 10, "bold")).pack(pady=(10, 4))
        self.users_listbox = tk.Listbox(left, activestyle="dotbox")
        self.users_listbox.pack(fill="both", expand=True, padx=8, pady=4)
        self.users_listbox.bind("<<ListboxSelect>>", self._on_select_user)

        tk.Button(left, text="Atualizar lista", command=self.refresh_users).pack(pady=6, padx=8, fill="x")

        # ---- painel direito: conversa ----
        right = tk.Frame(root)
        right.pack(side="left", fill="both", expand=True)

        self.chat_title = tk.Label(right, text="Selecione um usuário para conversar",
                                    font=("Segoe UI", 10, "bold"), anchor="w")
        self.chat_title.pack(fill="x", padx=10, pady=(10, 2))

        self.chat_area = scrolledtext.ScrolledText(right, state="disabled", wrap="word")
        self.chat_area.pack(fill="both", expand=True, padx=10, pady=4)
        self.chat_area.tag_config("me", foreground="#1d4ed8")
        self.chat_area.tag_config("other", foreground="#065f46")
        self.chat_area.tag_config("info", foreground="#888")

        bottom = tk.Frame(right)
        bottom.pack(fill="x", padx=10, pady=(0, 10))

        self.msg_var = tk.StringVar()
        entry = tk.Entry(bottom, textvariable=self.msg_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda e: self.send_current_message())

        tk.Button(bottom, text="Enviar", command=self.send_current_message).pack(side="left", padx=(6, 0))

        status = tk.Label(self, text=f"Conectado como {self.client.username} — chave RSA-2048 ativa",
                           anchor="w", fg="#555")
        status.pack(fill="x", padx=10, pady=(0, 4))

    # ------------------------------------------------------------- acoes
    def refresh_users(self):
        users = self.client.list_users()
        self.users_listbox.delete(0, tk.END)
        for u in users:
            self.users_listbox.insert(tk.END, u)

    def _on_select_user(self, _event):
        sel = self.users_listbox.curselection()
        if not sel:
            return
        target = self.users_listbox.get(sel[0])
        self.current_target = target
        self.chat_title.config(text=f"Conversando com {target}  (RSA + AES-256-CBC)")
        self._render_history(target)

    def _render_history(self, target):
        self.chat_area.config(state="normal")
        self.chat_area.delete("1.0", tk.END)
        for sender, text in self.history.get(target, []):
            self._append_line(sender, text, render_only=True)
        self.chat_area.config(state="disabled")
        self.chat_area.see(tk.END)

    def _append_line(self, sender, text, render_only=False):
        self.chat_area.config(state="normal")
        if sender == self.client.username:
            self.chat_area.insert(tk.END, f"Eu: {text}\n", "me")
        elif sender == "info":
            self.chat_area.insert(tk.END, f"{text}\n", "info")
        else:
            self.chat_area.insert(tk.END, f"{sender}: {text}\n", "other")
        self.chat_area.config(state="disabled")
        self.chat_area.see(tk.END)

    def send_current_message(self):
        text = self.msg_var.get().strip()
        if not text:
            return
        if not self.current_target:
            messagebox.showinfo("Selecione um destinatário", "Escolha um usuário na lista à esquerda antes de enviar.")
            return

        self.client.send_message(self.current_target, text)

        self.history.setdefault(self.current_target, []).append((self.client.username, text))
        self._append_line(self.client.username, text)

        self.msg_var.set("")

    # --------------------------------------------------------- rede -> GUI
    def _poll_incoming(self):
        """Roda no thread principal do Tkinter (via `after`) e consome
        mensagens que chegaram na thread de rede, atualizando a tela com
        seguranca (Tkinter nao e thread-safe por si so)."""
        try:
            while True:
                sender, text = self.incoming_queue.get_nowait()
                self.history.setdefault(sender, []).append((sender, text))
                if sender == self.current_target:
                    self._append_line(sender, text)
                else:
                    self.title(f"Secure Chat — logado como {self.client.username}  (nova mensagem de {sender})")
        except queue.Empty:
            pass
        self.after(200, self._poll_incoming)


def main():
    app = LoginWindow()
    app.mainloop()


if __name__ == "__main__":
    main()
