"""
database.py
------------
Armazenamento simples de usuarios em um arquivo JSON local
(users.json). Guardamos apenas username -> "salt$hash" (nunca a senha
em texto claro).

Em um sistema real usariamos um banco de dados (SQLite, Postgres etc.),
mas para fins didaticos um arquivo JSON deixa claro o que esta sendo
persistido: apenas hashes.
"""

import json
import os
import threading

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")

_lock = threading.Lock()


def _load() -> dict:
    if not os.path.exists(DB_PATH):
        return {}
    with open(DB_PATH, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def _save(data: dict) -> None:
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def user_exists(username: str) -> bool:
    with _lock:
        return username in _load()


def add_user(username: str, stored_hash: str) -> None:
    with _lock:
        data = _load()
        data[username] = stored_hash
        _save(data)


def get_user_hash(username: str):
    with _lock:
        return _load().get(username)


def list_users():
    with _lock:
        return list(_load().keys())
