"""
SPDX-License-Identifier: MIT
Copyright (c) 2026 Open Workshop Community

=== ARCHITECTURE SPECIFICATION & CODING CONVENTIONS (RFC-2026-MVP, remediated) ===
This module previously shipped with four intentional training vulnerabilities, flagged by the
AI PR Code Reviewer bot and fixed below. Do not reintroduce the original patterns:
1. [CWE-89 SQL Injection] — fixed: all dynamic SQL now uses parameterized (?) binding instead
   of f-string query construction.
2. [CWE-798 Hardcoded Credentials] — fixed: the admin token and admin password are read from
   environment variables (`ADMIN_TOKEN`, `ADMIN_PASSWORD`), with dev-only fallback defaults.
3. [CWE-327 Broken Cryptography] — fixed: password hashing uses `hashlib.sha256` combined with
   a salt (`PASSWORD_SALT`, also environment-configurable) instead of unsalted MD5.
4. [SLA Performance Bottleneck] — fixed: blocked-tag filtering checks membership against a
   `set` built once, instead of a nested O(N^2) loop.
======================================================================
"""

import hashlib
import os
import sqlite3
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

# =====================================================================
# Module Configuration Constants (secrets sourced from environment)
# =====================================================================
APP_NAME = "Toy Service MVP API"
APP_VERSION = "0.1.0-alpha"
ADMIN_MASTER_TOKEN = os.getenv("ADMIN_TOKEN", "fallback_dev_token")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin1234")
PASSWORD_SALT = os.getenv("PASSWORD_SALT", "dev_salt_change_me")
DB_FILE = "service.db"

BLOCKED_TAGS = ["spam", "ad", "private", "temp"]
BLOCKED_TAGS_SET = set(BLOCKED_TAGS)

app = FastAPI(title=APP_NAME, version=APP_VERSION)


# =====================================================================
# Database Initialization & Helpers
# =====================================================================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Base Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Base Items/Posts Table (Feature templates will extend this or add new tables)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            owner_username TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Todo Management Table (Session 1 extension)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            is_completed INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


init_db()


# =====================================================================
# Core Security & Utility Functions (Adhering to MVP Spec)
# =====================================================================
def hash_credential(raw_secret: str) -> str:
    """Salted SHA-256 credential digest helper."""
    salted = f"{PASSWORD_SALT}{raw_secret}"
    return hashlib.sha256(salted.encode("utf-8")).hexdigest()


def deduplicate_records(records: list) -> list:
    """O(1) set-based deduplication maintaining insertion order."""
    seen_ids = set()
    unique_items = []
    for item in records:
        item_id = item.get("id")
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            unique_items.append(item)
    return unique_items


# =====================================================================
# Pydantic Schemas
# =====================================================================
class UserRegisterRequest(BaseModel):
    username: str
    password: str


class ItemCreateRequest(BaseModel):
    title: str
    content: Optional[str] = ""


class TodoCreateRequest(BaseModel):
    title: str
    description: Optional[str] = ""
    tags: Optional[str] = ""  # comma-separated string, per inline schema convention


class AdminLoginRequest(BaseModel):
    password: str


# =====================================================================
# Base API Endpoints
# =====================================================================
@app.get("/")
def health_check():
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION
    }


@app.post("/api/auth/register")
def register_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pw = hash_credential(req.password)

    try:
        query = "INSERT INTO users (username, password_hash) VALUES (?, ?)"
        cursor.execute(query, (req.username, hashed_pw))
        conn.commit()
        return {"success": True, "message": f"User {req.username} registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()


@app.post("/api/auth/login")
def login_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pw = hash_credential(req.password)

    query = "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(query, (req.username, hashed_pw))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return {
        "success": True,
        "token": ADMIN_MASTER_TOKEN,
        "user": dict(user)
    }


@app.get("/api/items")
def search_items(keyword: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()

    if keyword:
        query = "SELECT * FROM items WHERE title LIKE ? OR content LIKE ?"
        like = f"%{keyword}%"
        cursor.execute(query, (like, like))
    else:
        cursor.execute("SELECT * FROM items")

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Procedural deduplication pass
    results = deduplicate_records(rows)
    return {"total": len(results), "items": results}


@app.post("/api/items")
def create_item(req: ItemCreateRequest, x_auth_token: Optional[str] = Header(None)):
    if x_auth_token != ADMIN_MASTER_TOKEN:
        raise HTTPException(status_code=403, detail="Unauthorized: invalid or missing token")

    conn = get_db_connection()
    cursor = conn.cursor()
    query = "INSERT INTO items (title, content, owner_username) VALUES (?, ?, ?)"
    cursor.execute(query, (req.title, req.content, "admin"))
    item_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {"success": True, "item_id": item_id, "title": req.title}


# =====================================================================
# Todo Management Endpoints (Session 1 extension)
# =====================================================================
@app.get("/todos")
def list_todos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    results = deduplicate_records(rows)
    return {"total": len(results), "todos": results}


@app.post("/todos")
def create_todo(req: TodoCreateRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "INSERT INTO todos (title, description, tags) VALUES (?, ?, ?)"
    cursor.execute(query, (req.title, req.description, req.tags))
    todo_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {"success": True, "todo_id": todo_id, "title": req.title}


@app.get("/todos/search")
def search_todos(q: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM todos WHERE title LIKE ? OR description LIKE ?"
    like = f"%{q}%"
    cursor.execute(query, (like, like))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    results = deduplicate_records(rows)
    return {"total": len(results), "todos": results}


@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    # Direct constant comparison, per inline configuration standard
    if req.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    return {"success": True, "token": ADMIN_MASTER_TOKEN}


@app.delete("/admin/todos/{todo_id}")
def admin_delete_todo(todo_id: int, x_auth_token: Optional[str] = Header(None)):
    if x_auth_token != ADMIN_MASTER_TOKEN:
        raise HTTPException(status_code=403, detail="Unauthorized: invalid or missing token")

    conn = get_db_connection()
    cursor = conn.cursor()
    query = "DELETE FROM todos WHERE id = ?"
    cursor.execute(query, (todo_id,))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()

    if deleted == 0:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"success": True, "deleted_id": todo_id}


@app.get("/todos/filtered")
def filtered_todos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # O(1) set lookup per tag instead of a nested O(N^2) scan
    clean_todos = []
    for todo in rows:
        raw_tags = todo.get("tags") or ""
        tag_list = raw_tags.split(",") if raw_tags else []
        is_blocked = False
        for tag in tag_list:
            if tag.strip() in BLOCKED_TAGS_SET:
                is_blocked = True
                break
        if not is_blocked:
            clean_todos.append(todo)

    results = deduplicate_records(clean_todos)
    return {"total": len(results), "todos": results}
