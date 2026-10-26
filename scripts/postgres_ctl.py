"""
Manage an isolated PostgreSQL 17 instance strictly inside securepay_lab/private/pgdata
bound only to 127.0.0.1:55432. Never modifies or touches any database or directory outside securepay_lab.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PRIVATE_DIR = BASE_DIR / "private"
PGDATA_DIR = PRIVATE_DIR / "pgdata"
PGLOG_FILE = PRIVATE_DIR / "postgres.log"
PG_BIN_DIR = Path(r"C:\Program Files\PostgreSQL\17\bin")

PG_HOST = os.environ.get("POSTGRES_HOST", "127.0.0.1")
PG_PORT = int(os.environ.get("POSTGRES_PORT", "55432"))
PG_SUPERUSER = "postgres"
PG_APP_USER = os.environ.get("POSTGRES_USER", "securepay_user")
PG_APP_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "securepay_local_dev_pw")
PG_APP_DB = os.environ.get("POSTGRES_DB", "securepay_lab")


def _bin(name: str) -> str:
    exe = PG_BIN_DIR / f"{name}.exe"
    if exe.exists():
        return str(exe)
    return name


def is_port_open(host: str = PG_HOST, port: int = PG_PORT) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        return sock.connect_ex((host, port)) == 0


def init_cluster() -> None:
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    if (PGDATA_DIR / "PG_VERSION").exists():
        print(f"[postgres_ctl] PGDATA already initialized at {PGDATA_DIR}")
        return
    print(f"[postgres_ctl] Initializing isolated PostgreSQL cluster at {PGDATA_DIR}...")
    cmd = [
        _bin("initdb"),
        "-D",
        str(PGDATA_DIR),
        "-U",
        PG_SUPERUSER,
        "-A",
        "trust",
        "-E",
        "UTF8",
        "--no-locale",
    ]
    subprocess.run(cmd, check=True)
    conf_file = PGDATA_DIR / "postgresql.conf"
    with conf_file.open("a", encoding="utf-8") as f:
        f.write(f"\nlisten_addresses = '127.0.0.1'\nport = {PG_PORT}\nmax_connections = 100\n")


def start_cluster() -> None:
    init_cluster()
    if is_port_open():
        print(f"[postgres_ctl] PostgreSQL already listening on {PG_HOST}:{PG_PORT}")
    else:
        print(f"[postgres_ctl] Starting PostgreSQL on {PG_HOST}:{PG_PORT}...")
        cmd = [
            _bin("pg_ctl"),
            "-D",
            str(PGDATA_DIR),
            "-l",
            str(PGLOG_FILE),
            "-o",
            f"-p {PG_PORT} -h 127.0.0.1",
            "start",
        ]
        subprocess.run(cmd, check=True)
        for _ in range(20):
            if is_port_open():
                break
            time.sleep(0.5)
        if not is_port_open():
            raise RuntimeError(f"PostgreSQL failed to start on {PG_HOST}:{PG_PORT}")

    ensure_role_and_db()


init_and_start = start_cluster


def ensure_role_and_db() -> None:
    import psycopg

    with psycopg.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_SUPERUSER,
        dbname="postgres",
        autocommit=True,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (PG_APP_USER,))
            if not cur.fetchone():
                cur.execute(
                    f"CREATE ROLE {PG_APP_USER} WITH LOGIN PASSWORD '{PG_APP_PASSWORD}' CREATEDB"
                )
                print(f"[postgres_ctl] Created role {PG_APP_USER} (with CREATEDB for pytest-django)")
            else:
                cur.execute(
                    f"ALTER ROLE {PG_APP_USER} WITH LOGIN PASSWORD '{PG_APP_PASSWORD}' CREATEDB"
                )

            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (PG_APP_DB,))
            if not cur.fetchone():
                cur.execute(f"CREATE DATABASE {PG_APP_DB} OWNER {PG_APP_USER}")
                print(f"[postgres_ctl] Created database {PG_APP_DB}")


def stop_cluster() -> None:
    if not (PGDATA_DIR / "PG_VERSION").exists():
        print("[postgres_ctl] Cluster not initialized.")
        return
    if not is_port_open():
        print("[postgres_ctl] Cluster is not running.")
        return
    cmd = [_bin("pg_ctl"), "-D", str(PGDATA_DIR), "stop", "-m", "fast"]
    subprocess.run(cmd, check=True)
    print("[postgres_ctl] Stopped PostgreSQL cluster.")


def status_cluster() -> None:
    print(f"[postgres_ctl] Port {PG_HOST}:{PG_PORT} open: {is_port_open()}")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "start"
    if action == "init":
        init_cluster()
    elif action == "start":
        start_cluster()
    elif action == "stop":
        stop_cluster()
    elif action == "status":
        status_cluster()
    else:
        raise SystemExit(f"Unknown action: {action}")
