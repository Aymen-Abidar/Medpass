import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict

from .config import DATABASE_URL, DB_BACKEND, DB_PATH
from .security import encrypt_text, hash_secret

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:
    psycopg = None
    dict_row = None

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('patient','doctor')),
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    birth_date TEXT,
    doctor_pin_hash TEXT,
    phone_number TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    must_complete_onboarding INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dossiers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER UNIQUE NOT NULL,
    blood_type TEXT,
    public_allergies_json TEXT NOT NULL DEFAULT '[]',
    public_conditions_json TEXT NOT NULL DEFAULT '[]',
    emergency_contact_name TEXT,
    emergency_contact_phone TEXT,
    emergency_instructions TEXT,
    appointments_json TEXT NOT NULL DEFAULT '[]',
    private_data_enc TEXT NOT NULL,
    is_archived INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(patient_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS doctor_patients (
    doctor_id INTEGER NOT NULL,
    patient_id INTEGER NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (doctor_id, patient_id),
    FOREIGN KEY(doctor_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(patient_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS qrcodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY(patient_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    accessed_by INTEGER,
    access_role TEXT NOT NULL,
    access_level TEXT NOT NULL,
    ip_address TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(patient_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(accessed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS email_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    purpose TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0
);
"""

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('patient','doctor')),
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    birth_date TEXT,
    doctor_pin_hash TEXT,
    phone_number TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    must_complete_onboarding INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dossiers (
    id BIGSERIAL PRIMARY KEY,
    patient_id BIGINT UNIQUE NOT NULL,
    blood_type TEXT,
    public_allergies_json TEXT NOT NULL DEFAULT '[]',
    public_conditions_json TEXT NOT NULL DEFAULT '[]',
    emergency_contact_name TEXT,
    emergency_contact_phone TEXT,
    emergency_instructions TEXT,
    appointments_json TEXT NOT NULL DEFAULT '[]',
    private_data_enc TEXT NOT NULL,
    is_archived INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CONSTRAINT fk_dossiers_patient FOREIGN KEY(patient_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS doctor_patients (
    doctor_id BIGINT NOT NULL,
    patient_id BIGINT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (doctor_id, patient_id),
    CONSTRAINT fk_dp_doctor FOREIGN KEY(doctor_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_dp_patient FOREIGN KEY(patient_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS qrcodes (
    id BIGSERIAL PRIMARY KEY,
    patient_id BIGINT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    CONSTRAINT fk_qr_patient FOREIGN KEY(patient_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS access_logs (
    id BIGSERIAL PRIMARY KEY,
    patient_id BIGINT NOT NULL,
    accessed_by BIGINT,
    access_role TEXT NOT NULL,
    access_level TEXT NOT NULL,
    ip_address TEXT,
    created_at TEXT NOT NULL,
    CONSTRAINT fk_logs_patient FOREIGN KEY(patient_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_logs_accessed_by FOREIGN KEY(accessed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS email_verifications (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    purpose TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


def is_postgres() -> bool:
    return DB_BACKEND == 'postgres'


def adapt_sql(sql: str) -> str:
    return sql.replace('?', '%s') if is_postgres() else sql


def execute(conn, sql: str, params=()):
    return conn.execute(adapt_sql(sql), params)


def _connect():
    if is_postgres():
        if psycopg is None:
            raise RuntimeError('psycopg is required when DATABASE_URL points to Postgres/Supabase.')
        return psycopg.connect(DATABASE_URL, row_factory=dict_row)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = dict_factory
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def _create_schema(conn):
    if not is_postgres():
        conn.executescript(SQLITE_SCHEMA)
        return
    for statement in [s.strip() for s in POSTGRES_SCHEMA.split(';') if s.strip()]:
        conn.execute(statement)


def _get_columns(conn, table_name: str) -> set[str]:
    if is_postgres():
        rows = execute(conn, "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ?", (table_name,)).fetchall()
        return {r['column_name'] for r in rows}
    rows = execute(conn, f'PRAGMA table_info({table_name})').fetchall()
    return {r['name'] for r in rows}


def _add_column_if_missing(conn, table_name: str, column_name: str, definition: str):
    cols = _get_columns(conn, table_name)
    if column_name not in cols:
        execute(conn, f'ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}')


def _ensure_migrations(conn):
    if not {'users', 'dossiers'}.issubset(_get_existing_tables(conn)):
        return
    _add_column_if_missing(conn, 'users', 'phone_number', 'TEXT')
    _add_column_if_missing(conn, 'users', 'email_verified', 'INTEGER NOT NULL DEFAULT 0')
    _add_column_if_missing(conn, 'users', 'must_complete_onboarding', 'INTEGER NOT NULL DEFAULT 0')
    _add_column_if_missing(conn, 'dossiers', 'appointments_json', "TEXT NOT NULL DEFAULT '[]'")


def _get_existing_tables(conn) -> set[str]:
    if is_postgres():
        rows = execute(conn, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'").fetchall()
        return {r['table_name'] for r in rows}
    rows = execute(conn, "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r['name'] for r in rows}


def insert_user(conn, *, email: str, password_hash: str, role: str, first_name: str, last_name: str,
                birth_date: str | None, doctor_pin_hash: str | None, created_at: str,
                phone_number: str | None = None, email_verified: int = 0,
                must_complete_onboarding: int = 0) -> int:
    sql = ('INSERT INTO users '
           '(email, password_hash, role, first_name, last_name, birth_date, doctor_pin_hash, phone_number, email_verified, must_complete_onboarding, created_at) '
           'VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    params = (email, password_hash, role, first_name, last_name, birth_date, doctor_pin_hash, phone_number, email_verified, must_complete_onboarding, created_at)
    if is_postgres():
        row = execute(conn, sql + ' RETURNING id', params).fetchone()
        return int(row['id'])
    execute(conn, sql, params)
    row = execute(conn, 'SELECT last_insert_rowid() as id').fetchone()
    return int(row['id'])


def seed_if_empty(conn):
    count = execute(conn, 'SELECT COUNT(*) as c FROM users').fetchone()['c']
    if count:
        return
    now = utcnow()
    doctor_id = insert_user(
        conn,
        email='doctor@medpassdemo.com',
        password_hash=hash_secret('doctor123'),
        role='doctor',
        first_name='Sara',
        last_name='Bennani',
        birth_date='1987-03-12',
        doctor_pin_hash=hash_secret('1234'),
        phone_number='+212600111111',
        email_verified=1,
        created_at=now,
    )
    patient_id = insert_user(
        conn,
        email='patient@medpassdemo.com',
        password_hash=hash_secret('patient123'),
        role='patient',
        first_name='Youssef',
        last_name='Amrani',
        birth_date='1996-09-02',
        doctor_pin_hash=None,
        phone_number='+212600000000',
        email_verified=1,
        created_at=now,
    )
    private_data = {
        'doctor_name': 'Dr. Sara Bennani',
        'doctor_rpps': 'RPPS-112233',
        'cases': [{'title': 'Suivi diabète', 'content': 'Patient diabétique de type 1. Toujours vérifier glycémie.'}],
        'notes': 'Patient diabétique de type 1. Toujours vérifier glycémie.'
    }
    execute(conn, """
        INSERT INTO dossiers (
            patient_id, blood_type, public_allergies_json, public_conditions_json,
            emergency_contact_name, emergency_contact_phone, emergency_instructions,
            appointments_json, private_data_enc, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        patient_id, 'O+', json.dumps(['Pénicilline'], ensure_ascii=False), json.dumps(['Diabète de type 1'], ensure_ascii=False),
        'Amina Amrani', '+212600000000', 'En cas de malaise, vérifier glycémie puis contacter la famille.',
        json.dumps([{'date': '2026-05-15', 'time': '10:00', 'title': 'Contrôle diabète'}], ensure_ascii=False),
        encrypt_text(json.dumps(private_data, ensure_ascii=False)), now, now,
    ))
    execute(conn, 'INSERT INTO doctor_patients (doctor_id, patient_id, created_at) VALUES (?,?,?)', (doctor_id, patient_id, now))
    token = secrets.token_urlsafe(24)
    execute(conn, 'INSERT INTO qrcodes (patient_id, token, is_active, created_at) VALUES (?,?,1,?)', (patient_id, token, now))


@contextmanager
def get_conn():
    conn = _connect()
    _create_schema(conn)
    _ensure_migrations(conn)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    conn = _connect()
    try:
        _create_schema(conn)
        _ensure_migrations(conn)
        seed_if_empty(conn)
        conn.commit()
    finally:
        conn.close()


def create_default_private_data() -> Dict[str, Any]:
    return {
        'doctor_name': '',
        'doctor_rpps': '',
        'cases': [],
        'notes': ''
    }
