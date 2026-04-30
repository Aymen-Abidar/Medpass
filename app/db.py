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
except Exception:  # pragma: no cover - optional in local sqlite dev
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
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        return conn
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



def insert_user(conn, *, email: str, password_hash: str, role: str, first_name: str, last_name: str, birth_date: str | None, doctor_pin_hash: str | None, created_at: str) -> int:
    sql = 'INSERT INTO users (email, password_hash, role, first_name, last_name, birth_date, doctor_pin_hash, created_at) VALUES (?,?,?,?,?,?,?,?)'
    params = (email, password_hash, role, first_name, last_name, birth_date, doctor_pin_hash, created_at)
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
        created_at=now,
    )

    private_data = {
        'doctor_name': 'Dr. Sara Bennani',
        'doctor_rpps': 'RPPS-112233',
        'treatments': [{'name': 'Insuline', 'dosage': '10 UI', 'frequency': 'Matin et soir'}],
        'antecedents': ['Appendicectomie 2018'],
        'vaccinations': [{'name': 'Tétanos', 'date': '2024-05-11'}],
        'ordonnances': [{'title': 'Suivi diabète', 'date': '2026-04-01'}],
        'imc': '24.3',
        'blood_pressure': '12/8',
        'notes': 'Patient diabétique de type 1. Toujours vérifier glycémie.'
    }
    execute(
        conn,
        """
        INSERT INTO dossiers (
            patient_id, blood_type, public_allergies_json, public_conditions_json,
            emergency_contact_name, emergency_contact_phone, emergency_instructions,
            private_data_enc, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            patient_id,
            'O+',
            json.dumps(['Pénicilline'], ensure_ascii=False),
            json.dumps(['Diabète de type 1'], ensure_ascii=False),
            'Amina Amrani',
            '+212600000000',
            'En cas de malaise, vérifier glycémie puis contacter la famille.',
            encrypt_text(json.dumps(private_data, ensure_ascii=False)),
            now,
            now,
        ),
    )
    execute(conn, 'INSERT INTO doctor_patients (doctor_id, patient_id, created_at) VALUES (?,?,?)', (doctor_id, patient_id, now))
    token = secrets.token_urlsafe(24)
    execute(conn, 'INSERT INTO qrcodes (patient_id, token, is_active, created_at) VALUES (?,?,1,?)', (patient_id, token, now))


@contextmanager
def get_conn():
    conn = _connect()
    _create_schema(conn)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()



def init_db():
    conn = _connect()
    try:
        _create_schema(conn)
        seed_if_empty(conn)
        conn.commit()
    finally:
        conn.close()



def create_default_private_data() -> Dict[str, Any]:
    return {
        'doctor_name': '',
        'doctor_rpps': '',
        'treatments': [],
        'antecedents': [],
        'vaccinations': [],
        'ordonnances': [],
        'imc': '',
        'blood_pressure': '',
        'notes': ''
    }
