import base64
import json
import secrets
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Optional

import qrcode
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import APP_NAME
from .db import create_default_private_data, execute, get_conn, init_db, insert_user, utcnow
from .schemas import (
    ArrayItemPayload,
    CreatePatientPayload,
    DoctorPinPayload,
    DossierUpdatePayload,
    LoginPayload,
    RegisterPayload,
)
from .security import create_token, decode_token, decrypt_text, encrypt_text, hash_secret, verify_secret

app = FastAPI(title=APP_NAME)

init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / 'public'
if not STATIC_DIR.exists():
    STATIC_DIR = BASE_DIR / 'static'


def json_loads_safe(value: str, fallback: Any):
    try:
        return json.loads(value or '')
    except Exception:
        return fallback


def get_current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='Authentification requise.')
    token = authorization.split(' ', 1)[1]
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail='Token invalide ou expiré.')
    with get_conn() as conn:
        user = execute(conn, 'SELECT * FROM users WHERE id = ?', (payload['id'],)).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail='Utilisateur introuvable.')
        return user


def require_role(expected: str):
    def dependency(user=Depends(get_current_user)):
        if user['role'] != expected:
            raise HTTPException(status_code=403, detail='Accès refusé.')
        return user
    return dependency


def require_doctor_pin(user: Dict[str, Any], x_doctor_pin: Optional[str]):
    if user['role'] != 'doctor':
        raise HTTPException(status_code=403, detail='Accès médecin requis.')
    if not x_doctor_pin:
        raise HTTPException(status_code=403, detail='PIN médecin requis.')
    if not user.get('doctor_pin_hash') or not verify_secret(x_doctor_pin, user['doctor_pin_hash']):
        raise HTTPException(status_code=403, detail='PIN médecin invalide.')


def serialize_dossier(user: Dict[str, Any], dossier: Dict[str, Any], *, include_private: bool):
    payload = {
        'patient_id': user['id'],
        'email': user['email'],
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'birth_date': user['birth_date'],
        'blood_type': dossier.get('blood_type') or '',
        'public_allergies': json_loads_safe(dossier.get('public_allergies_json'), []),
        'public_conditions': json_loads_safe(dossier.get('public_conditions_json'), []),
        'emergency_contact_name': dossier.get('emergency_contact_name') or '',
        'emergency_contact_phone': dossier.get('emergency_contact_phone') or '',
        'emergency_instructions': dossier.get('emergency_instructions') or '',
        'updated_at': dossier.get('updated_at'),
        'is_archived': bool(dossier.get('is_archived')),
    }
    if include_private:
        payload['private_data'] = json_loads_safe(decrypt_text(dossier.get('private_data_enc') or ''), create_default_private_data())
    return payload


def log_access(patient_id: int, accessed_by: Optional[int], access_role: str, access_level: str, ip_address: Optional[str]):
    with get_conn() as conn:
        execute(
            conn,
            'INSERT INTO access_logs (patient_id, accessed_by, access_role, access_level, ip_address, created_at) VALUES (?,?,?,?,?,?)',
            (patient_id, accessed_by, access_role, access_level, ip_address, utcnow()),
        )


@app.on_event('startup')
def startup_event():
    init_db()


@app.get('/health')
def health():
    return {'ok': True, 'app': APP_NAME}


@app.post('/api/auth/register')
def register(payload: RegisterPayload):
    role = payload.role.lower().strip()
    if role not in {'patient', 'doctor'}:
        raise HTTPException(status_code=400, detail='Rôle invalide.')
    if role == 'doctor' and (not payload.doctor_pin or len(payload.doctor_pin) != 4 or not payload.doctor_pin.isdigit()):
        raise HTTPException(status_code=400, detail='Le médecin doit définir un PIN à 4 chiffres.')

    with get_conn() as conn:
        existing = execute(conn, 'SELECT id FROM users WHERE email = ?', (payload.email.lower(),)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail='Cet e-mail existe déjà.')

        user_id = insert_user(
            conn,
            email=payload.email.lower(),
            password_hash=hash_secret(payload.password),
            role=role,
            first_name=payload.first_name.strip(),
            last_name=payload.last_name.strip(),
            birth_date=payload.birth_date,
            doctor_pin_hash=hash_secret(payload.doctor_pin) if payload.doctor_pin else None,
            created_at=utcnow(),
        )
        if role == 'patient':
            execute(conn,
                """
                INSERT INTO dossiers (
                    patient_id, blood_type, public_allergies_json, public_conditions_json,
                    emergency_contact_name, emergency_contact_phone, emergency_instructions,
                    private_data_enc, created_at, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (user_id, '', '[]', '[]', '', '', '', encrypt_text(json.dumps(create_default_private_data())), utcnow(), utcnow()),
            )
            token = secrets.token_urlsafe(24)
            execute(conn,'INSERT INTO qrcodes (patient_id, token, is_active, created_at) VALUES (?,?,1,?)', (user_id, token, utcnow()))

        user = execute(conn, 'SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    token = create_token({'id': user['id'], 'role': user['role'], 'email': user['email']})
    return {'token': token, 'user': {'id': user['id'], 'role': user['role'], 'email': user['email'], 'first_name': user['first_name'], 'last_name': user['last_name']}}


@app.post('/api/auth/login')
def login(payload: LoginPayload):
    with get_conn() as conn:
        user = execute(conn, 'SELECT * FROM users WHERE email = ?', (payload.email.lower(),)).fetchone()
        if not user or not verify_secret(payload.password, user['password_hash']):
            raise HTTPException(status_code=401, detail='E-mail ou mot de passe incorrect.')
    token = create_token({'id': user['id'], 'role': user['role'], 'email': user['email']})
    return {'token': token, 'user': {'id': user['id'], 'role': user['role'], 'email': user['email'], 'first_name': user['first_name'], 'last_name': user['last_name']}}


@app.get('/api/auth/me')
def me(user=Depends(get_current_user)):
    return {'id': user['id'], 'role': user['role'], 'email': user['email'], 'first_name': user['first_name'], 'last_name': user['last_name'], 'birth_date': user['birth_date']}


@app.post('/api/doctor/verify-pin')
def verify_doctor_pin(payload: DoctorPinPayload, user=Depends(require_role('doctor'))):
    require_doctor_pin(user, payload.pin)
    return {'ok': True}


@app.get('/api/dossier/mon-dossier')
def get_my_dossier(user=Depends(require_role('patient'))):
    with get_conn() as conn:
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (user['id'],)).fetchone()
        if not dossier:
            raise HTTPException(status_code=404, detail='Dossier introuvable.')
    return serialize_dossier(user, dossier, include_private=True)


@app.put('/api/dossier/mon-dossier')
def update_my_dossier(payload: DossierUpdatePayload, user=Depends(require_role('patient'))):
    with get_conn() as conn:
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (user['id'],)).fetchone()
        if not dossier:
            raise HTTPException(status_code=404, detail='Dossier introuvable.')
        private_data = json_loads_safe(decrypt_text(dossier['private_data_enc']), create_default_private_data())
        if payload.private_data is not None:
            private_data.update(payload.private_data)
        execute(conn,
            """
            UPDATE dossiers SET blood_type = ?, public_allergies_json = ?, public_conditions_json = ?,
            emergency_contact_name = ?, emergency_contact_phone = ?, emergency_instructions = ?,
            private_data_enc = ?, updated_at = ? WHERE patient_id = ?
            """,
            (
                payload.blood_type if payload.blood_type is not None else dossier['blood_type'],
                json.dumps(payload.public_allergies if payload.public_allergies is not None else json_loads_safe(dossier['public_allergies_json'], []), ensure_ascii=False),
                json.dumps(payload.public_conditions if payload.public_conditions is not None else json_loads_safe(dossier['public_conditions_json'], []), ensure_ascii=False),
                payload.emergency_contact_name if payload.emergency_contact_name is not None else dossier['emergency_contact_name'],
                payload.emergency_contact_phone if payload.emergency_contact_phone is not None else dossier['emergency_contact_phone'],
                payload.emergency_instructions if payload.emergency_instructions is not None else dossier['emergency_instructions'],
                encrypt_text(json.dumps(private_data, ensure_ascii=False)),
                utcnow(),
                user['id'],
            ),
        )
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (user['id'],)).fetchone()
    return serialize_dossier(user, dossier, include_private=True)


@app.get('/api/dossier/logs')
def get_logs(user=Depends(require_role('patient'))):
    with get_conn() as conn:
        logs = execute(conn,
            """
            SELECT access_logs.*, users.first_name, users.last_name
            FROM access_logs
            LEFT JOIN users ON users.id = access_logs.accessed_by
            WHERE patient_id = ?
            ORDER BY created_at DESC
            LIMIT 50
            """,
            (user['id'],),
        ).fetchall()
    return {'items': logs}


@app.get('/api/qrcode/generate')
def generate_qrcode(request: Request, user=Depends(require_role('patient'))):
    with get_conn() as conn:
        row = execute(conn, 'SELECT * FROM qrcodes WHERE patient_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1', (user['id'],)).fetchone()
        if not row:
            token = secrets.token_urlsafe(24)
            execute(conn,'INSERT INTO qrcodes (patient_id, token, is_active, created_at) VALUES (?,?,1,?)', (user['id'], token, utcnow()))
            row = execute(conn, 'SELECT * FROM qrcodes WHERE patient_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1', (user['id'],)).fetchone()
    public_url = str(request.base_url).rstrip('/') + f'/emergency.html?token={row["token"]}'
    img = qrcode.make(public_url)
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    image_b64 = 'data:image/png;base64,' + base64.b64encode(buffer.getvalue()).decode('utf-8')
    return {'token': row['token'], 'public_url': public_url, 'image': image_b64}


@app.post('/api/qrcode/regenerate')
def regenerate_qrcode(user=Depends(require_role('patient'))):
    token = secrets.token_urlsafe(24)
    with get_conn() as conn:
        execute(conn, 'UPDATE qrcodes SET is_active = 0 WHERE patient_id = ?', (user['id'],))
        execute(conn, 'INSERT INTO qrcodes (patient_id, token, is_active, created_at) VALUES (?,?,1,?)', (user['id'], token, utcnow()))
    return {'ok': True, 'token': token}


@app.get('/api/qrcode/verify/{token}')
def verify_qr(token: str):
    with get_conn() as conn:
        row = execute(conn, 'SELECT * FROM qrcodes WHERE token = ? AND is_active = 1', (token,)).fetchone()
        return {'valid': bool(row), 'patient_id': row['patient_id'] if row else None}


@app.get('/api/dossier/public/{token}')
def public_dossier(token: str, request: Request):
    with get_conn() as conn:
        qr = execute(conn, 'SELECT * FROM qrcodes WHERE token = ? AND is_active = 1', (token,)).fetchone()
        if not qr:
            raise HTTPException(status_code=404, detail='QR Code invalide ou révoqué.')
        user = execute(conn, "SELECT * FROM users WHERE id = ? AND role = 'patient'", (qr['patient_id'],)).fetchone()
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (qr['patient_id'],)).fetchone()
        if not user or not dossier or dossier.get('is_archived'):
            raise HTTPException(status_code=404, detail='Patient introuvable.')
    log_access(user['id'], None, 'secours', 'public', request.client.host if request.client else None)
    data = serialize_dossier(user, dossier, include_private=False)
    data['medpass_id'] = f'PMU-{user["id"]:05d}'
    return data


@app.get('/api/patients')
def list_patients(user=Depends(require_role('doctor'))):
    with get_conn() as conn:
        rows = execute(conn,
            """
            SELECT u.id, u.email, u.first_name, u.last_name, u.birth_date,
                   d.blood_type, d.public_allergies_json, d.public_conditions_json, d.updated_at, d.is_archived
            FROM doctor_patients dp
            JOIN users u ON u.id = dp.patient_id
            JOIN dossiers d ON d.patient_id = u.id
            WHERE dp.doctor_id = ?
            ORDER BY u.first_name, u.last_name
            """,
            (user['id'],),
        ).fetchall()
    for row in rows:
        row['public_allergies'] = json_loads_safe(row.pop('public_allergies_json'), [])
        row['public_conditions'] = json_loads_safe(row.pop('public_conditions_json'), [])
        row['is_archived'] = bool(row['is_archived'])
    return {'items': rows}


@app.post('/api/patients')
def create_patient(payload: CreatePatientPayload, doctor=Depends(require_role('doctor'))):
    with get_conn() as conn:
        existing = execute(conn, 'SELECT id FROM users WHERE email = ?', (payload.email.lower(),)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail='Cet e-mail existe déjà.')
        now = utcnow()
        patient_id = insert_user(
            conn,
            email=payload.email.lower(),
            password_hash=hash_secret(payload.password),
            role='patient',
            first_name=payload.first_name.strip(),
            last_name=payload.last_name.strip(),
            birth_date=payload.birth_date,
            doctor_pin_hash=None,
            created_at=now,
        )
        private_data = create_default_private_data()
        private_data.update(payload.private_data)
        execute(conn,
            """
            INSERT INTO dossiers (
                patient_id, blood_type, public_allergies_json, public_conditions_json,
                emergency_contact_name, emergency_contact_phone, emergency_instructions,
                private_data_enc, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                patient_id, payload.blood_type or '', json.dumps(payload.public_allergies, ensure_ascii=False),
                json.dumps(payload.public_conditions, ensure_ascii=False), payload.emergency_contact_name or '',
                payload.emergency_contact_phone or '', payload.emergency_instructions or '',
                encrypt_text(json.dumps(private_data, ensure_ascii=False)), now, now,
            ),
        )
        execute(conn, 'INSERT INTO doctor_patients (doctor_id, patient_id, created_at) VALUES (?,?,?)', (doctor['id'], patient_id, now))
        token = secrets.token_urlsafe(24)
        execute(conn, 'INSERT INTO qrcodes (patient_id, token, is_active, created_at) VALUES (?,?,1,?)', (patient_id, token, now))
        patient = execute(conn, 'SELECT * FROM users WHERE id = ?', (patient_id,)).fetchone()
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (patient_id,)).fetchone()
    return serialize_dossier(patient, dossier, include_private=True)


@app.get('/api/patients/{patient_id}')
def doctor_get_patient(patient_id: int, request: Request, x_doctor_pin: Optional[str] = Header(default=None), doctor=Depends(require_role('doctor'))):
    require_doctor_pin(doctor, x_doctor_pin)
    with get_conn() as conn:
        link = execute(conn, 'SELECT * FROM doctor_patients WHERE doctor_id = ? AND patient_id = ?', (doctor['id'], patient_id)).fetchone()
        if not link:
            raise HTTPException(status_code=404, detail='Patient introuvable pour ce médecin.')
        patient = execute(conn, "SELECT * FROM users WHERE id = ? AND role = 'patient'", (patient_id,)).fetchone()
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (patient_id,)).fetchone()
        if not patient or not dossier:
            raise HTTPException(status_code=404, detail='Patient introuvable.')
    log_access(patient_id, doctor['id'], 'doctor', 'private', request.client.host if request.client else None)
    return serialize_dossier(patient, dossier, include_private=True)


@app.put('/api/patients/{patient_id}')
def doctor_update_patient(patient_id: int, payload: DossierUpdatePayload, x_doctor_pin: Optional[str] = Header(default=None), doctor=Depends(require_role('doctor'))):
    require_doctor_pin(doctor, x_doctor_pin)
    with get_conn() as conn:
        link = execute(conn, 'SELECT * FROM doctor_patients WHERE doctor_id = ? AND patient_id = ?', (doctor['id'], patient_id)).fetchone()
        if not link:
            raise HTTPException(status_code=404, detail='Patient introuvable pour ce médecin.')
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (patient_id,)).fetchone()
        patient = execute(conn, 'SELECT * FROM users WHERE id = ?', (patient_id,)).fetchone()
        if not patient or not dossier:
            raise HTTPException(status_code=404, detail='Patient introuvable.')
        private_data = json_loads_safe(decrypt_text(dossier['private_data_enc']), create_default_private_data())
        if payload.private_data is not None:
            private_data.update(payload.private_data)
        execute(conn,
            """
            UPDATE dossiers SET blood_type = ?, public_allergies_json = ?, public_conditions_json = ?,
            emergency_contact_name = ?, emergency_contact_phone = ?, emergency_instructions = ?,
            private_data_enc = ?, updated_at = ? WHERE patient_id = ?
            """,
            (
                payload.blood_type if payload.blood_type is not None else dossier['blood_type'],
                json.dumps(payload.public_allergies if payload.public_allergies is not None else json_loads_safe(dossier['public_allergies_json'], []), ensure_ascii=False),
                json.dumps(payload.public_conditions if payload.public_conditions is not None else json_loads_safe(dossier['public_conditions_json'], []), ensure_ascii=False),
                payload.emergency_contact_name if payload.emergency_contact_name is not None else dossier['emergency_contact_name'],
                payload.emergency_contact_phone if payload.emergency_contact_phone is not None else dossier['emergency_contact_phone'],
                payload.emergency_instructions if payload.emergency_instructions is not None else dossier['emergency_instructions'],
                encrypt_text(json.dumps(private_data, ensure_ascii=False)),
                utcnow(),
                patient_id,
            ),
        )
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (patient_id,)).fetchone()
    return serialize_dossier(patient, dossier, include_private=True)


@app.delete('/api/patients/{patient_id}')
def archive_patient(patient_id: int, x_doctor_pin: Optional[str] = Header(default=None), doctor=Depends(require_role('doctor'))):
    require_doctor_pin(doctor, x_doctor_pin)
    with get_conn() as conn:
        link = execute(conn, 'SELECT * FROM doctor_patients WHERE doctor_id = ? AND patient_id = ?', (doctor['id'], patient_id)).fetchone()
        if not link:
            raise HTTPException(status_code=404, detail='Patient introuvable pour ce médecin.')
        execute(conn, 'UPDATE dossiers SET is_archived = 1, updated_at = ? WHERE patient_id = ?', (utcnow(), patient_id))
    return {'ok': True}


@app.post('/api/patients/{patient_id}/allergies')
def doctor_add_allergy(patient_id: int, payload: ArrayItemPayload, x_doctor_pin: Optional[str] = Header(default=None), doctor=Depends(require_role('doctor'))):
    require_doctor_pin(doctor, x_doctor_pin)
    with get_conn() as conn:
        link = execute(conn, 'SELECT * FROM doctor_patients WHERE doctor_id = ? AND patient_id = ?', (doctor['id'], patient_id)).fetchone()
        if not link:
            raise HTTPException(status_code=404, detail='Patient introuvable pour ce médecin.')
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (patient_id,)).fetchone()
        items = json_loads_safe(dossier['public_allergies_json'], [])
        items.append(payload.value)
        execute(conn, 'UPDATE dossiers SET public_allergies_json = ?, updated_at = ? WHERE patient_id = ?', (json.dumps(items, ensure_ascii=False), utcnow(), patient_id))
    return {'items': items}


@app.post('/api/patients/{patient_id}/conditions')
def doctor_add_condition(patient_id: int, payload: ArrayItemPayload, x_doctor_pin: Optional[str] = Header(default=None), doctor=Depends(require_role('doctor'))):
    require_doctor_pin(doctor, x_doctor_pin)
    with get_conn() as conn:
        link = execute(conn, 'SELECT * FROM doctor_patients WHERE doctor_id = ? AND patient_id = ?', (doctor['id'], patient_id)).fetchone()
        if not link:
            raise HTTPException(status_code=404, detail='Patient introuvable pour ce médecin.')
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (patient_id,)).fetchone()
        items = json_loads_safe(dossier['public_conditions_json'], [])
        items.append(payload.value)
        execute(conn, 'UPDATE dossiers SET public_conditions_json = ?, updated_at = ? WHERE patient_id = ?', (json.dumps(items, ensure_ascii=False), utcnow(), patient_id))
    return {'items': items}


@app.get('/')
def root_index():
    return FileResponse(STATIC_DIR / 'index.html')


app.mount('/', StaticFiles(directory=STATIC_DIR, html=True), name='static')
