import base64
import json
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from html import escape
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Optional

import qrcode
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .config import (
    APP_NAME,
    DOCTOR_PIN_RECHECK_MINUTES,
    EMAIL_CODE_EXPIRY_MINUTES,
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USER,
)
from .db import create_default_private_data, execute, get_conn, init_db, insert_user, utcnow
from .schemas import (
    AccountProfileUpdatePayload,
    AppointmentPayload,
    CompleteOnboardingPayload,
    ChangeEmailConfirmPayload,
    ChangeEmailRequestPayload,
    ChangePasswordPayload,
    DeleteAccountPayload,
    CreatePatientPayload,
    DoctorPinPayload,
    DossierUpdatePayload,
    EmailCodePayload,
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


def get_site_origin(request: Request) -> str:
    origin = request.headers.get('origin')
    if origin:
        return origin.rstrip('/')
    proto = request.headers.get('x-forwarded-proto') or request.url.scheme
    host = request.headers.get('x-forwarded-host') or request.headers.get('host') or request.url.netloc
    return f"{proto}://{host}".rstrip('/')


def json_loads_safe(value: str, fallback: Any):
    try:
        return json.loads(value or '')
    except Exception:
        return fallback


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: Optional[str]) -> datetime:
    if not value:
        return now_dt() - timedelta(days=1)
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return now_dt() - timedelta(days=1)


def send_email_code_message(email: str, code: str, purpose: str) -> Dict[str, Any]:
    subject = 'Code de vérification MedPass'
    reason = 'finaliser votre inscription' if purpose == 'signup' else 'confirmer votre adresse e-mail'
    html = f"""
    <div style='font-family:Arial,sans-serif;padding:24px;color:#10213a'>
      <h2 style='margin:0 0 12px'>MedPass</h2>
      <p>Utilisez ce code pour {reason} :</p>
      <div style='font-size:32px;font-weight:700;letter-spacing:6px;margin:18px 0'>{escape(code)}</div>
      <p>Ce code expire dans {EMAIL_CODE_EXPIRY_MINUTES} minutes.</p>
    </div>
    """
    if not (SMTP_USER and SMTP_PASSWORD and SMTP_FROM):
        return {'sent': False, 'dev_code': code}
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = SMTP_FROM
    msg['To'] = email
    msg.set_content(f'MedPass verification code: {code}')
    msg.add_alternative(html, subtype='html')
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
    return {'sent': True}


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


def log_access(patient_id: int, accessed_by: Optional[int], access_role: str, access_level: str, ip_address: Optional[str]):
    with get_conn() as conn:
        execute(conn,
            'INSERT INTO access_logs (patient_id, accessed_by, access_role, access_level, ip_address, created_at) VALUES (?,?,?,?,?,?)',
            (patient_id, accessed_by, access_role, access_level, ip_address, utcnow()),
        )


def serialize_dossier(user: Dict[str, Any], dossier: Dict[str, Any], *, include_private: bool):
    payload = {
        'patient_id': user['id'],
        'email': user['email'],
        'email_verified': bool(user.get('email_verified')),
        'phone_number': user.get('phone_number') or '',
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'birth_date': user['birth_date'],
        'blood_type': dossier.get('blood_type') or '',
        'public_allergies': json_loads_safe(dossier.get('public_allergies_json'), []),
        'public_conditions': json_loads_safe(dossier.get('public_conditions_json'), []),
        'appointments': json_loads_safe(dossier.get('appointments_json'), []),
        'emergency_contact_name': dossier.get('emergency_contact_name') or '',
        'emergency_contact_phone': dossier.get('emergency_contact_phone') or '',
        'emergency_instructions': dossier.get('emergency_instructions') or '',
        'updated_at': dossier.get('updated_at'),
        'is_archived': bool(dossier.get('is_archived')),
    }
    if include_private:
        payload['private_data'] = json_loads_safe(decrypt_text(dossier.get('private_data_enc') or ''), create_default_private_data())
    return payload


def get_public_patient_payload(token: str, request: Request):
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
    data['medpass_id'] = f"PMU-{user['id']:05d}"
    return data


def ensure_public_required(payload: DossierUpdatePayload):
    if not (payload.blood_type or '').strip():
        raise HTTPException(status_code=400, detail='Le groupe sanguin est obligatoire.')
    if not (payload.emergency_contact_name or '').strip():
        raise HTTPException(status_code=400, detail='Le contact d’urgence est obligatoire.')
    if not (payload.emergency_contact_phone or '').strip():
        raise HTTPException(status_code=400, detail='Le numéro d’urgence est obligatoire.')


def verify_email_code(conn, email: str, code: str, purpose: str):
    row = execute(conn,
        'SELECT * FROM email_verifications WHERE email = ? AND purpose = ? AND is_used = 0 ORDER BY id DESC LIMIT 1',
        (email.lower(), purpose),
    ).fetchone()
    if not row or parse_dt(row['expires_at']) < now_dt() or not verify_secret(code, row['code_hash']):
        raise HTTPException(status_code=400, detail='Code de vérification invalide ou expiré.')
    execute(conn, 'UPDATE email_verifications SET is_used = 1 WHERE id = ?', (row['id'],))


@app.get('/health')
def health():
    return {'ok': True, 'app': APP_NAME}


@app.post('/api/auth/send-email-code')
def send_email_code(payload: EmailCodePayload):
    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    now = now_dt()
    expires = now + timedelta(minutes=EMAIL_CODE_EXPIRY_MINUTES)
    with get_conn() as conn:
        execute(conn, 'INSERT INTO email_verifications (email, code_hash, purpose, created_at, expires_at, is_used) VALUES (?,?,?,?,?,0)',
                (payload.email.lower(), hash_secret(code), payload.purpose, now.isoformat(), expires.isoformat()))
    result = send_email_code_message(payload.email.lower(), code, payload.purpose)
    return {'ok': True, **result}


@app.post('/api/auth/register-verified')
def register_verified(payload: RegisterPayload):
    role = payload.role.lower().strip()
    if role not in {'patient', 'doctor'}:
        raise HTTPException(status_code=400, detail='Rôle invalide.')
    if role == 'doctor' and (not payload.doctor_pin or len(payload.doctor_pin) != 4 or not payload.doctor_pin.isdigit()):
        raise HTTPException(status_code=400, detail='Le médecin doit définir un PIN à 4 chiffres.')
    if role == 'patient' and not (payload.phone_number or '').strip():
        raise HTTPException(status_code=400, detail='Le numéro de téléphone est obligatoire.')
    if not payload.verification_code:
        raise HTTPException(status_code=400, detail='Le code de vérification e-mail est obligatoire.')

    with get_conn() as conn:
        existing = execute(conn, 'SELECT id FROM users WHERE email = ?', (payload.email.lower(),)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail='Cet e-mail existe déjà.')
        verify_email_code(conn, payload.email.lower(), payload.verification_code, 'signup')
        now = utcnow()
        user_id = insert_user(
            conn,
            email=payload.email.lower(),
            password_hash=hash_secret(payload.password),
            role=role,
            first_name=payload.first_name.strip(),
            last_name=payload.last_name.strip(),
            birth_date=payload.birth_date,
            doctor_pin_hash=hash_secret(payload.doctor_pin) if payload.doctor_pin else None,
            phone_number=(payload.phone_number or '').strip(),
            email_verified=1,
            created_at=now,
        )
        if role == 'patient':
            execute(conn, """
                INSERT INTO dossiers (
                    patient_id, blood_type, public_allergies_json, public_conditions_json,
                    emergency_contact_name, emergency_contact_phone, emergency_instructions,
                    appointments_json, private_data_enc, created_at, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (user_id, '', '[]', '[]', '', '', '', '[]', encrypt_text(json.dumps(create_default_private_data())), now, now))
            token = secrets.token_urlsafe(24)
            execute(conn, 'INSERT INTO qrcodes (patient_id, token, is_active, created_at) VALUES (?,?,1,?)', (user_id, token, now))
        user = execute(conn, 'SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    token = create_token({'id': user['id'], 'role': user['role'], 'email': user['email']})
    return {'token': token, 'user': {'id': user['id'], 'role': user['role'], 'email': user['email'], 'first_name': user['first_name'], 'last_name': user['last_name'], 'must_complete_onboarding': False}}


@app.post('/api/auth/login')
def login(payload: LoginPayload):
    with get_conn() as conn:
        user = execute(conn, 'SELECT * FROM users WHERE email = ?', (payload.email.lower(),)).fetchone()
        if not user or not verify_secret(payload.password, user['password_hash']):
            raise HTTPException(status_code=401, detail='E-mail ou mot de passe incorrect.')
    token = create_token({'id': user['id'], 'role': user['role'], 'email': user['email']})
    return {'token': token, 'user': {'id': user['id'], 'role': user['role'], 'email': user['email'], 'first_name': user['first_name'], 'last_name': user['last_name'], 'must_complete_onboarding': bool(user.get('must_complete_onboarding')), 'email_verified': bool(user.get('email_verified'))}}


@app.post('/api/auth/complete-onboarding')
def complete_onboarding(payload: CompleteOnboardingPayload):
    with get_conn() as conn:
        user = execute(conn, "SELECT * FROM users WHERE email = ? AND role = 'patient'", (payload.email.lower(),)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail='Compte patient introuvable.')
        verify_email_code(conn, payload.email.lower(), payload.verification_code, 'onboarding')
        execute(conn, 'UPDATE users SET password_hash = ?, phone_number = ?, email_verified = 1, must_complete_onboarding = 0 WHERE id = ?',
                (hash_secret(payload.new_password), payload.phone_number.strip(), user['id']))
        user = execute(conn, 'SELECT * FROM users WHERE id = ?', (user['id'],)).fetchone()
    token = create_token({'id': user['id'], 'role': user['role'], 'email': user['email']})
    return {'token': token, 'user': {'id': user['id'], 'role': user['role'], 'email': user['email'], 'first_name': user['first_name'], 'last_name': user['last_name'], 'must_complete_onboarding': False}}


@app.get('/api/auth/me')
def me(user=Depends(get_current_user)):
    return {
        'id': user['id'],
        'role': user['role'],
        'email': user['email'],
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'birth_date': user['birth_date'],
        'phone_number': user.get('phone_number') or '',
        'email_verified': bool(user.get('email_verified')),
        'must_complete_onboarding': bool(user.get('must_complete_onboarding')),
        'doctor_pin_recheck_minutes': DOCTOR_PIN_RECHECK_MINUTES,
    }


@app.get('/api/account/settings')
def account_settings(user=Depends(get_current_user)):
    return {
        'id': user['id'],
        'role': user['role'],
        'email': user['email'],
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'birth_date': user['birth_date'],
        'phone_number': user.get('phone_number') or '',
        'email_verified': bool(user.get('email_verified')),
    }


@app.put('/api/account/profile')
def update_account_profile(payload: AccountProfileUpdatePayload, user=Depends(get_current_user)):
    with get_conn() as conn:
        execute(conn, 'UPDATE users SET first_name = ?, last_name = ?, birth_date = ?, phone_number = ? WHERE id = ?',
                (payload.first_name.strip(), payload.last_name.strip(), payload.birth_date, (payload.phone_number or '').strip(), user['id']))
        updated = execute(conn, 'SELECT * FROM users WHERE id = ?', (user['id'],)).fetchone()
    return {
        'id': updated['id'],
        'role': updated['role'],
        'email': updated['email'],
        'first_name': updated['first_name'],
        'last_name': updated['last_name'],
        'birth_date': updated['birth_date'],
        'phone_number': updated.get('phone_number') or '',
        'email_verified': bool(updated.get('email_verified')),
    }


@app.post('/api/account/request-email-change')
def request_email_change(payload: ChangeEmailRequestPayload, user=Depends(get_current_user)):
    new_email = payload.new_email.lower().strip()
    if new_email == user['email'].lower():
        raise HTTPException(status_code=400, detail='Cet e-mail est déjà utilisé sur votre compte.')
    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    now = now_dt()
    expires = now + timedelta(minutes=EMAIL_CODE_EXPIRY_MINUTES)
    purpose = f'change_email:{user["id"]}'
    with get_conn() as conn:
        existing = execute(conn, 'SELECT id FROM users WHERE email = ?', (new_email,)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail='Cet e-mail est déjà utilisé.')
        execute(conn, 'INSERT INTO email_verifications (email, code_hash, purpose, created_at, expires_at, is_used) VALUES (?,?,?,?,?,0)',
                (new_email, hash_secret(code), purpose, now.isoformat(), expires.isoformat()))
    result = send_email_code_message(new_email, code, 'change_email')
    return {'ok': True, **result}


@app.post('/api/account/confirm-email-change')
def confirm_email_change(payload: ChangeEmailConfirmPayload, user=Depends(get_current_user)):
    new_email = payload.new_email.lower().strip()
    purpose = f'change_email:{user["id"]}'
    with get_conn() as conn:
        existing = execute(conn, 'SELECT id FROM users WHERE email = ?', (new_email,)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail='Cet e-mail est déjà utilisé.')
        verify_email_code(conn, new_email, payload.verification_code, purpose)
        execute(conn, 'UPDATE users SET email = ?, email_verified = 1 WHERE id = ?', (new_email, user['id']))
        updated = execute(conn, 'SELECT * FROM users WHERE id = ?', (user['id'],)).fetchone()
    token = create_token({'id': updated['id'], 'role': updated['role'], 'email': updated['email']})
    return {'token': token, 'user': {'id': updated['id'], 'role': updated['role'], 'email': updated['email'], 'first_name': updated['first_name'], 'last_name': updated['last_name'], 'must_complete_onboarding': bool(updated.get('must_complete_onboarding'))}}


@app.post('/api/account/change-password')
def change_password(payload: ChangePasswordPayload, user=Depends(get_current_user)):
    if not verify_secret(payload.current_password, user['password_hash']):
        raise HTTPException(status_code=400, detail='Mot de passe actuel incorrect.')
    with get_conn() as conn:
        execute(conn, 'UPDATE users SET password_hash = ? WHERE id = ?', (hash_secret(payload.new_password), user['id']))
    return {'ok': True}


@app.delete('/api/account/delete')
def delete_account(payload: DeleteAccountPayload, user=Depends(get_current_user)):
    if not verify_secret(payload.current_password, user['password_hash']):
        raise HTTPException(status_code=400, detail='Mot de passe actuel incorrect.')
    with get_conn() as conn:
        if user['role'] == 'patient':
            execute(conn, 'DELETE FROM doctor_patients WHERE patient_id = ?', (user['id'],))
            execute(conn, 'DELETE FROM access_logs WHERE patient_id = ? OR accessed_by = ?', (user['id'], user['id']))
            execute(conn, 'DELETE FROM qrcodes WHERE patient_id = ?', (user['id'],))
            execute(conn, 'DELETE FROM dossiers WHERE patient_id = ?', (user['id'],))
            execute(conn, 'DELETE FROM email_verifications WHERE email = ?', (user['email'],))
            execute(conn, 'DELETE FROM users WHERE id = ?', (user['id'],))
        else:
            execute(conn, 'DELETE FROM doctor_patients WHERE doctor_id = ?', (user['id'],))
            execute(conn, 'DELETE FROM access_logs WHERE accessed_by = ?', (user['id'],))
            execute(conn, 'DELETE FROM email_verifications WHERE email = ?', (user['email'],))
            execute(conn, 'DELETE FROM users WHERE id = ?', (user['id'],))
    return {'ok': True}

@app.post('/api/doctor/verify-pin')
def verify_doctor_pin(payload: DoctorPinPayload, user=Depends(require_role('doctor'))):
    require_doctor_pin(user, payload.pin)
    return {'ok': True, 'valid_for_minutes': DOCTOR_PIN_RECHECK_MINUTES}


@app.get('/api/dossier/mon-dossier')
def get_my_dossier(user=Depends(require_role('patient'))):
    with get_conn() as conn:
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (user['id'],)).fetchone()
        if not dossier:
            raise HTTPException(status_code=404, detail='Dossier introuvable.')
        link = execute(conn, 'SELECT doctor_id FROM doctor_patients WHERE patient_id = ?', (user['id'],)).fetchone()
    payload = serialize_dossier(user, dossier, include_private=False)
    payload['linked_to_doctor'] = bool(link)
    return payload


@app.put('/api/dossier/mon-dossier')
def update_my_dossier(payload: DossierUpdatePayload, user=Depends(require_role('patient'))):
    ensure_public_required(payload)
    with get_conn() as conn:
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (user['id'],)).fetchone()
        if not dossier:
            raise HTTPException(status_code=404, detail='Dossier introuvable.')
        execute(conn, """
            UPDATE dossiers SET blood_type = ?, public_allergies_json = ?, public_conditions_json = ?,
            emergency_contact_name = ?, emergency_contact_phone = ?, emergency_instructions = ?, updated_at = ?
            WHERE patient_id = ?
        """, (
            (payload.blood_type or '').strip(),
            json.dumps(payload.public_allergies or [], ensure_ascii=False),
            json.dumps(payload.public_conditions or [], ensure_ascii=False),
            (payload.emergency_contact_name or '').strip(),
            (payload.emergency_contact_phone or '').strip(),
            (payload.emergency_instructions or '').strip(),
            utcnow(),
            user['id'],
        ))
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (user['id'],)).fetchone()
    return serialize_dossier(user, dossier, include_private=False)


@app.get('/api/patient/appointments')
def patient_appointments(user=Depends(require_role('patient'))):
    with get_conn() as conn:
        dossier = execute(conn, 'SELECT appointments_json FROM dossiers WHERE patient_id = ?', (user['id'],)).fetchone()
        items = json_loads_safe(dossier.get('appointments_json') if dossier else '[]', [])
    return {'items': items}


@app.post('/api/patient/appointments')
def add_appointment(payload: AppointmentPayload, user=Depends(require_role('patient'))):
    with get_conn() as conn:
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (user['id'],)).fetchone()
        if not dossier:
            raise HTTPException(status_code=404, detail='Dossier introuvable.')
        items = json_loads_safe(dossier.get('appointments_json'), [])
        items.append({'date': payload.date, 'time': payload.time or '', 'title': payload.title})
        items.sort(key=lambda x: f"{x.get('date','')} {x.get('time','')}")
        execute(conn, 'UPDATE dossiers SET appointments_json = ?, updated_at = ? WHERE patient_id = ?',
                (json.dumps(items, ensure_ascii=False), utcnow(), user['id']))
    return {'items': items}


@app.delete('/api/patient/appointments/{index}')
def delete_appointment(index: int, user=Depends(require_role('patient'))):
    with get_conn() as conn:
        dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (user['id'],)).fetchone()
        items = json_loads_safe(dossier.get('appointments_json') if dossier else '[]', [])
        if index < 0 or index >= len(items):
            raise HTTPException(status_code=404, detail='Rendez-vous introuvable.')
        items.pop(index)
        execute(conn, 'UPDATE dossiers SET appointments_json = ?, updated_at = ? WHERE patient_id = ?',
                (json.dumps(items, ensure_ascii=False), utcnow(), user['id']))
    return {'items': items}


@app.get('/api/qrcode/generate')
def generate_qrcode(request: Request, user=Depends(require_role('patient'))):
    with get_conn() as conn:
        row = execute(conn, 'SELECT * FROM qrcodes WHERE patient_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1', (user['id'],)).fetchone()
        if not row:
            token = secrets.token_urlsafe(24)
            execute(conn, 'INSERT INTO qrcodes (patient_id, token, is_active, created_at) VALUES (?,?,1,?)', (user['id'], token, utcnow()))
            row = execute(conn, 'SELECT * FROM qrcodes WHERE patient_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1', (user['id'],)).fetchone()
    public_url = get_site_origin(request) + f'/api/secours/{row["token"]}'
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
    return get_public_patient_payload(token, request)


@app.get('/api/secours/{token}', response_class=HTMLResponse)
def api_secours_page(token: str, request: Request):
    return secours_page(token, request)


@app.get('/secours/{token}', response_class=HTMLResponse)
def secours_page(token: str, request: Request):
    data = get_public_patient_payload(token, request)
    def chips(items):
        values = items or []
        if not values:
            return '<span class="array-item">Aucune</span>'
        return ''.join(f'<span class="array-item">{escape(str(item))}</span>' for item in values)
    phone_raw = data.get('emergency_contact_phone') or ''
    phone_btn = f'<a class="btn btn-primary btn-full" href="tel:{escape(phone_raw)}">Appeler le contact d’urgence</a>' if phone_raw else ''
    html = f"""<!DOCTYPE html><html lang='fr'><head><meta charset='UTF-8'/><meta name='viewport' content='width=device-width, initial-scale=1.0'/><title>MedPass — Vue secours</title><link rel='stylesheet' href='/styles.css'/></head>
<body><div class='app-bg'></div><main class='shell shell-site shell-full'><section class='phone-frame wide-frame site-frame site-frame-full'>
<header class='topbar topbar-site landing-topbar'><div><p class='eyebrow'>Passeport médical d'urgence</p><h1>MedPass</h1><p class='muted site-subtitle'>Vue secours directe du patient.</p></div><div class='topbar-pill blue'>Accès d'urgence</div></header>
<section class='hero-card hero-site hero-site-full'><div class='hero-copy'><span class='badge red'>Informations vitales</span><h2>{escape((data.get('first_name','')+' '+data.get('last_name','')).strip())}</h2><p class='muted site-description'>Accès immédiat aux données essentielles du patient.</p>
<div class='feature-points feature-points-simple'><div class='mini-feature'><strong>Groupe sanguin</strong><span>{escape(data.get('blood_type') or '—')}</span></div><div class='mini-feature'><strong>Identifiant</strong><span>{escape(data.get('medpass_id') or '—')}</span></div><div class='mini-feature'><strong>Contact d'urgence</strong><span>{escape(data.get('emergency_contact_name') or 'Non renseigné')}<br>{escape(data.get('emergency_contact_phone') or 'Non renseigné')}</span></div></div>
<div class='hero-actions' style='margin-top:18px;'>{phone_btn}</div></div>
<div class='hero-visual app-card hero-visual-large'><div class='visual-badge-row'><span class='status-pill danger'>Urgence</span><span class='status-pill'>Secours</span></div><div class='visual-panel' style='justify-items:stretch; text-align:left;'><div class='app-card' style='padding:16px;'><h3>Allergies</h3><div class='array-list'>{chips(data.get('public_allergies'))}</div></div><div class='app-card' style='padding:16px;'><h3>Pathologies d'urgence</h3><div class='array-list'>{chips(data.get('public_conditions'))}</div></div><div class='app-card' style='padding:16px;'><h3>Consignes</h3><p class='muted' style='margin-bottom:0;'>{escape(data.get('emergency_instructions') or 'Aucune consigne spécifique.')}</p></div></div></div>
</section></section></main></body></html>"""
    return HTMLResponse(content=html)


@app.get('/api/patients')
def list_patients(include_archived: bool = Query(False), doctor=Depends(require_role('doctor'))):
    where = 'AND d.is_archived = 0' if not include_archived else ''
    with get_conn() as conn:
        rows = execute(conn, f"""
            SELECT u.id, u.email, u.first_name, u.last_name, u.birth_date, u.phone_number,
                   d.blood_type, d.public_allergies_json, d.public_conditions_json, d.updated_at, d.is_archived
            FROM doctor_patients dp
            JOIN users u ON u.id = dp.patient_id
            JOIN dossiers d ON d.patient_id = u.id
            WHERE dp.doctor_id = ? {where}
            ORDER BY u.first_name, u.last_name
        """, (doctor['id'],)).fetchall()
    for row in rows:
        row['public_allergies'] = json_loads_safe(row.pop('public_allergies_json'), [])
        row['public_conditions'] = json_loads_safe(row.pop('public_conditions_json'), [])
        row['is_archived'] = bool(row['is_archived'])
    return {'items': rows}


@app.post('/api/patients')
def create_or_link_patient(payload: CreatePatientPayload, doctor=Depends(require_role('doctor'))):
    with get_conn() as conn:
        now = utcnow()
        existing = execute(conn, 'SELECT * FROM users WHERE email = ?', (payload.email.lower(),)).fetchone()
        if existing and existing['role'] != 'patient':
            raise HTTPException(status_code=400, detail='Cet e-mail appartient déjà à un médecin.')
        if existing:
            patient_id = existing['id']
            link = execute(conn, 'SELECT * FROM doctor_patients WHERE patient_id = ?', (patient_id,)).fetchone()
            if not link:
                execute(conn, 'INSERT INTO doctor_patients (doctor_id, patient_id, created_at) VALUES (?,?,?)', (doctor['id'], patient_id, now))
            dossier = execute(conn, 'SELECT * FROM dossiers WHERE patient_id = ?', (patient_id,)).fetchone()
            private_data = json_loads_safe(decrypt_text(dossier['private_data_enc']), create_default_private_data())
            private_data.update(payload.private_data or {})
            execute(conn, """
                UPDATE dossiers SET blood_type=?, public_allergies_json=?, public_conditions_json=?, emergency_contact_name=?, emergency_contact_phone=?, emergency_instructions=?, private_data_enc=?, is_archived=0, updated_at=? WHERE patient_id=?
            """, (
                payload.blood_type or dossier.get('blood_type') or '',
                json.dumps(payload.public_allergies or json_loads_safe(dossier.get('public_allergies_json'), []), ensure_ascii=False),
                json.dumps(payload.public_conditions or json_loads_safe(dossier.get('public_conditions_json'), []), ensure_ascii=False),
                payload.emergency_contact_name or dossier.get('emergency_contact_name') or '',
                payload.emergency_contact_phone or dossier.get('emergency_contact_phone') or '',
                payload.emergency_instructions or dossier.get('emergency_instructions') or '',
                encrypt_text(json.dumps(private_data, ensure_ascii=False)),
                now,
                patient_id,
            ))
        else:
            patient_id = insert_user(
                conn,
                email=payload.email.lower(),
                password_hash=hash_secret(payload.password),
                role='patient',
                first_name=payload.first_name.strip(),
                last_name=payload.last_name.strip(),
                birth_date=payload.birth_date,
                doctor_pin_hash=None,
                phone_number=(payload.phone_number or '').strip(),
                email_verified=0,
                must_complete_onboarding=1,
                created_at=now,
            )
            private_data = create_default_private_data()
            private_data.update(payload.private_data or {})
            execute(conn, """
                INSERT INTO dossiers (
                    patient_id, blood_type, public_allergies_json, public_conditions_json,
                    emergency_contact_name, emergency_contact_phone, emergency_instructions,
                    appointments_json, private_data_enc, created_at, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                patient_id, payload.blood_type or '', json.dumps(payload.public_allergies, ensure_ascii=False), json.dumps(payload.public_conditions, ensure_ascii=False),
                payload.emergency_contact_name or '', payload.emergency_contact_phone or '', payload.emergency_instructions or '', '[]', encrypt_text(json.dumps(private_data, ensure_ascii=False)), now, now,
            ))
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
        private_data = json_loads_safe(decrypt_text(dossier['private_data_enc']), create_default_private_data())
        if payload.private_data:
            private_data.update(payload.private_data)
        execute(conn, """
            UPDATE dossiers SET blood_type=?, public_allergies_json=?, public_conditions_json=?, emergency_contact_name=?, emergency_contact_phone=?, emergency_instructions=?, private_data_enc=?, updated_at=? WHERE patient_id=?
        """, (
            payload.blood_type or dossier.get('blood_type') or '',
            json.dumps(payload.public_allergies or [], ensure_ascii=False),
            json.dumps(payload.public_conditions or [], ensure_ascii=False),
            payload.emergency_contact_name or '',
            payload.emergency_contact_phone or '',
            payload.emergency_instructions or '',
            encrypt_text(json.dumps(private_data, ensure_ascii=False)),
            utcnow(),
            patient_id,
        ))
        patient = execute(conn, 'SELECT * FROM users WHERE id = ?', (patient_id,)).fetchone()
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


@app.post('/api/patients/{patient_id}/restore')
def restore_patient(patient_id: int, x_doctor_pin: Optional[str] = Header(default=None), doctor=Depends(require_role('doctor'))):
    require_doctor_pin(doctor, x_doctor_pin)
    with get_conn() as conn:
        link = execute(conn, 'SELECT * FROM doctor_patients WHERE doctor_id = ? AND patient_id = ?', (doctor['id'], patient_id)).fetchone()
        if not link:
            raise HTTPException(status_code=404, detail='Patient introuvable pour ce médecin.')
        execute(conn, 'UPDATE dossiers SET is_archived = 0, updated_at = ? WHERE patient_id = ?', (utcnow(), patient_id))
    return {'ok': True}


@app.get('/api/doctor/rescue-links')
def doctor_rescue_links(request: Request, doctor=Depends(require_role('doctor'))):
    items = []
    with get_conn() as conn:
        rows = execute(conn, """
            SELECT u.id, u.first_name, u.last_name, u.email, d.blood_type, d.emergency_contact_name, d.emergency_contact_phone,
                   q.token
            FROM doctor_patients dp
            JOIN users u ON u.id = dp.patient_id
            JOIN dossiers d ON d.patient_id = u.id
            LEFT JOIN qrcodes q ON q.patient_id = u.id AND q.is_active = 1
            WHERE dp.doctor_id = ? AND d.is_archived = 0
            ORDER BY u.first_name, u.last_name
        """, (doctor['id'],)).fetchall()
        for row in rows:
            token = row.get('token')
            if not token:
                token = secrets.token_urlsafe(24)
                execute(conn, 'INSERT INTO qrcodes (patient_id, token, is_active, created_at) VALUES (?,?,1,?)', (row['id'], token, utcnow()))
            items.append({
                'patient_id': row['id'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'email': row['email'],
                'blood_type': row.get('blood_type') or '',
                'emergency_contact_name': row.get('emergency_contact_name') or '',
                'emergency_contact_phone': row.get('emergency_contact_phone') or '',
                'token': token,
                'public_url': get_site_origin(request) + f'/api/secours/{token}',
            })
    return {'items': items}


app.mount('/', StaticFiles(directory=STATIC_DIR, html=True), name='static')
