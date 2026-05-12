from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_URL = (
    os.getenv('DATABASE_URL')
    or os.getenv('SUPABASE_DB_URL')
    or os.getenv('POSTGRES_URL')
    or ''
).strip()
DB_BACKEND = 'postgres' if DATABASE_URL.startswith(('postgres://', 'postgresql://')) else 'sqlite'

if DB_BACKEND == 'sqlite':
    default_data_dir = '/tmp/medpass_data' if os.getenv('VERCEL') else str(BASE_DIR / 'data')
    DATA_DIR = Path(os.getenv('MEDPASS_DATA_DIR', default_data_dir))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH = os.getenv('MEDPASS_DB_PATH', str(DATA_DIR / 'medpass.db'))
else:
    DATA_DIR = None
    DB_PATH = os.getenv('MEDPASS_DB_PATH', '')

JWT_SECRET = os.getenv('MEDPASS_JWT_SECRET', 'change-this-jwt-secret-in-production')
ENCRYPTION_KEY = os.getenv('MEDPASS_ENCRYPTION_KEY', '0123456789abcdef0123456789abcdef')
APP_NAME = 'MedPass'
ACCESS_TOKEN_HOURS = int(os.getenv('MEDPASS_ACCESS_TOKEN_HOURS', '8'))

SMTP_HOST = os.getenv('MEDPASS_SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('MEDPASS_SMTP_PORT', '587'))
SMTP_USER = os.getenv('MEDPASS_SMTP_USER', '').strip()
SMTP_PASSWORD = os.getenv('MEDPASS_SMTP_PASSWORD', '').strip()
SMTP_FROM = os.getenv('MEDPASS_SMTP_FROM', SMTP_USER).strip()
EMAIL_CODE_EXPIRY_MINUTES = int(os.getenv('MEDPASS_EMAIL_CODE_EXPIRY_MINUTES', '10'))
DOCTOR_PIN_RECHECK_MINUTES = int(os.getenv('MEDPASS_DOCTOR_PIN_RECHECK_MINUTES', '60'))

LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('MEDPASS_LOGIN_RATE_LIMIT_WINDOW_SECONDS', '300'))
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv('MEDPASS_LOGIN_RATE_LIMIT_MAX_ATTEMPTS', '8'))
PIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('MEDPASS_PIN_RATE_LIMIT_WINDOW_SECONDS', '300'))
PIN_RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv('MEDPASS_PIN_RATE_LIMIT_MAX_ATTEMPTS', '6'))
EMAIL_CODE_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('MEDPASS_EMAIL_CODE_RATE_LIMIT_WINDOW_SECONDS', '600'))
EMAIL_CODE_RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv('MEDPASS_EMAIL_CODE_RATE_LIMIT_MAX_ATTEMPTS', '4'))
PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('MEDPASS_PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS', '900'))
PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv('MEDPASS_PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS', '3'))
