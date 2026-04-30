from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / 'data'
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = (
    os.getenv('DATABASE_URL')
    or os.getenv('SUPABASE_DB_URL')
    or os.getenv('POSTGRES_URL')
    or ''
).strip()
DB_BACKEND = 'postgres' if DATABASE_URL.startswith(('postgres://', 'postgresql://')) else 'sqlite'
DB_PATH = os.getenv('MEDPASS_DB_PATH', str(DATA_DIR / 'medpass.db'))
JWT_SECRET = os.getenv('MEDPASS_JWT_SECRET', 'change-this-jwt-secret-in-production')
ENCRYPTION_KEY = os.getenv('MEDPASS_ENCRYPTION_KEY', '0123456789abcdef0123456789abcdef')
APP_NAME = 'MedPass'
ACCESS_TOKEN_HOURS = int(os.getenv('MEDPASS_ACCESS_TOKEN_HOURS', '8'))
