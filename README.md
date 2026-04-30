# MedPass — Vercel-ready FastAPI + HTML/CSS/JS

Cette version garde ton application presque identique, mais elle est préparée pour un déploiement **Vercel + GitHub** avec une base **Supabase Postgres** en production.

## Ce qui a changé
- les fichiers front sont maintenant aussi dans `public/` pour que Vercel les serve en statique
- le backend FastAPI est exporté via `app/index.py`, ce qui est un point d'entrée supporté par Vercel pour FastAPI
- la base est désormais **double mode**:
  - **SQLite** en local
  - **Postgres / Supabase** en production via `DATABASE_URL`
- le code métier et les routes ont été gardés au maximum

## Structure utile
- `app/main.py` → backend FastAPI
- `app/index.py` → entrypoint Vercel
- `public/` → pages statiques servies par Vercel
- `static/` → copie locale conservée
- `requirements.txt` → dépendances Python
- `.python-version` → version Python pour Vercel

## Démo locale
- Médecin: `doctor@medpassdemo.com` / `doctor123` / PIN `1234`
- Patient: `patient@medpassdemo.com` / `patient123`

## Lancer en local
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Puis ouvre:
- `http://127.0.0.1:8000/`

## Déployer sur Vercel
1. Mets ce projet sur GitHub
2. Va sur Vercel et importe le repository
3. Dans **Environment Variables**, ajoute:
   - `DATABASE_URL`
   - `MEDPASS_JWT_SECRET`
   - `MEDPASS_ENCRYPTION_KEY`
   - `MEDPASS_ACCESS_TOKEN_HOURS` (optionnel)
4. Lance le déploiement

## Variables d'environnement
### Obligatoires en production
- `DATABASE_URL` → connection string Postgres/Supabase
- `MEDPASS_JWT_SECRET` → secret JWT fort
- `MEDPASS_ENCRYPTION_KEY` → clé AES de 32 caractères minimum recommandée

### Optionnelle
- `MEDPASS_ACCESS_TOKEN_HOURS` → par défaut `8`

## Supabase conseillé pour Vercel
Pour un environnement serverless comme Vercel, Supabase recommande d'utiliser le **pooler / transaction mode** plutôt qu'une connexion directe, et précise aussi que Vercel n'est pas IPv6-compatible pour les connexions directes standard. Utilise donc la connection string pooler donnée dans le bouton **Connect** de Supabase, généralement sur le port `6543`.

## Notes importantes
- En local, si `DATABASE_URL` n'est pas défini, l'application continue d'utiliser SQLite
- Sur Vercel, SQLite local n'est pas adapté à la persistance: il faut utiliser `DATABASE_URL` vers Supabase Postgres
- Le schéma de base est auto-créé au démarrage si nécessaire
- Les données de démonstration sont seedées automatiquement seulement si la base est vide

## Ce qui marche
- inscription / connexion patient et médecin
- dashboard patient
- dashboard médecin
- création de patient par le médecin
- validation PIN médecin
- dossier patient privé
- QR code patient
- vue secours publique
- journal d'accès
- chiffrement AES-256-CBC des données privées

## Déploiement local Vercel (optionnel)
```bash
npm i -g vercel
vercel dev
```
Vercel documente FastAPI avec un export `app` dans un entrypoint supporté, et les assets statiques doivent être placés dans `public/`.
