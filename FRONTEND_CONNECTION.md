# Frontend Connection Guide

This addon connects the existing Member 2 Python pipeline to a browser UI.

## Files

```text
project-root/
├── app/
├── config/
├── samples/
├── tests/
├── frontend/
│   └── index.html
├── main.py
├── web_api.py
├── run_web.ps1
└── requirements.txt
```

## 1. Copy the files

Copy `frontend/index.html` into a `frontend` folder at the project root.
Copy `web_api.py` and `run_web.ps1` into the project root.

## 2. Dependencies

Your `requirements.txt` must contain:

```text
fastapi>=0.115.0
uvicorn[standard]>=0.34.0
python-multipart>=0.0.20
```

Keep the existing dependencies too.

Install:

```powershell
pip install -r requirements.txt
```

## 3. Start the web application

From the project root:

```powershell
python -m uvicorn web_api:app --host 127.0.0.1 --port 8000 --reload
```

Or:

```powershell
.\run_web.ps1
```

## 4. Open the frontend

Open:

```text
http://127.0.0.1:8000
```

Do not open `frontend/index.html` with `file://` and do not use VS Code Live Server for this setup. FastAPI serves the HTML and the API from the same origin, so the browser can call `/api/v1/analyses` without a separate CORS setup.

## 5. What happens after upload

```text
Browser
  ↓ POST /api/v1/analyses
FastAPI web_api.py
  ↓
existing run_pipeline()
  ↓
file validation
  ↓
vendor detection
  ↓
Cisco/Fortinet parser
  ↓
normalization
  ↓
deterministic compliance
  ↓
risk/severity
  ↓
optional Groq enrichment
  ↓
JSON response
  ↓
Browser dashboard
```

The frontend does not contain compliance logic. It only uploads the file and displays the backend result.
