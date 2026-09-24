# SIH26155 Member 2 - Local Prototype

This is a temporary standalone prototype for local development in VS Code.

Flow:

CONFIG FILE
    -> validation
    -> deterministic vendor detection
    -> Cisco/Fortinet parsing
    -> vendor-neutral normalized JSON
    -> deterministic temporary rules
    -> PASS/FAIL + risk/severity + evidence
    -> optional Groq AI call for explanation/remediation/unknown-command interpretation
    -> terminal report

Important:
- The final PASS/FAIL decision is deterministic.
- Groq never decides PASS/FAIL.
- The temporary controls in config/controls.json are DEMO controls only.
- Replace config/controls.json with Member 1's approved controls before merging.
- Configuration files are treated as untrusted text and are never executed.
- No live network/device connection is made.

## 1. Setup

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create the environment file:

```powershell
copy .env.example .env
```

Put your Groq key in `.env`:

```text
GROQ_API_KEY=your_key_here
```

## 2. Run

Interactive:

```powershell
python main.py
```

It will ask:

```text
Enter configuration file path:
```

Or pass a path directly:

```powershell
python main.py samples\cisco_noncompliant.conf
```

The normalized analysis JSON is written to:

```text
output\analysis_<analysis_id>.json
```

## 3. Demo files

- `samples/cisco_noncompliant.conf`
- `samples/cisco_compliant.conf`
- `samples/fortinet_noncompliant.conf`
- `samples/fortinet_compliant.conf`
- `samples/unknown.conf`

## 4. What the prototype currently recognizes

Cisco:
- hostname
- SSH version
- VTY transport / Telnet exposure
- logging
- password minimum length

Fortinet:
- hostname
- SSH status
- Telnet status
- admin password minimum length
- logging status

These mappings are deliberately small. They are not intended to represent every vendor syntax.

## 5. AI behavior

Groq is called only when there is something useful to explain:
- one or more deterministic FAIL findings, and/or
- unknown/unparsed command lines

The request contains only the minimum relevant context. The response is requested as structured JSON and validated before being used.

The AI result is an explanation/suggestion layer only. It cannot change:
- PASS/FAIL
- control definitions
- observed values
- evidence

## 6. Later merge with Member 1

Keep the following concepts:

```text
app/parsers/
app/vendor_detection.py
app/normalizer.py
app/compliance.py
app/ai/
config/controls.json
```

When Member 1's repository is ready:
1. Move these modules into the agreed folders.
2. Replace the temporary demo control definitions with Member 1's approved controls.
3. Replace the temporary parser schema with DATA_MODEL.md.
4. Keep the deterministic compliance engine separate from AI.

## 7. Frontend + API

This local prototype also includes a simple frontend connected to the existing pipeline.

Start the API/frontend from the project root:

```powershell
python -m uvicorn web_api:app --host 127.0.0.1 --port 8000 --reload
```

Or:

```powershell
.\run_web.ps1
```

Open:

```text
http://127.0.0.1:8000
```

The browser uploads the selected configuration to:

```text
POST /api/v1/analyses
```

The endpoint writes the uploaded text to a temporary local file, calls the existing `run_pipeline()` function, returns the same deterministic analysis result, and deletes the temporary file.

The frontend does not implement compliance logic. It only displays the backend result.
