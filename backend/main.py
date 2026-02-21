import os
import io
import re
import base64
import subprocess
import tempfile
import threading
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Tuple
import xml.etree.ElementTree as ET

import pdfplumber
import requests
import certifi

# ===== QR + OCR =====
import fitz  # PyMuPDF
from PIL import Image
from pyzbar.pyzbar import decode as qr_decode
import pytesseract

# ===== TLS adapter (FIX DH_KEY_TOO_SMALL) =====
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from fastapi import FastAPI, Header, HTTPException, UploadFile, File
from pydantic import BaseModel, Field

# ===== Email (Resend + Brevo) =====
import resend

# ✅ NUEVO: SMTP (para brevo_smtp)
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ============================================================
# FASTAPI
# ============================================================
app = FastAPI(title="Verificador CAE Backend", version="1.0.0")


# ============================================================
# AUTH (LOGIN DE TU SISTEMA)
# ============================================================
MAXI_CUIT = os.getenv("MAXI_CUIT", "")
MAXI_PASSWORD = os.getenv("MAXI_PASSWORD", "")
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY", "")
DEMO_ACCESS_TOKEN = os.getenv("DEMO_ACCESS_TOKEN", "DEMO_TOKEN_OK")


class LoginRequest(BaseModel):
    cuit: str
    password: str


def check_api_key(x_api_key: str):
    if BACKEND_API_KEY and x_api_key != BACKEND_API_KEY:
        raise HTTPException(status_code=401, detail="API key inválida")


def check_bearer(authorization: str):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Falta Authorization Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if token != DEMO_ACCESS_TOKEN:
        raise HTTPException(status_code=401, detail="Token inválido")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/auth/login")
def login(payload: LoginRequest, x_api_key: str = Header(default="")):
    check_api_key(x_api_key)
    if payload.cuit != MAXI_CUIT or payload.password != MAXI_PASSWORD:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    return {"access_token": DEMO_ACCESS_TOKEN}


# ============================================================
# USAGE COUNTER (SQLite en disk de Render)
# ============================================================
# PRIORIDAD:
# 1) SQLITE_PATH (si lo seteás explícito)
# 2) Si existe /var/data (Render Disk) => /var/data/usage.db
# 3) fallback => /tmp/usage.db (efímero)
SQLITE_PATH = (os.getenv("SQLITE_PATH", "") or "").strip()
if not SQLITE_PATH:
    if os.path.isdir("/var/data"):
        SQLITE_PATH = "/var/data/usage.db"
    else:
        SQLITE_PATH = "/tmp/usage.db"

_DB_LOCK = threading.Lock()


def _year_month_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _ensure_sqlite_dir():
    # Si SQLITE_PATH es un archivo con path, asegura que exista el directorio
    if "/" in SQLITE_PATH:
        dirp = os.path.dirname(SQLITE_PATH)
        if dirp:
            os.makedirs(dirp, exist_ok=True)


def _sqlite_init():
    _ensure_sqlite_dir()
    with sqlite3.connect(SQLITE_PATH) as con:
        # mensual (lo mantenemos para reportes/email)
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_monthly (
                year_month TEXT PRIMARY KEY,
                files_count INTEGER NOT NULL DEFAULT 0,
                requests_count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            """
        )

        # ✅ total (bolsa real, NO se resetea por mes)
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_total (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                files_count INTEGER NOT NULL DEFAULT 0,
                requests_count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            """
        )

        # ✅ NUEVO: tenants para WSFE (multi-cliente)
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS afip_tenants (
                cuit TEXT PRIMARY KEY,
                cert_b64 TEXT NOT NULL,
                key_b64 TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

        # asegurar fila única id=1
        now_iso = datetime.now(timezone.utc).isoformat()
        con.execute(
            """
            INSERT INTO usage_total (id, files_count, requests_count, updated_at)
            VALUES (1, 0, 0, ?)
            ON CONFLICT(id) DO NOTHING;
            """,
            (now_iso,),
        )

        con.commit()


def _sqlite_upsert(year_month: str, files_delta: int, requests_delta: int):
    _ensure_sqlite_dir()
    now_iso = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(SQLITE_PATH) as con:
        con.execute(
            """
            INSERT INTO usage_monthly (year_month, files_count, requests_count, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(year_month) DO UPDATE SET
                files_count = files_count + excluded.files_count,
                requests_count = requests_count + excluded.requests_count,
                updated_at = excluded.updated_at;
            """,
            (year_month, int(files_delta), int(requests_delta), now_iso),
        )
        con.commit()


def _sqlite_get(year_month: str) -> Dict[str, Any]:
    _sqlite_init()
    with sqlite3.connect(SQLITE_PATH) as con:
        cur = con.execute(
            "SELECT year_month, files_count, requests_count, updated_at FROM usage_monthly WHERE year_month = ?",
            (year_month,),
        )
        row = cur.fetchone()
    if not row:
        return {"year_month": year_month, "files_count": 0, "requests_count": 0, "updated_at": None}
    return {"year_month": row[0], "files_count": int(row[1]), "requests_count": int(row[2]), "updated_at": row[3]}


def _sqlite_total_add(files_delta: int, requests_delta: int):
    _ensure_sqlite_dir()
    _sqlite_init()
    now_iso = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(SQLITE_PATH) as con:
        con.execute(
            """
            UPDATE usage_total
               SET files_count = files_count + ?,
                   requests_count = requests_count + ?,
                   updated_at = ?
             WHERE id = 1;
            """,
            (int(files_delta), int(requests_delta), now_iso),
        )
        con.commit()


def _sqlite_total_get() -> Dict[str, Any]:
    _sqlite_init()
    with sqlite3.connect(SQLITE_PATH) as con:
        cur = con.execute("SELECT files_count, requests_count, updated_at FROM usage_total WHERE id = 1")
        row = cur.fetchone()
    if not row:
        return {"files_count": 0, "requests_count": 0, "updated_at": None}
    return {"files_count": int(row[0]), "requests_count": int(row[1]), "updated_at": row[2]}


def usage_increment(files_delta: int, requests_delta: int = 1) -> Dict[str, Any]:
    ym = _year_month_utc()
    with _DB_LOCK:
        _sqlite_upsert(ym, files_delta, requests_delta)
        return _sqlite_get(ym)


def usage_current() -> Dict[str, Any]:
    ym = _year_month_utc()
    with _DB_LOCK:
        return _sqlite_get(ym)


def usage_total_increment(files_delta: int, requests_delta: int = 1) -> Dict[str, Any]:
    with _DB_LOCK:
        _sqlite_total_add(files_delta, requests_delta)
        return _sqlite_total_get()


def usage_total_current() -> Dict[str, Any]:
    with _DB_LOCK:
        return _sqlite_total_get()


@app.get("/usage/current")
def usage_current_endpoint(x_api_key: str = Header(default=""), authorization: str = Header(default="")):
    check_api_key(x_api_key)
    check_bearer(authorization)
    return usage_current()


@app.get("/usage/total")
def usage_total_endpoint(x_api_key: str = Header(default=""), authorization: str = Header(default="")):
    check_api_key(x_api_key)
    check_bearer(authorization)
    return usage_total_current()


# ============================================================
# PLAN LIMIT (se configura por ENV en el backend)
# ============================================================
PLAN_LIMIT = int(os.getenv("PLAN_LIMIT", "100"))  # ej: 100 / 500 / 1000 / ...


def check_plan_limit_or_raise(files_to_add: int):
    """
    Bloquea validaciones cuando se alcanza el límite del plan.
    ✅ Control real en backend contra CONTADOR TOTAL (bolsa), no mensual.
    """
    usage = usage_total_current()
    used = int(usage.get("files_count", 0))
    limit = int(PLAN_LIMIT)

    if used + int(files_to_add) > limit:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "PLAN_LIMIT_REACHED",
                "message": "Ha alcanzado el límite de su plan. Renueve para continuar.",
                "used": used,
                "limit": limit,
            },
        )


# ============================================================
# EMAIL REPORT (Resend + Brevo)  ✅ ACTUALIZADO
# ============================================================
# ENV:
# - EMAIL_PROVIDER=resend | brevo | brevo_smtp
# - RESEND_API_KEY=...
# - BREVO_API_KEY=...              (solo si EMAIL_PROVIDER=brevo)
# - SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS (solo si EMAIL_PROVIDER=brevo_smtp)
# - SMTP_FROM="LexaCAE <no-reply@lexacae.com.ar>"
# - CLIENT_REPORT_EMAIL=... (CSV: a@a.com,b@b.com)
EMAIL_PROVIDER = (os.getenv("EMAIL_PROVIDER", "resend") or "").strip().lower()

RESEND_API_KEY = (os.getenv("RESEND_API_KEY", "") or "").strip()
BREVO_API_KEY = (os.getenv("BREVO_API_KEY", "") or "").strip()

SMTP_FROM = (os.getenv("SMTP_FROM", "") or "").strip()
CLIENT_REPORT_EMAIL = (os.getenv("CLIENT_REPORT_EMAIL", "") or "").strip()

SMTP_HOST = (os.getenv("SMTP_HOST", "") or "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or "587")
SMTP_USER = (os.getenv("SMTP_USER", "") or "").strip()
SMTP_PASS = (os.getenv("SMTP_PASS", "") or "").strip()


def _parse_emails_csv(s: str) -> List[str]:
    if not s:
        return []
    return [e.strip() for e in s.split(",") if e.strip()]


def _parse_from_name_email(from_value: str) -> Tuple[str, str]:
    """
    Soporta:
      - "Nombre <email@dominio>"
      - "email@dominio"
    """
    v = (from_value or "").strip()
    m = re.match(r'^\s*(?:"?([^"]*)"?\s*)?<([^>]+)>\s*$', v)
    if m:
        name = (m.group(1) or "").strip() or "LexaCAE"
        email = (m.group(2) or "").strip()
        return name, email
    return "LexaCAE", v


def send_usage_report_email(usage: Dict[str, Any]) -> Dict[str, Any]:
    provider = (EMAIL_PROVIDER or "").strip().lower()

    if not SMTP_FROM:
        raise RuntimeError("Falta SMTP_FROM en variables de entorno.")

    to_list = _parse_emails_csv(CLIENT_REPORT_EMAIL)
    if not to_list:
        raise RuntimeError("Falta CLIENT_REPORT_EMAIL (destinatario) en variables de entorno.")

    ym = usage.get("year_month") or "-"
    files_count = int(usage.get("files_count", 0) or 0)
    requests_count = int(usage.get("requests_count", 0) or 0)
    updated_at = usage.get("updated_at") or "-"

    subject = f"Resumen de uso - {ym} (Verificador CAE)"

    # Texto plano (backup)
    text = (
        f"Resumen de uso - {ym}\n"
        f"Estimado cliente,\n\n"
        f"PDFs procesados: {files_count}\n"
        f"Solicitudes realizadas: {requests_count}\n"
        f"Actualizado: {updated_at}\n\n"
        f"Gracias por usar nuestro servicio.\n"
    )

    # HTML (lo que se ve normalmente)
    html = (
        "<div style='font-family: Arial, sans-serif; line-height: 1.5;'>"
        f"<h2>Resumen de uso - {ym}</h2>"
        "<p>Estimado cliente,</p>"
        f"<p><b>PDFs procesados:</b> {files_count}<br>"
        f"<b>Solicitudes realizadas:</b> {requests_count}<br>"
        f"<b>Actualizado:</b> {updated_at}</p>"
        "<p>Gracias por usar nuestro servicio.</p>"
        "</div>"
    )

    # ---------------------------
    # Provider: RESEND (como venías)
    # ---------------------------
    if provider == "resend":
        if not RESEND_API_KEY:
            raise RuntimeError("Falta RESEND_API_KEY en variables de entorno.")

        resend.api_key = RESEND_API_KEY
        params = {
            "from": SMTP_FROM,
            "to": to_list,
            "subject": subject,
            "text": text,
            "html": html,
        }
        resp = resend.Emails.send(params)
        return {"ok": True, "provider": "resend", "to": to_list, "resend": resp}

    # ---------------------------
    # Provider: BREVO API (v3)
    # POST https://api.brevo.com/v3/smtp/email
    # ---------------------------
    if provider == "brevo":
        if not BREVO_API_KEY:
            raise RuntimeError("Falta BREVO_API_KEY en variables de entorno.")

        from_name, from_email = _parse_from_name_email(SMTP_FROM)
        if not from_email or "@" not in from_email:
            raise RuntimeError("SMTP_FROM inválido. Formato esperado: 'Nombre <email@dominio>' o 'email@dominio'.")

        payload = {
            "sender": {"name": from_name, "email": from_email},
            "to": [{"email": e} for e in to_list],
            "subject": subject,
            "htmlContent": html,
            "textContent": text,
        }

        r = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "Content-Type": "application/json"},
            json=payload,
            timeout=25,
        )
        if r.status_code >= 300:
            raise RuntimeError(f"Brevo API error {r.status_code}: {r.text[:800]}")

        return {"ok": True, "provider": "brevo", "to": to_list, "brevo": r.json()}

    # ---------------------------
    # Provider: BREVO SMTP
    # ---------------------------
    if provider == "brevo_smtp":
        if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
            raise RuntimeError("Faltan SMTP_HOST/SMTP_USER/SMTP_PASS para brevo_smtp.")
        if not SMTP_PORT:
            raise RuntimeError("Falta SMTP_PORT para brevo_smtp.")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = ", ".join(to_list)

        msg.attach(MIMEText(text, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))

        # sendmail espera dirección real como envelope-from
        _, from_email = _parse_from_name_email(SMTP_FROM)
        envelope_from = from_email if from_email and "@" in from_email else SMTP_FROM

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=25) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(envelope_from, to_list, msg.as_string())

        return {"ok": True, "provider": "brevo_smtp", "to": to_list}

    raise RuntimeError(f"EMAIL_PROVIDER no soportado: {provider}. Usá 'resend', 'brevo' o 'brevo_smtp'.")


@app.post("/usage/email")
def usage_email_endpoint(x_api_key: str = Header(default=""), authorization: str = Header(default="")):
    check_api_key(x_api_key)
    check_bearer(authorization)
    u = usage_current()  # ✅ email sigue siendo mensual (tu lógica original)
    try:
        return send_usage_report_email(u)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# PDF -> IMAGEN / QR / OCR
# ============================================================
def _pdf_page_to_png_bytes(pdf_bytes: bytes, page_index: int = 0, dpi: int = 220) -> bytes:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    page = doc.load_page(page_index)
    zoom = dpi / 72
    mat = fitz.Matrix(zoom, zoom)
    pix = page.get_pixmap(matrix=mat, alpha=False)
    return pix.tobytes("png")


def _try_extract_afip_qr(pdf_bytes: bytes, max_pages: int = 2) -> Dict[str, Any]:
    """
    Intenta leer QR AFIP (RG 4892). Devuelve dict si encuentra payload, si no {}.
    Maneja base64 urlsafe (con '-' '_' ) y prueba todos los QRs detectados.
    """
    for pi in range(max_pages):
        try:
            img_bytes = _pdf_page_to_png_bytes(pdf_bytes, page_index=pi, dpi=240)
            img = Image.open(io.BytesIO(img_bytes))
            codes = qr_decode(img)
            if not codes:
                continue

            for c in codes:
                raw = c.data.decode("utf-8", "ignore").strip()

                # suele ser URL con param 'p'
                if raw.startswith("http") and "p=" in raw:
                    from urllib.parse import urlparse, parse_qs

                    parsed = urlparse(raw)
                    qs = parse_qs(parsed.query)
                    p = (qs.get("p") or [None])[0]
                    if not p:
                        continue

                    pad = "=" * (-len(p) % 4)
                    payload_b64 = p + pad

                    payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8", "ignore")
                    import json

                    data = json.loads(payload_json)
                    if isinstance(data, dict) and data:
                        return data
        except Exception:
            continue
    return {}


def _ocr_pdf_text(pdf_bytes: bytes, max_pages: int = 2) -> str:
    """
    OCR de páginas iniciales. Usamos spa por si aparecen labels, pero nos interesa sobre todo números/fechas.
    """
    texts = []
    for pi in range(max_pages):
        try:
            img_bytes = _pdf_page_to_png_bytes(pdf_bytes, page_index=pi, dpi=260)
            img = Image.open(io.BytesIO(img_bytes))
            txt = pytesseract.image_to_string(img, lang="spa", config="--psm 6")
            if txt:
                texts.append(txt)
        except Exception:
            continue
    return "\n".join(texts)


# ============================================================
# PDF EXTRACTION (regex + heurísticas)
# ============================================================
CAE_PATTERNS = [
    re.compile(r"\bCAE\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bC\.?A\.?E\.?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bCAE\s*N[º°o]?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bCAE\s*NRO\.?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
]

VTO_PATTERNS = [
    re.compile(
        r"(?:Fecha\s+de\s+)?(?:Vto\.?\s*de\s*CAE|Vto\.?\s*CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{2}[/-]\d{2}[/-]\d{4})",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:Fecha\s+de\s+)?(?:Vto\.?\s*de\s*CAE|Vto\.?\s*CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{4}[/-]\d{2}[/-]\d{2})",
        re.IGNORECASE,
    ),
]

CBTETIPO_PATTERNS = [
    re.compile(r"\bCOD\.?\s*(\d{1,3})\b", re.IGNORECASE),
    re.compile(r"\bC[oó]digo\s*(\d{1,3})\b", re.IGNORECASE),
]

PTOVTA_PATTERNS = [
    re.compile(r"\bPunto\s+de\s+Venta:?\s*(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\bPto\.?\s*Vta\.?:?\s*(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\b(\d{4,5})\s*[-/]\s*(\d{6,10})\b"),
]

CBTENRO_PATTERNS = [
    re.compile(r"\bComp\.?\s*Nro:?\s*(\d{1,12})\b", re.IGNORECASE),
    re.compile(r"\bComprobante\s*N[º°o]?:?\s*(\d{1,12})\b", re.IGNORECASE),
    re.compile(r"\b(\d{4,5})\s*[-/]\s*(\d{6,10})\b"),
]

CBTEFCH_PATTERNS = [
    re.compile(r"\bFecha\s+de\s+Emisi[oó]n:?\s*(\d{2}[/-]\d{2}[/-]\d{4})\b", re.IGNORECASE),
    re.compile(r"\bFecha\s+de\s+Emisi[oó]n:?\s*(\d{4}[/-]\d{2}[/-]\d{2})\b", re.IGNORECASE),
    # fallback: "Fecha: 21/01/2026"
    re.compile(r"\bFecha:?\s*(\d{2}[/-]\d{2}[/-]\d{4})\b", re.IGNORECASE),
]

TOTAL_PATTERNS = [
    re.compile(
        r"\b(?:IMPORTE\s+TOTAL|TOTAL\s+A\s+PAGAR|IMP\.?\s*TOTAL|IMPORTE\s+FINAL|TOTAL)\b\D{0,80}(\d{1,3}(?:[.\s]\d{3})*(?:,\d{2})|\d+(?:,\d{2})|\d+(?:\.\d{2}))",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:IMPORTE\s+TOTAL|TOTAL\s+A\s+PAGAR|IMP\.?\s*TOTAL|TOTAL)\b\D{0,80}\$\s*(\d{1,3}(?:[.\s]\d{3})*(?:,\d{2})|\d+(?:,\d{2})|\d+(?:\.\d{2}))",
        re.IGNORECASE,
    ),
]

FACTURA_TIPO_PATTERNS = [
    re.compile(r"\bA\s+FACTURA\b", re.IGNORECASE),
    re.compile(r"\bB\s+FACTURA\b", re.IGNORECASE),
    re.compile(r"\bC\s+FACTURA\b", re.IGNORECASE),
    # fallback: "Factura A" / "Factura B"
    re.compile(r"\bFactura\s+([ABC])\b", re.IGNORECASE),
]

CUIT_AFTER_LABEL_RE = re.compile(r"\bCUIT:\s*([0-9]{11})\b", re.IGNORECASE)
CUIT_ANY_11_RE = re.compile(r"\b([0-9]{11})\b")
DNI_RE = re.compile(r"\bDNI\b\D{0,20}(\d{7,8})\b", re.IGNORECASE)


def extract_text_pdf(file_bytes: bytes, max_pages: int = 5) -> str:
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        texts = []
        for page in pdf.pages[:max_pages]:
            texts.append(page.extract_text() or "")
        return "\n".join(texts)


def find_first(patterns, text: str) -> Optional[str]:
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m.group(1)
    # fallback: ventana alrededor de "cae"
    idx = text.lower().find("cae")
    if idx != -1:
        window = text[idx: idx + 250]
        m2 = re.search(r"(\d{14})", window)
        if m2:
            return m2.group(1)
    return None


def find_ptovta(text: str) -> Optional[str]:
    for pat in PTOVTA_PATTERNS:
        m = pat.search(text)
        if m:
            if m.lastindex == 2:
                return m.group(1)
            return m.group(1)
    return None


def find_cbtenro(text: str) -> Optional[str]:
    for pat in CBTENRO_PATTERNS:
        m = pat.search(text)
        if m:
            if m.lastindex == 2:
                return m.group(2)
            return m.group(1)
    return None


def parse_date(date_str: Optional[str]):
    if not date_str:
        return None
    s = date_str.strip()
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            pass
    return None


def basic_format_ok(cae: Optional[str]) -> bool:
    return bool(cae and re.fullmatch(r"\d{14}", cae))


def date_to_yyyymmdd(d) -> Optional[str]:
    if not d:
        return None
    return d.strftime("%Y%m%d")


def normalize_amount_ar_to_float(s: Optional[str]) -> Optional[float]:
    """
    Normaliza importes AR (1.234,56) y protege contra falsos positivos:
    - si el "importe" parece un CAE (14 dígitos) => None
    - si es un número exagerado (muy probable parsing incorrecto) => None
    """
    if not s:
        return None
    x = s.strip().replace(" ", "")

    # si es un número "plano" de 14 dígitos, es casi seguro un CAE mal capturado
    if re.fullmatch(r"\d{14}", x):
        return None

    if "," in x:
        x = x.replace(".", "")
        x = x.replace(",", ".")
    try:
        v = float(x)
    except ValueError:
        return None

    # guardia de magnitud (evita mandar CAE/IDs como total)
    if v >= 1_000_000_000:
        return None

    return v


def detect_factura_letra(text: str) -> Optional[str]:
    for pat in FACTURA_TIPO_PATTERNS:
        m = pat.search(text)
        if m:
            g = m.group(0)
            if "Factura" in g or "FACTURA" in g:
                if m.lastindex:
                    return m.group(1).upper()
            return g.strip()[0].upper()
    return None


def extract_all_cuits(text: str) -> List[str]:
    cuits = []
    for m in CUIT_AFTER_LABEL_RE.finditer(text):
        cuits.append(m.group(1))

    if not cuits:
        for m in CUIT_ANY_11_RE.finditer(text):
            cuits.append(m.group(1))

    seen = set()
    out = []
    for c in cuits:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def decide_cuit_emisor(text: str) -> Optional[str]:
    cuits = extract_all_cuits(text)
    if cuits:
        return cuits[0]
    return None


def decide_receptor_doc(text: str, cuit_emisor: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Intenta deducir receptor desde el PDF:
    - si hay otro CUIT distinto al emisor => DocTipo=80
    - si hay DNI => DocTipo=96
    """
    cuit_emisor = (cuit_emisor or "").strip()
    cuits = extract_all_cuits(text)

    for c in cuits:
        if cuit_emisor and c == cuit_emisor:
            continue
        return 80, c

    dni = find_first([DNI_RE], text)
    if dni:
        return 96, dni

    return None, None


def _sanitize_receptor(doc_tipo: Optional[int], doc_nro: Optional[str]) -> Tuple[Optional[int], Optional[str]]:
    """
    Evita receptores imposibles (ej: DocTipo=96 y nro de 14 dígitos).
    """
    if not doc_tipo or not doc_nro:
        return None, None

    n = re.sub(r"\D+", "", str(doc_nro).strip())

    if doc_tipo == 80:
        if not re.fullmatch(r"\d{11}", n):
            return None, None
        return 80, n

    if doc_tipo == 96:
        if not re.fullmatch(r"\d{7,8}", n):
            return None, None
        return 96, n

    if len(n) < 5 or len(n) > 20:
        return None, None
    return int(doc_tipo), n


# ============================================================
# AFIP CONFIG (WSAA + WSCDC + WSFEv1)
# ============================================================
AFIP_ENV = os.getenv("AFIP_ENV", "prod").strip().lower()  # prod | homo

# ✅ WSCDC: CUIT consultante (TU CUIT, habilitado en tu cuenta)
AFIP_CUIT = os.getenv("AFIP_CUIT", "").strip()

# ✅ Credenciales "base" (TU CERT/KEY) para WSCDC (servicio consultante)
AFIP_CERT_B64 = os.getenv("AFIP_CERT_B64", "")
AFIP_KEY_B64 = os.getenv("AFIP_KEY_B64", "")

WSAA_URLS = {
    "prod": "https://wsaa.afip.gov.ar/ws/services/LoginCms",
    "homo": "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
}

# ✅ FIX: WSCDC PROD va en afip.gov.ar (no afip.gob.ar)
WSCDC_URLS = {
    "prod": "https://servicios1.afip.gov.ar/WSCDC/service.asmx",
    "homo": "https://wswhomo.afip.gob.ar/WSCDC/service.asmx",
}

# ✅ WSFEv1 endpoints
# (si querés, los podés pisar por ENV; si no, quedan estos defaults)
WSFE_URLS = {
    "prod": os.getenv("WSFE_URL_PROD", "https://servicios1.afip.gov.ar/wsfev1/service.asmx").strip(),
    "homo": os.getenv("WSFE_URL_HOMO", "https://wswhomo.afip.gob.ar/wsfev1/service.asmx").strip(),
}

WSAA_SOAP_ACTION = os.getenv("WSAA_SOAP_ACTION", "loginCms").strip()

# SOAPAction/NS suelen mantenerse con "afip.gob.ar" aunque el HOST sea "afip.gov.ar"
WSCDC_SOAP_ACTION = os.getenv(
    "WSCDC_SOAP_ACTION",
    "http://servicios1.afip.gob.ar/wscdc/ComprobanteConstatar",
).strip()
WSCDC_NS = os.getenv(
    "WSCDC_NS",
    "http://servicios1.afip.gob.ar/wscdc/",
).strip()

# WSFEv1 SOAP details
WSFE_NS = os.getenv("WSFE_NS", "http://ar.gov.afip.dif.FEV1/").strip()
WSFE_SOAP_ACTION = os.getenv("WSFE_SOAP_ACTION", "").strip()  # opcional; muchas implementaciones no lo requieren


def require_afip_env():
    if AFIP_ENV not in ("prod", "homo"):
        raise HTTPException(status_code=500, detail="AFIP_ENV debe ser 'prod' o 'homo'")
    if not AFIP_CUIT:
        raise HTTPException(status_code=500, detail="Falta AFIP_CUIT (CUIT consultante) en variables de entorno")
    if not AFIP_CERT_B64 or not AFIP_KEY_B64:
        raise HTTPException(status_code=500, detail="Faltan AFIP_CERT_B64 y/o AFIP_KEY_B64 en variables de entorno")


def b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


class AfipTLSAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.create_default_context(cafile=certifi.where())
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        pool_kwargs["ssl_context"] = ctx
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)


# Bundle CA explícito (útil en contenedores)
os.environ.setdefault("REQUESTS_CA_BUNDLE", certifi.where())
os.environ.setdefault("SSL_CERT_FILE", certifi.where())

AFIP_SESSION = requests.Session()
AFIP_SESSION.trust_env = False  # ✅ evita proxies del entorno (MITM / hostname mismatch)

AFIP_SESSION.mount("https://wsaa.afip.gov.ar", AfipTLSAdapter())
AFIP_SESSION.mount("https://wsaahomo.afip.gov.ar", AfipTLSAdapter())

# ✅ FIX: montar hosts correctos
AFIP_SESSION.mount("https://servicios1.afip.gov.ar", AfipTLSAdapter())
AFIP_SESSION.mount("https://wswhomo.afip.gob.ar", AfipTLSAdapter())


# ============================================================
# MULTI-TENANT STORE (SQLite)
# ============================================================
class TenantUpsertRequest(BaseModel):
    cuit: str = Field(..., description="CUIT emisor (11 dígitos)")
    cert_b64: str = Field(..., description="Certificado X509 en base64 (PEM o DER)")
    key_b64: str = Field(..., description="Clave privada en base64 (PEM o DER)")
    enabled: bool = True


def _norm_cuit(cuit: str) -> str:
    return re.sub(r"\D+", "", (cuit or "").strip())


def tenant_upsert(cuit: str, cert_b64: str, key_b64: str, enabled: bool = True) -> Dict[str, Any]:
    _sqlite_init()
    now_iso = datetime.now(timezone.utc).isoformat()
    c = _norm_cuit(cuit)
    if not re.fullmatch(r"\d{11}", c):
        raise HTTPException(status_code=400, detail="CUIT inválido (debe tener 11 dígitos).")
    if not cert_b64 or not key_b64:
        raise HTTPException(status_code=400, detail="Faltan cert_b64 y/o key_b64.")

    with sqlite3.connect(SQLITE_PATH) as con:
        con.execute(
            """
            INSERT INTO afip_tenants (cuit, cert_b64, key_b64, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(cuit) DO UPDATE SET
              cert_b64 = excluded.cert_b64,
              key_b64 = excluded.key_b64,
              enabled = excluded.enabled,
              updated_at = excluded.updated_at;
            """,
            (c, cert_b64.strip(), key_b64.strip(), 1 if enabled else 0, now_iso, now_iso),
        )
        con.commit()

    return {"ok": True, "cuit": c, "enabled": bool(enabled)}


def tenant_get(cuit: str) -> Optional[Dict[str, Any]]:
    _sqlite_init()
    c = _norm_cuit(cuit)
    with sqlite3.connect(SQLITE_PATH) as con:
        cur = con.execute(
            "SELECT cuit, cert_b64, key_b64, enabled, created_at, updated_at FROM afip_tenants WHERE cuit = ?",
            (c,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "cuit": row[0],
        "cert_b64": row[1],
        "key_b64": row[2],
        "enabled": bool(int(row[3] or 0)),
        "created_at": row[4],
        "updated_at": row[5],
    }


@app.post("/tenants/upsert")
def tenants_upsert_endpoint(
    payload: TenantUpsertRequest,
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
):
    # admin-only: mismo auth que tu sistema
    check_api_key(x_api_key)
    check_bearer(authorization)
    return tenant_upsert(payload.cuit, payload.cert_b64, payload.key_b64, payload.enabled)


@app.get("/tenants/{cuit}")
def tenants_get_endpoint(
    cuit: str,
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
):
    check_api_key(x_api_key)
    check_bearer(authorization)
    t = tenant_get(cuit)
    if not t:
        raise HTTPException(status_code=404, detail="Tenant no encontrado.")
    # no exponemos cert/key por seguridad
    return {"cuit": t["cuit"], "enabled": t["enabled"], "created_at": t["created_at"], "updated_at": t["updated_at"]}


# ============================================================
# WSAA HELPERS (firma + cache multi-tenant)
# ============================================================
def build_tra(service: str) -> str:
    now = datetime.now(timezone.utc)
    gen = now - timedelta(minutes=5)
    exp = now + timedelta(hours=8)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>{int(now.timestamp())}</uniqueId>
    <generationTime>{gen.isoformat()}</generationTime>
    <expirationTime>{exp.isoformat()}</expirationTime>
  </header>
  <service>{service}</service>
</loginTicketRequest>"""


def _run_openssl(cmd: List[str]) -> None:
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except FileNotFoundError:
        raise RuntimeError("No se encontró 'openssl' en el entorno (Render).")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"OpenSSL error: {e.stderr.decode('utf-8', 'ignore')}")


def normalize_cert_key_to_pem(cert_bytes: bytes, key_bytes: bytes) -> tuple[bytes, bytes]:
    cert_is_pem = b"BEGIN CERTIFICATE" in cert_bytes
    key_is_pem = b"BEGIN" in key_bytes

    if cert_is_pem and key_is_pem:
        return cert_bytes, key_bytes

    with tempfile.TemporaryDirectory() as tmp:
        cert_in = os.path.join(tmp, "cert_in.bin")
        key_in = os.path.join(tmp, "key_in.bin")
        cert_out = os.path.join(tmp, "cert.pem")
        key_out = os.path.join(tmp, "key.pem")

        with open(cert_in, "wb") as f:
            f.write(cert_bytes)
        with open(key_in, "wb") as f:
            f.write(key_bytes)

        if cert_is_pem:
            with open(cert_out, "wb") as f:
                f.write(cert_bytes)
        else:
            _run_openssl(["openssl", "x509", "-inform", "DER", "-in", cert_in, "-out", cert_out])

        if key_is_pem:
            with open(key_out, "wb") as f:
                f.write(key_bytes)
        else:
            _run_openssl(["openssl", "rsa", "-inform", "DER", "-in", key_in, "-out", key_out])

        with open(cert_out, "rb") as f:
            cert_pem = f.read()
        with open(key_out, "rb") as f:
            key_pem = f.read()

    return cert_pem, key_pem


def sign_tra_with_openssl(tra_xml: str, cert_pem: bytes, key_pem: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        cert_path = os.path.join(tmp, "cert.pem")
        key_path = os.path.join(tmp, "private.key")
        tra_path = os.path.join(tmp, "tra.xml")
        out_path = os.path.join(tmp, "tra.cms")

        with open(cert_path, "wb") as f:
            f.write(cert_pem)
        with open(key_path, "wb") as f:
            f.write(key_pem)
        with open(tra_path, "wb") as f:
            f.write(tra_xml.encode("utf-8"))

        cmd = [
            "openssl", "smime", "-sign",
            "-signer", cert_path,
            "-inkey", key_path,
            "-in", tra_path,
            "-out", out_path,
            "-outform", "DER",
            "-nodetach",
            "-binary",
        ]
        _run_openssl(cmd)

        with open(out_path, "rb") as f:
            return f.read()


# Cache TA: key = (tenant_cuit, service)
_TA_CACHE_MULTI: Dict[Tuple[str, str], Dict[str, Any]] = {}
_TA_LOCK = threading.Lock()


def wsaa_login_get_ta_for(
    service: str,
    tenant_cuit: str,
    cert_b64: str,
    key_b64: str,
) -> Dict[str, str]:
    """
    Devuelve {token, sign} para (tenant_cuit, service), con cache por expiración.
    """
    now = datetime.now(timezone.utc)
    key = (_norm_cuit(tenant_cuit), (service or "").strip().lower())

    with _TA_LOCK:
        c = _TA_CACHE_MULTI.get(key)
        if c and c.get("token") and c.get("sign") and c.get("exp_utc"):
            if now + timedelta(minutes=2) < c["exp_utc"]:
                return {"token": c["token"], "sign": c["sign"]}

    cert_bytes = b64_to_bytes(cert_b64)
    key_bytes = b64_to_bytes(key_b64)
    cert_pem, key_pem = normalize_cert_key_to_pem(cert_bytes, key_bytes)

    tra_xml = build_tra(service=service)
    cms_der = sign_tra_with_openssl(tra_xml, cert_pem, key_pem)
    cms_b64 = base64.b64encode(cms_der).decode("utf-8")

    wsaa_url = WSAA_URLS[AFIP_ENV]
    soap = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <loginCms xmlns="http://wsaa.view.sua.dvadac.desein.afip.gov">
      <in0>{cms_b64}</in0>
    </loginCms>
  </soap:Body>
</soap:Envelope>"""

    headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": WSAA_SOAP_ACTION}

    r = AFIP_SESSION.post(wsaa_url, data=soap.encode("utf-8"), headers=headers, timeout=40)
    if r.status_code != 200:
        raise RuntimeError(f"WSAA HTTP {r.status_code}: {r.text[:800]}")

    root = ET.fromstring(r.text)
    ta_xml = None
    for el in root.iter():
        if el.tag.endswith("loginCmsReturn"):
            ta_xml = el.text
            break
    if not ta_xml:
        raise RuntimeError("WSAA: no se encontró loginCmsReturn en la respuesta.")

    ta_root = ET.fromstring(ta_xml)
    token = ta_root.findtext(".//token")
    sign = ta_root.findtext(".//sign")
    exp_s = ta_root.findtext(".//expirationTime")
    if not token or not sign or not exp_s:
        raise RuntimeError("WSAA: TA incompleto (token/sign/expirationTime).")

    exp_utc = datetime.fromisoformat(exp_s.replace("Z", "+00:00")).astimezone(timezone.utc)

    with _TA_LOCK:
        _TA_CACHE_MULTI[key] = {"token": token, "sign": sign, "exp_utc": exp_utc}

    return {"token": token, "sign": sign}


# ============================================================
# WSCDC (VALIDACIÓN) — usa TU CUIT + TU CERT/KEY
# ============================================================
def wscdc_comprobante_constatar(
    cbte_tipo: int,
    pto_vta: int,
    cbte_nro: int,
    cbte_fch_yyyymmdd: str,
    cae: str,
    imp_total: float,
    cuit_emisor: str,
    doc_tipo_receptor: Optional[int] = None,
    doc_nro_receptor: Optional[str] = None,
) -> Dict[str, Any]:
    # ✅ WSCDC se autentica con TU CUIT (consultante) y TU cert/key
    ta = wsaa_login_get_ta_for(service="wscdc", tenant_cuit=AFIP_CUIT, cert_b64=AFIP_CERT_B64, key_b64=AFIP_KEY_B64)

    url = WSCDC_URLS[AFIP_ENV]
    cuit_consulta = AFIP_CUIT

    receptor_xml = ""
    if doc_tipo_receptor and doc_nro_receptor:
        receptor_xml = f"""
        <DocTipoReceptor>{int(doc_tipo_receptor)}</DocTipoReceptor>
        <DocNroReceptor>{str(doc_nro_receptor).strip()}</DocNroReceptor>"""

    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ComprobanteConstatar xmlns="{WSCDC_NS}">
      <Auth>
        <Token>{ta["token"]}</Token>
        <Sign>{ta["sign"]}</Sign>
        <Cuit>{cuit_consulta}</Cuit>
      </Auth>
      <CmpReq>
        <CbteModo>CAE</CbteModo>
        <CuitEmisor>{str(cuit_emisor).strip()}</CuitEmisor>{receptor_xml}
        <PtoVta>{pto_vta}</PtoVta>
        <CbteTipo>{cbte_tipo}</CbteTipo>
        <CbteNro>{cbte_nro}</CbteNro>
        <CbteFch>{cbte_fch_yyyymmdd}</CbteFch>
        <ImpTotal>{float(imp_total):.2f}</ImpTotal>
        <CodAutorizacion>{str(cae).strip()}</CodAutorizacion>
      </CmpReq>
    </ComprobanteConstatar>
  </soap:Body>
</soap:Envelope>"""

    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": f"\"{WSCDC_SOAP_ACTION}\"",
    }

    r = AFIP_SESSION.post(url, data=soap.encode("utf-8"), headers=headers, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"WSCDC HTTP {r.status_code}: {r.text[:2000]}")

    root = ET.fromstring(r.text)
    resultado = None
    for el in root.iter():
        if el.tag.lower().endswith("resultado") and el.text:
            resultado = el.text.strip()
            break

    return {"resultado": resultado, "raw": r.text}


# ============================================================
# WSFEv1 (FACTURACIÓN) — cada cliente emite con su CUIT y su cert/key
# ============================================================
class WsfeLastRequest(BaseModel):
    cuit: str
    pto_vta: int
    cbte_tipo: int


class AlicIva(BaseModel):
    id: int
    base_imp: float
    importe: float


class WsfeCaeRequest(BaseModel):
    cuit: str
    pto_vta: int
    cbte_tipo: int
    concepto: int = 1  # 1=Productos, 2=Servicios, 3=Productos y Servicios
    doc_tipo: int = 80  # 80=CUIT, 96=DNI, etc.
    doc_nro: str
    cbte_fch: str = Field(..., description="YYYYMMDD")

    imp_total: float
    imp_tot_conc: float = 0.0
    imp_neto: float = 0.0
    imp_op_ex: float = 0.0
    imp_trib: float = 0.0
    imp_iva: float = 0.0

    mon_id: str = "PES"
    mon_ctz: float = 1.0

    iva: List[AlicIva] = Field(default_factory=list)


# locks por numeración correlativa (por tenant+pto+tipo)
_WSFE_LOCKS: Dict[Tuple[str, int, int], threading.Lock] = {}
_WSFE_LOCKS_GUARD = threading.Lock()


def _wsfe_lock_for(cuit: str, pto_vta: int, cbte_tipo: int) -> threading.Lock:
    key = (_norm_cuit(cuit), int(pto_vta), int(cbte_tipo))
    with _WSFE_LOCKS_GUARD:
        if key not in _WSFE_LOCKS:
            _WSFE_LOCKS[key] = threading.Lock()
        return _WSFE_LOCKS[key]


def _wsfe_headers() -> Dict[str, str]:
    h = {"Content-Type": "text/xml; charset=utf-8"}
    if WSFE_SOAP_ACTION:
        h["SOAPAction"] = WSFE_SOAP_ACTION
    return h


def _wsfe_call(url: str, soap: str, timeout: int = 60) -> str:
    r = AFIP_SESSION.post(url, data=soap.encode("utf-8"), headers=_wsfe_headers(), timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"WSFE HTTP {r.status_code}: {r.text[:2500]}")
    return r.text


def wsfe_comp_ultimo_autorizado(tenant_cuit: str, pto_vta: int, cbte_tipo: int) -> Dict[str, Any]:
    t = tenant_get(tenant_cuit)
    if not t or not t.get("enabled"):
        raise HTTPException(status_code=404, detail="Tenant no encontrado o deshabilitado.")
    ta = wsaa_login_get_ta_for(service="wsfe", tenant_cuit=t["cuit"], cert_b64=t["cert_b64"], key_b64=t["key_b64"])

    url = WSFE_URLS[AFIP_ENV]
    cuit = t["cuit"]

    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:fe="{WSFE_NS}">
  <soap:Body>
    <fe:FECompUltimoAutorizado>
      <fe:Auth>
        <fe:Token>{ta["token"]}</fe:Token>
        <fe:Sign>{ta["sign"]}</fe:Sign>
        <fe:Cuit>{cuit}</fe:Cuit>
      </fe:Auth>
      <fe:PtoVta>{int(pto_vta)}</fe:PtoVta>
      <fe:CbteTipo>{int(cbte_tipo)}</fe:CbteTipo>
    </fe:FECompUltimoAutorizado>
  </soap:Body>
</soap:Envelope>"""

    raw = _wsfe_call(url, soap, timeout=60)

    root = ET.fromstring(raw)

    # Parse: buscamos CbteNro dentro de FECompUltimoAutorizadoResult
    cbte_nro = None
    for el in root.iter():
        if el.tag.endswith("CbteNro") and el.text:
            try:
                cbte_nro = int(el.text.strip())
                break
            except Exception:
                pass

    return {"cbte_nro": cbte_nro, "raw": raw}


def wsfe_cae_solicitar(req: WsfeCaeRequest) -> Dict[str, Any]:
    t = tenant_get(req.cuit)
    if not t or not t.get("enabled"):
        raise HTTPException(status_code=404, detail="Tenant no encontrado o deshabilitado.")

    tenant_cuit = t["cuit"]
    url = WSFE_URLS[AFIP_ENV]
    ta = wsaa_login_get_ta_for(service="wsfe", tenant_cuit=tenant_cuit, cert_b64=t["cert_b64"], key_b64=t["key_b64"])

    # Lock para numeración correlativa
    lock = _wsfe_lock_for(tenant_cuit, req.pto_vta, req.cbte_tipo)
    with lock:
        # 1) Traer último autorizado
        last = wsfe_comp_ultimo_autorizado(tenant_cuit, req.pto_vta, req.cbte_tipo)
        last_nro = int(last.get("cbte_nro") or 0)
        next_nro = last_nro + 1

        # IVA XML
        iva_xml = ""
        if req.iva:
            iva_items = []
            for it in req.iva:
                iva_items.append(
                    f"""
            <fe:AlicIva>
              <fe:Id>{int(it.id)}</fe:Id>
              <fe:BaseImp>{float(it.base_imp):.2f}</fe:BaseImp>
              <fe:Importe>{float(it.importe):.2f}</fe:Importe>
            </fe:AlicIva>"""
                )
            iva_xml = f"""
          <fe:Iva>
            {''.join(iva_items)}
          </fe:Iva>"""

        # ✅ doc nro limpio (evita backslash dentro del f-string)
        doc_nro_clean = _norm_cuit(req.doc_nro) if int(req.doc_tipo) == 80 else re.sub(r"\D+", "", str(req.doc_nro))

        soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:fe="{WSFE_NS}">
  <soap:Body>
    <fe:FECAESolicitar>
      <fe:Auth>
        <fe:Token>{ta["token"]}</fe:Token>
        <fe:Sign>{ta["sign"]}</fe:Sign>
        <fe:Cuit>{tenant_cuit}</fe:Cuit>
      </fe:Auth>
      <fe:FeCAEReq>
        <fe:FeCabReq>
          <fe:CantReg>1</fe:CantReg>
          <fe:PtoVta>{int(req.pto_vta)}</fe:PtoVta>
          <fe:CbteTipo>{int(req.cbte_tipo)}</fe:CbteTipo>
        </fe:FeCabReq>
        <fe:FeDetReq>
          <fe:FECAEDetRequest>
            <fe:Concepto>{int(req.concepto)}</fe:Concepto>
            <fe:DocTipo>{int(req.doc_tipo)}</fe:DocTipo>
            <fe:DocNro>{doc_nro_clean}</fe:DocNro>
            <fe:CbteDesde>{int(next_nro)}</fe:CbteDesde>
            <fe:CbteHasta>{int(next_nro)}</fe:CbteHasta>
            <fe:CbteFch>{str(req.cbte_fch).strip()}</fe:CbteFch>

            <fe:ImpTotal>{float(req.imp_total):.2f}</fe:ImpTotal>
            <fe:ImpTotConc>{float(req.imp_tot_conc):.2f}</fe:ImpTotConc>
            <fe:ImpNeto>{float(req.imp_neto):.2f}</fe:ImpNeto>
            <fe:ImpOpEx>{float(req.imp_op_ex):.2f}</fe:ImpOpEx>
            <fe:ImpTrib>{float(req.imp_trib):.2f}</fe:ImpTrib>
            <fe:ImpIVA>{float(req.imp_iva):.2f}</fe:ImpIVA>

            <fe:MonId>{str(req.mon_id).strip()}</fe:MonId>
            <fe:MonCotiz>{float(req.mon_ctz):.6f}</fe:MonCotiz>
            {iva_xml}
          </fe:FECAEDetRequest>
        </fe:FeDetReq>
      </fe:FeCAEReq>
    </fe:FECAESolicitar>
  </soap:Body>
</soap:Envelope>"""

        raw = _wsfe_call(url, soap, timeout=80)
        root = ET.fromstring(raw)

        # Parse resultado, CAE, vto, errores/obs
        cae = None
        cae_vto = None
        resultado = None
        obs = []
        errs = []

        for el in root.iter():
            tag = el.tag.split("}")[-1]
            if tag == "Resultado" and el.text:
                resultado = el.text.strip()
            if tag == "CAE" and el.text:
                cae = el.text.strip()
            if tag in ("CAEFchVto", "FchVto") and el.text:
                cae_vto = el.text.strip()

        # Observaciones/Errores (best-effort)
        for el in root.iter():
            tag = el.tag.split("}")[-1]
            if tag == "Obs":
                # dentro suelen venir Code/Msg
                code = None
                msg = None
                for ch in el.iter():
                    t2 = ch.tag.split("}")[-1]
                    if t2 in ("Code", "Codigo") and ch.text:
                        code = ch.text.strip()
                    if t2 in ("Msg", "Mensaje") and ch.text:
                        msg = ch.text.strip()
                if code or msg:
                    obs.append({"code": code, "msg": msg})
            if tag in ("Err", "Errors"):
                code = None
                msg = None
                for ch in el.iter():
                    t2 = ch.tag.split("}")[-1]
                    if t2 in ("Code", "Codigo") and ch.text:
                        code = ch.text.strip()
                    if t2 in ("Msg", "Mensaje") and ch.text:
                        msg = ch.text.strip()
                if code or msg:
                    errs.append({"code": code, "msg": msg})

        return {
            "resultado": resultado,
            "cuit": tenant_cuit,
            "pto_vta": int(req.pto_vta),
            "cbte_tipo": int(req.cbte_tipo),
            "cbte_nro": int(next_nro),
            "cae": cae,
            "cae_vto": cae_vto,
            "observaciones": obs,
            "errores": errs,
            "raw": raw,
        }


@app.post("/wsfe/last")
def wsfe_last_endpoint(
    payload: WsfeLastRequest,
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
):
    check_api_key(x_api_key)
    check_bearer(authorization)
    # WSFE no depende de tu AFIP_CUIT, depende del tenant; igual validamos env general
    if AFIP_ENV not in ("prod", "homo"):
        raise HTTPException(status_code=500, detail="AFIP_ENV debe ser 'prod' o 'homo'")
    return wsfe_comp_ultimo_autorizado(payload.cuit, payload.pto_vta, payload.cbte_tipo)


@app.post("/wsfe/cae")
def wsfe_cae_endpoint(
    payload: WsfeCaeRequest,
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
):
    check_api_key(x_api_key)
    check_bearer(authorization)
    if AFIP_ENV not in ("prod", "homo"):
        raise HTTPException(status_code=500, detail="AFIP_ENV debe ser 'prod' o 'homo'")
    # Contabilizamos request (sin tocar tu PLAN_LIMIT de PDFs)
    try:
        usage_total_increment(files_delta=0, requests_delta=1)
        usage_increment(files_delta=0, requests_delta=1)
    except Exception:
        pass
    try:
        return wsfe_cae_solicitar(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# VERIFY ENDPOINT (PROD) — TU LÓGICA, INTACTA
# ============================================================
@app.post("/verify")
async def verify(
    files: List[UploadFile] = File(...),
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
):
    check_api_key(x_api_key)
    check_bearer(authorization)
    require_afip_env()

    # ============================================================
    # PLAN LIMIT CHECK (ANTES DE PROCESAR / CONTAR)
    # ============================================================
    check_plan_limit_or_raise(files_to_add=len(files))

    # contador TOTAL (bolsa real) + mensual (solo reportes)
    try:
        usage_total_increment(files_delta=len(files), requests_delta=1)
    except Exception:
        pass

    try:
        usage_increment(files_delta=len(files), requests_delta=1)
    except Exception:
        pass

    today = datetime.now().date()
    out_rows: List[Dict[str, Any]] = []

    for f in files:
        try:
            pdf_bytes = await f.read()

            # 1) Intentar QR primero (lo más robusto)
            qr = _try_extract_afip_qr(pdf_bytes, max_pages=2)

            # 2) Texto normal por pdfplumber
            text = extract_text_pdf(pdf_bytes, max_pages=5)

            # Si casi no hay texto, OCR ayuda muchísimo
            if len((text or "").strip()) < 40:
                text_ocr = _ocr_pdf_text(pdf_bytes, max_pages=2)
                text = (text or "") + "\n" + (text_ocr or "")

            # --- campos desde texto ---
            cae_pdf = find_first(CAE_PATTERNS, text)
            vto_raw = find_first(VTO_PATTERNS, text)
            vto_pdf = parse_date(vto_raw)

            cbte_tipo_raw = find_first(CBTETIPO_PATTERNS, text)
            pto_vta_raw = find_ptovta(text)
            cbte_nro_raw = find_cbtenro(text)
            cbte_fch_raw = find_first(CBTEFCH_PATTERNS, text)
            cbte_fch = parse_date(cbte_fch_raw)

            factura_letra = detect_factura_letra(text)
            total_raw = find_first(TOTAL_PATTERNS, text)
            imp_total = normalize_amount_ar_to_float(total_raw)

            cbte_tipo = int(cbte_tipo_raw) if cbte_tipo_raw else None
            pto_vta = int(pto_vta_raw) if pto_vta_raw else None
            cbte_nro = int(cbte_nro_raw) if cbte_nro_raw else None
            cbte_fch_yyyymmdd = date_to_yyyymmdd(cbte_fch)

            cuit_emisor = decide_cuit_emisor(text)

            # receptor desde PDF (luego lo pisamos con QR si existe)
            doc_tipo_rec, doc_nro_rec = decide_receptor_doc(text, cuit_emisor=cuit_emisor or "")
            doc_tipo_rec, doc_nro_rec = _sanitize_receptor(doc_tipo_rec, doc_nro_rec)

            # --- aplicar QR como “source of truth” si viene ---
            if qr:
                try:
                    # Emisor / Comprobante
                    if qr.get("cuit"):
                        cuit_emisor = str(qr.get("cuit")).strip() or cuit_emisor
                    if qr.get("ptoVta") is not None:
                        pto_vta = int(qr.get("ptoVta"))
                    if qr.get("tipoCmp") is not None:
                        cbte_tipo = int(qr.get("tipoCmp"))
                    if qr.get("nroCmp") is not None:
                        cbte_nro = int(qr.get("nroCmp"))

                    # Fecha
                    fqr = (qr.get("fecha") or "").strip()
                    if fqr:
                        if "-" in fqr and len(fqr) >= 10:
                            cbte_fch_yyyymmdd = fqr[:10].replace("-", "")
                        elif "/" in fqr:
                            try:
                                d = datetime.strptime(fqr, "%d/%m/%Y").date()
                                cbte_fch_yyyymmdd = d.strftime("%Y%m%d")
                            except Exception:
                                pass

                    # Importe
                    if qr.get("importe") is not None:
                        try:
                            imp_total = float(qr.get("importe"))
                        except Exception:
                            pass

                    # CAE
                    if qr.get("codAut"):
                        cae_pdf = str(qr.get("codAut")).strip()

                    # ✅ Receptor desde QR (cuando existe)
                    q_tipo_doc = qr.get("tipoDocRec")
                    q_nro_doc = qr.get("nroDocRec")
                    if q_tipo_doc is not None and q_nro_doc is not None:
                        doc_tipo_rec, doc_nro_rec = _sanitize_receptor(int(q_tipo_doc), str(q_nro_doc))
                except Exception:
                    pass

            # ✅ Guardias finales contra falsos positivos:
            if cae_pdf and imp_total is not None:
                try:
                    if str(int(round(float(imp_total)))) == str(cae_pdf).strip():
                        imp_total = None
                except Exception:
                    pass

            # si siguen faltando campos críticos, hacemos OCR “más agresivo”
            missing_critical = (
                (cbte_fch_yyyymmdd is None)
                or (imp_total is None)
                or (cbte_tipo is None)
                or (pto_vta is None)
                or (cbte_nro is None)
                or (not cuit_emisor)
            )
            if missing_critical:
                text_ocr2 = _ocr_pdf_text(pdf_bytes, max_pages=3)
                if text_ocr2:
                    text2 = (text or "") + "\n" + text_ocr2

                    # reintentar parse sobre texto extendido
                    cae_pdf = cae_pdf or find_first(CAE_PATTERNS, text2)
                    vto_raw = vto_raw or find_first(VTO_PATTERNS, text2)
                    vto_pdf = vto_pdf or parse_date(vto_raw)

                    cbte_tipo_raw = cbte_tipo_raw or find_first(CBTETIPO_PATTERNS, text2)
                    pto_vta_raw = pto_vta_raw or find_ptovta(text2)
                    cbte_nro_raw = cbte_nro_raw or find_cbtenro(text2)
                    cbte_fch_raw = cbte_fch_raw or find_first(CBTEFCH_PATTERNS, text2)
                    cbte_fch = cbte_fch or parse_date(cbte_fch_raw)

                    factura_letra = factura_letra or detect_factura_letra(text2)
                    total_raw = total_raw or find_first(TOTAL_PATTERNS, text2)
                    imp_total = imp_total if imp_total is not None else normalize_amount_ar_to_float(total_raw)

                    cbte_tipo = cbte_tipo if cbte_tipo is not None else (int(cbte_tipo_raw) if cbte_tipo_raw else None)
                    pto_vta = pto_vta if pto_vta is not None else (int(pto_vta_raw) if pto_vta_raw else None)
                    cbte_nro = cbte_nro if cbte_nro is not None else (int(cbte_nro_raw) if cbte_nro_raw else None)
                    cbte_fch_yyyymmdd = cbte_fch_yyyymmdd or date_to_yyyymmdd(cbte_fch)

                    cuit_emisor = cuit_emisor or decide_cuit_emisor(text2)

                    # receptor desde OCR (solo si no había y no vino por QR)
                    if not doc_tipo_rec or not doc_nro_rec:
                        dtr2, dnr2 = decide_receptor_doc(text2, cuit_emisor=cuit_emisor or "")
                        dtr2, dnr2 = _sanitize_receptor(dtr2, dnr2)
                        doc_tipo_rec = doc_tipo_rec or dtr2
                        doc_nro_rec = doc_nro_rec or dnr2

                    # guardia ImpTotal vs CAE (otra vez)
                    if cae_pdf and imp_total is not None:
                        try:
                            if str(int(round(float(imp_total)))) == str(cae_pdf).strip():
                                imp_total = None
                        except Exception:
                            pass

            status = []
            status.append("CAE encontrado" if cae_pdf else "CAE NO encontrado")
            if basic_format_ok(cae_pdf):
                status.append("Formato OK")
            elif cae_pdf:
                status.append("Formato dudoso")
            if vto_pdf:
                status.append("Vigente" if vto_pdf >= today else "Vencido")
            else:
                status.append("Vto no detectado")
            if factura_letra:
                status.append(f"Factura {factura_letra}")
            if qr:
                status.append("QR detectado")
            if len((text or "").strip()) < 40 or missing_critical:
                status.append("OCR aplicado")

            # Reglas automáticas A/B/C
            require_receptor = (factura_letra == "A")

            # ✅ Para FACTURA A: si el QR no trajo receptor, NO usar DNI “por defecto”.
            if require_receptor:
                if doc_tipo_rec != 80:
                    doc_tipo_rec, doc_nro_rec = None, None

            missing = []
            if cbte_tipo is None:
                missing.append("CbteTipo")
            if pto_vta is None:
                missing.append("PtoVta")
            if cbte_nro is None:
                missing.append("CbteNro")
            if not cbte_fch_yyyymmdd:
                missing.append("CbteFch")
            if not cae_pdf:
                missing.append("CAE")
            if imp_total is None:
                missing.append("ImpTotal")
            if not cuit_emisor:
                missing.append("CuitEmisor(PDF/QR)")

            if require_receptor:
                if not doc_tipo_rec:
                    missing.append("DocTipoReceptor")
                if not doc_nro_rec:
                    missing.append("DocNroReceptor")

            if missing:
                out_rows.append(
                    {
                        "Archivo": f.filename,
                        "CAE": cae_pdf or "",
                        "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                        "Estado": " | ".join(status),
                        "Factura": factura_letra or "",
                        "CbteTipo": cbte_tipo_raw or (str(cbte_tipo) if cbte_tipo else ""),
                        "PtoVta": pto_vta_raw or (str(pto_vta) if pto_vta else ""),
                        "CbteNro": cbte_nro_raw or (str(cbte_nro) if cbte_nro else ""),
                        "CbteFch": cbte_fch_raw or (cbte_fch_yyyymmdd or ""),
                        "ImpTotal": total_raw or (f"{imp_total:.2f}" if imp_total is not None else ""),
                        "CuitEmisor": cuit_emisor or "",
                        "DocTipoRec": str(doc_tipo_rec) if doc_tipo_rec else "",
                        "DocNroRec": doc_nro_rec or "",
                        "AFIP": "DATOS_INSUFICIENTES",
                        "Detalle AFIP": "Datos insuficientes para validar",
                    }
                )
                continue

            try:
                res = wscdc_comprobante_constatar(
                    cbte_tipo=int(cbte_tipo),
                    pto_vta=int(pto_vta),
                    cbte_nro=int(cbte_nro),
                    cbte_fch_yyyymmdd=str(cbte_fch_yyyymmdd),
                    cae=str(cae_pdf).strip(),
                    imp_total=float(imp_total),
                    cuit_emisor=str(cuit_emisor).strip(),
                    doc_tipo_receptor=doc_tipo_rec,
                    doc_nro_receptor=doc_nro_rec,
                )

                resultado = (res.get("resultado") or "").strip()
                if resultado:
                    afip_ok = resultado.upper() in ("A", "OK", "APROBADO")
                    out_rows.append(
                        {
                            "Archivo": f.filename,
                            "CAE": cae_pdf or "",
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "Factura": factura_letra or "",
                            "CbteTipo": int(cbte_tipo),
                            "PtoVta": int(pto_vta),
                            "CbteNro": int(cbte_nro),
                            "CbteFch": cbte_fch_yyyymmdd,
                            "ImpTotal": f"{float(imp_total):.2f}",
                            "CuitEmisor": cuit_emisor,
                            "DocTipoRec": str(doc_tipo_rec) if doc_tipo_rec else "",
                            "DocNroRec": doc_nro_rec or "",
                            "AFIP": "OK" if afip_ok else "NO_CONSTA",
                            "Detalle AFIP": "Autorizado por AFIP" if afip_ok else "No consta en AFIP",
                        }
                    )
                else:
                    out_rows.append(
                        {
                            "Archivo": f.filename,
                            "CAE": cae_pdf or "",
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "Factura": factura_letra or "",
                            "CbteTipo": int(cbte_tipo),
                            "PtoVta": int(pto_vta),
                            "CbteNro": int(cbte_nro),
                            "CbteFch": cbte_fch_yyyymmdd,
                            "ImpTotal": f"{float(imp_total):.2f}",
                            "CuitEmisor": cuit_emisor,
                            "DocTipoRec": str(doc_tipo_rec) if doc_tipo_rec else "",
                            "DocNroRec": doc_nro_rec or "",
                            "AFIP": "OK_HTTP",
                            "Detalle AFIP": "AFIP respondió correctamente",
                        }
                    )

            except Exception:
                out_rows.append(
                    {
                        "Archivo": f.filename,
                        "CAE": cae_pdf or "",
                        "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                        "Estado": " | ".join(status),
                        "Factura": factura_letra or "",
                        "CbteTipo": int(cbte_tipo) if cbte_tipo is not None else "",
                        "PtoVta": int(pto_vta) if pto_vta is not None else "",
                        "CbteNro": int(cbte_nro) if cbte_nro is not None else "",
                        "CbteFch": cbte_fch_yyyymmdd or "",
                        "ImpTotal": f"{float(imp_total):.2f}" if imp_total is not None else "",
                        "CuitEmisor": cuit_emisor or "",
                        "DocTipoRec": str(doc_tipo_rec) if doc_tipo_rec else "",
                        "DocNroRec": doc_nro_rec or "",
                        "AFIP": "ERROR_AFIP",
                        "Detalle AFIP": "Error al validar contra AFIP",
                    }
                )

        except Exception as e:
            out_rows.append(
                {
                    "Archivo": getattr(f, "filename", "archivo"),
                    "CAE": "",
                    "Vto CAE": "",
                    "Estado": f"Error procesando PDF: {e}",
                    "Factura": "",
                    "CbteTipo": "",
                    "PtoVta": "",
                    "CbteNro": "",
                    "CbteFch": "",
                    "ImpTotal": "",
                    "CuitEmisor": "",
                    "DocTipoRec": "",
                    "DocNroRec": "",
                    "AFIP": "ERROR",
                    "Detalle AFIP": "Error procesando el PDF",
                }
            )

    return {"rows": out_rows}