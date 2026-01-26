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
from pydantic import BaseModel

# ===== Email (Resend) =====
import resend


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


def _sqlite_init():
    with sqlite3.connect(SQLITE_PATH) as con:
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
        con.commit()


def _sqlite_upsert(year_month: str, files_delta: int, requests_delta: int):
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


def usage_increment(files_delta: int, requests_delta: int = 1) -> Dict[str, Any]:
    ym = _year_month_utc()
    with _DB_LOCK:
        _sqlite_upsert(ym, files_delta, requests_delta)
        return _sqlite_get(ym)


def usage_current() -> Dict[str, Any]:
    ym = _year_month_utc()
    with _DB_LOCK:
        return _sqlite_get(ym)


@app.get("/usage/current")
def usage_current_endpoint(x_api_key: str = Header(default=""), authorization: str = Header(default="")):
    check_api_key(x_api_key)
    check_bearer(authorization)
    return usage_current()


# ============================================================
# EMAIL REPORT (Alineado a tus ENV actuales)
# ============================================================
# ENV según tu screenshot:
# - EMAIL_PROVIDER=resend
# - RESEND_API_KEY=...
# - SMTP_FROM="Verificador CAE <onboarding@resend.dev>"  (lo usamos como FROM)
# - CLIENT_REPORT_EMAIL=derricoelias@gmail.com           (destinatario)
EMAIL_PROVIDER = (os.getenv("EMAIL_PROVIDER", "resend") or "").strip().lower()
RESEND_API_KEY = (os.getenv("RESEND_API_KEY", "") or "").strip()
SMTP_FROM = (os.getenv("SMTP_FROM", "") or "").strip()
CLIENT_REPORT_EMAIL = (os.getenv("CLIENT_REPORT_EMAIL", "") or "").strip()


def _parse_emails_csv(s: str) -> List[str]:
    if not s:
        return []
    return [e.strip() for e in s.split(",") if e.strip()]


def send_usage_report_email(usage: Dict[str, Any]) -> Dict[str, Any]:
    if EMAIL_PROVIDER != "resend":
        raise RuntimeError(f"EMAIL_PROVIDER no soportado: {EMAIL_PROVIDER}. Usá 'resend'.")

    if not RESEND_API_KEY:
        raise RuntimeError("Falta RESEND_API_KEY en variables de entorno.")
    if not SMTP_FROM:
        raise RuntimeError("Falta SMTP_FROM en variables de entorno (From verificado/permitido por Resend).")

    to_list = _parse_emails_csv(CLIENT_REPORT_EMAIL)
    if not to_list:
        raise RuntimeError("Falta CLIENT_REPORT_EMAIL (destinatario) en variables de entorno.")

    resend.api_key = RESEND_API_KEY

    ym = usage.get("year_month") or "-"
    files_count = int(usage.get("files_count", 0) or 0)
    requests_count = int(usage.get("requests_count", 0) or 0)
    updated_at = usage.get("updated_at") or "-"

    subject = f"Resumen de uso - {ym} (Verificador CAE)"
    text = (
        f"Resumen de uso - {ym}\n"
        f"PDFs procesados: {files_count}\n"
        f"Solicitudes realizadas: {requests_count}\n"
        f"Actualizado: {updated_at}\n"
    )
    html = f"""
    <div style="font-family: Arial, sans-serif; line-height: 1.4;">
      <h2>Resumen de uso - {ym}</h2>
      <ul>
        <li><b>PDFs procesados:</b> {files_count}</li>
        <li><b>Solicitudes realizadas:</b> {requests_count}</li>
        <li><b>Actualizado:</b> {updated_at}</li>
      </ul>
    </div>
    """

    params: resend.Emails.SendParams = {
        "from": SMTP_FROM,
        "to": to_list,
        "subject": subject,
        "text": text,
        "html": html,
    }

    resp = resend.Emails.send(params)
    return {"ok": True, "provider": "resend", "to": to_list, "resend": resp}


@app.post("/usage/email")
def usage_email_endpoint(x_api_key: str = Header(default=""), authorization: str = Header(default="")):
    check_api_key(x_api_key)
    check_bearer(authorization)
    u = usage_current()
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
    # Ajustá el umbral si tu negocio realmente factura arriba de 1.000 millones
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

    # otros tipos: dejamos pasar solo si hay número razonable
    if len(n) < 5 or len(n) > 20:
        return None, None
    return int(doc_tipo), n


# ============================================================
# AFIP CONFIG (WSAA + WSCDC)
# ============================================================
AFIP_ENV = os.getenv("AFIP_ENV", "prod").strip().lower()  # prod | homo
AFIP_CUIT = os.getenv("AFIP_CUIT", "").strip()
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

# ✅ FIX: montar host correcto de WSCDC PROD
AFIP_SESSION.mount("https://servicios1.afip.gov.ar", AfipTLSAdapter())
AFIP_SESSION.mount("https://wswhomo.afip.gob.ar", AfipTLSAdapter())


_TA_CACHE: Dict[str, Any] = {"token": None, "sign": None, "exp_utc": None}


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


def wsaa_login_get_ta(service: str = "wscdc") -> Dict[str, str]:
    now = datetime.now(timezone.utc)
    if _TA_CACHE["token"] and _TA_CACHE["sign"] and _TA_CACHE["exp_utc"]:
        if now + timedelta(minutes=2) < _TA_CACHE["exp_utc"]:
            return {"token": _TA_CACHE["token"], "sign": _TA_CACHE["sign"]}

    cert_bytes = b64_to_bytes(AFIP_CERT_B64)
    key_bytes = b64_to_bytes(AFIP_KEY_B64)
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
    _TA_CACHE["token"] = token
    _TA_CACHE["sign"] = sign
    _TA_CACHE["exp_utc"] = exp_utc

    return {"token": token, "sign": sign}


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
    ta = wsaa_login_get_ta(service="wscdc")

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
# VERIFY ENDPOINT (PROD)
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

    # contador: suma por request + cantidad de archivos
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
                (cbte_fch_yyyymmdd is None) or (imp_total is None) or (cbte_tipo is None) or
                (pto_vta is None) or (cbte_nro is None) or (not cuit_emisor)
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
                        "Detalle AFIP": f"Faltan campos para WSCDC: {', '.join(missing)}.",
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
                            "Detalle AFIP": (
                                f"WSCDC Resultado={resultado} | Enviado: "
                                f"CuitEmisor={cuit_emisor} PtoVta={pto_vta} CbteTipo={cbte_tipo} "
                                f"CbteNro={cbte_nro} CbteFch={cbte_fch_yyyymmdd} "
                                f"ImpTotal={float(imp_total):.2f} CAE={str(cae_pdf).strip()} "
                                f"DocTipoRec={doc_tipo_rec or ''} DocNroRec={doc_nro_rec or ''}"
                            ),
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
                            "Detalle AFIP": "WSCDC respondió 200. No se detectó campo 'Resultado'.",
                        }
                    )

            except Exception as e:
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
                        "Detalle AFIP": str(e)[:2000],
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
                    "Detalle AFIP": str(e)[:1200],
                }
            )

    return {"rows": out_rows}
