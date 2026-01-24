import os
import io
import re
import base64
import subprocess
import tempfile
import threading
import sqlite3
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Tuple
import xml.etree.ElementTree as ET

import pdfplumber
import requests

# ===== TLS adapter (FIX DH_KEY_TOO_SMALL) =====
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from fastapi import FastAPI, Header, HTTPException, UploadFile, File
from pydantic import BaseModel


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
    # Producción real: JWT con exp. Hoy: token fijo por env.
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
# USAGE COUNTER (SQLite en Render Disk)
# ============================================================
# Recomendado en Render:
# SQLITE_PATH=/var/data/usage.db  (si montás Render Disk en /var/data)
SQLITE_PATH = os.getenv("SQLITE_PATH", "usage.db").strip()
_DB_LOCK = threading.Lock()

# Email settings (SMTP Gmail)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587").strip())
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()  # App Password de Gmail
SMTP_FROM = os.getenv("SMTP_FROM", "").strip()  # Ej: "Verificador CAE <tu@gmail.com>"
CLIENT_REPORT_EMAIL = os.getenv("CLIENT_REPORT_EMAIL", "").strip()
APP_NAME = os.getenv("APP_NAME", "Verificador CAE").strip()


def _year_month_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _sqlite_init():
    # Crea tabla si no existe
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
    _sqlite_init()
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


def _send_usage_email(payload: Dict[str, Any]) -> None:
    if not CLIENT_REPORT_EMAIL:
        raise RuntimeError("Falta CLIENT_REPORT_EMAIL en env vars.")
    if not SMTP_USER or not SMTP_PASS:
        raise RuntimeError("Faltan SMTP_USER / SMTP_PASS (App Password) en env vars.")

    msg = EmailMessage()
    sender = SMTP_FROM if SMTP_FROM else SMTP_USER
    msg["From"] = sender
    msg["To"] = CLIENT_REPORT_EMAIL
    msg["Subject"] = f"[{APP_NAME}] Reporte de uso mensual {payload.get('year_month','')}"
    body = (
        f"{APP_NAME} - Reporte de uso mensual\n\n"
        f"Mes (UTC): {payload.get('year_month')}\n"
        f"Requests: {payload.get('requests_count')}\n"
        f"Archivos procesados: {payload.get('files_count')}\n"
        f"Última actualización: {payload.get('updated_at')}\n"
    )
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


@app.on_event("startup")
def on_startup():
    # Inicializa la DB al levantar (así la tabla existe aunque no hayan consultas)
    try:
        _sqlite_init()
    except Exception:
        # No frenamos el servicio por el contador
        pass


@app.get("/usage/current")
def usage_current_endpoint(x_api_key: str = Header(default=""), authorization: str = Header(default="")):
    check_api_key(x_api_key)
    check_bearer(authorization)
    return usage_current()


@app.post("/usage/email")
def usage_email_endpoint(x_api_key: str = Header(default=""), authorization: str = Header(default="")):
    check_api_key(x_api_key)
    check_bearer(authorization)

    data = usage_current()
    _send_usage_email(data)
    return {"ok": True, "sent_to": CLIENT_REPORT_EMAIL, "usage": data}


# ============================================================
# PDF EXTRACTION
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
]

TOTAL_PATTERNS = [
    re.compile(
        r"\b(?:IMPORTE\s+TOTAL|TOTAL\s+A\s+PAGAR|IMP\.?\s*TOTAL|IMPORTE\s+FINAL|TOTAL)\b\D{0,60}(\d{1,3}(?:[.\s]\d{3})*(?:,\d{2})|\d+(?:,\d{2})|\d+(?:\.\d{2}))",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:IMPORTE\s+TOTAL|TOTAL\s+A\s+PAGAR|IMP\.?\s*TOTAL|TOTAL)\b\D{0,60}\$\s*(\d{1,3}(?:[.\s]\d{3})*(?:,\d{2})|\d+(?:,\d{2})|\d+(?:\.\d{2}))",
        re.IGNORECASE,
    ),
]

FACTURA_TIPO_PATTERNS = [
    re.compile(r"\bA\s+FACTURA\b", re.IGNORECASE),
    re.compile(r"\bB\s+FACTURA\b", re.IGNORECASE),
    re.compile(r"\bC\s+FACTURA\b", re.IGNORECASE),
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
    if not s:
        return None
    x = s.strip().replace(" ", "")
    if "," in x:
        x = x.replace(".", "")
        x = x.replace(",", ".")
    try:
        return float(x)
    except ValueError:
        return None


def detect_factura_letra(text: str) -> Optional[str]:
    for pat in FACTURA_TIPO_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0).strip()[0].upper()
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


# ============================================================
# AFIP CONFIG (WSAA + WSCDC)
# ============================================================
AFIP_ENV = os.getenv("AFIP_ENV", "prod").strip().lower()  # prod | homo
AFIP_CUIT = os.getenv("AFIP_CUIT", "").strip()  # CUIT consultante (cert)

AFIP_CERT_B64 = os.getenv("AFIP_CERT_B64", "")
AFIP_KEY_B64 = os.getenv("AFIP_KEY_B64", "")

WSAA_URLS = {
    "prod": "https://wsaa.afip.gov.ar/ws/services/LoginCms",
    "homo": "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
}

WSCDC_URLS = {
    "prod": "https://servicios1.afip.gov.ar/WSCDC/service.asmx",
    "homo": "https://wswhomo.afip.gob.ar/WSCDC/service.asmx",
}

WSAA_SOAP_ACTION = os.getenv("WSAA_SOAP_ACTION", "loginCms").strip()
WSCDC_SOAP_ACTION = os.getenv("WSCDC_SOAP_ACTION", "http://servicios1.afip.gob.ar/wscdc/ComprobanteConstatar").strip()
WSCDC_NS = os.getenv("WSCDC_NS", "http://servicios1.afip.gob.ar/wscdc/").strip()


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
        ctx = ssl.create_default_context()
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        pool_kwargs["ssl_context"] = ctx
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)


AFIP_SESSION = requests.Session()
AFIP_SESSION.mount("https://wsaa.afip.gov.ar", AfipTLSAdapter())
AFIP_SESSION.mount("https://wsaahomo.afip.gov.ar", AfipTLSAdapter())
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
            "openssl",
            "smime",
            "-sign",
            "-signer",
            cert_path,
            "-inkey",
            key_path,
            "-in",
            tra_path,
            "-out",
            out_path,
            "-outform",
            "DER",
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
    cuit_consulta = AFIP_CUIT  # CUIT consultante (cert)

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

    # Contador mensual (cliente por deploy): suma por request y por cantidad de archivos
    try:
        usage_increment(files_delta=len(files), requests_delta=1)
    except Exception:
        # No frenamos la validación AFIP por un tema de métricas
        pass

    today = datetime.now().date()
    out_rows: List[Dict[str, Any]] = []

    for f in files:
        try:
            pdf_bytes = await f.read()
            text = extract_text_pdf(pdf_bytes, max_pages=5)

            cae_pdf = find_first(CAE_PATTERNS, text)
            vto_raw = find_first(VTO_PATTERNS, text)
            vto_pdf = parse_date(vto_raw)

            cbte_tipo_raw = find_first(CBTETIPO_PATTERNS, text)
            pto_vta_raw = find_ptovta(text)
            cbte_nro_raw = find_cbtenro(text)
            cbte_fch_raw = find_first(CBTEFCH_PATTERNS, text)
            cbte_fch = parse_date(cbte_fch_raw)

            factura_letra = detect_factura_letra(text)  # 'A'/'B'/'C' o None
            total_raw = find_first(TOTAL_PATTERNS, text)
            imp_total = normalize_amount_ar_to_float(total_raw)

            cbte_tipo = int(cbte_tipo_raw) if cbte_tipo_raw else None
            pto_vta = int(pto_vta_raw) if pto_vta_raw else None
            cbte_nro = int(cbte_nro_raw) if cbte_nro_raw else None
            cbte_fch_yyyymmdd = date_to_yyyymmdd(cbte_fch)

            # CUIT EMISOR = DEL PDF
            cuit_emisor = decide_cuit_emisor(text)

            # Receptor: auto-detección (si hay 2 CUITs, toma el que no es emisor)
            doc_tipo_rec, doc_nro_rec = decide_receptor_doc(text, cuit_emisor=cuit_emisor or "")

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

            # Reglas automáticas A/B/C
            require_receptor = (factura_letra == "A")

            missing = []
            if not cbte_tipo:
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
                missing.append("CuitEmisor(PDF)")

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
                        "CbteTipo": cbte_tipo_raw or "",
                        "PtoVta": pto_vta_raw or "",
                        "CbteNro": cbte_nro_raw or "",
                        "CbteFch": cbte_fch_raw or "",
                        "ImpTotal": total_raw or "",
                        "CuitEmisor": cuit_emisor or "",
                        "DocTipoRec": str(doc_tipo_rec) if doc_tipo_rec else "",
                        "DocNroRec": doc_nro_rec or "",
                        "AFIP": "DATOS_INSUFICIENTES",
                        "Detalle AFIP": f"Faltan campos para WSCDC: {', '.join(missing)}. Mejorar extracción del PDF.",
                    }
                )
                continue

            try:
                res = wscdc_comprobante_constatar(
                    cbte_tipo=cbte_tipo,
                    pto_vta=pto_vta,
                    cbte_nro=cbte_nro,
                    cbte_fch_yyyymmdd=cbte_fch_yyyymmdd,
                    cae=str(cae_pdf).strip(),
                    imp_total=float(imp_total),
                    cuit_emisor=cuit_emisor,
                    doc_tipo_receptor=doc_tipo_rec,
                    doc_nro_receptor=doc_nro_rec,
                )

                resultado = (res.get("resultado") or "").strip()
                if resultado:
                    # AFIP: A = aprobado/ok. R = rechazado.
                    afip_ok = resultado.upper() in ("A", "OK", "APROBADO")
                    out_rows.append(
                        {
                            "Archivo": f.filename,
                            "CAE": cae_pdf or "",
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "Factura": factura_letra or "",
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "CbteFch": cbte_fch_yyyymmdd,
                            "ImpTotal": f"{imp_total:.2f}" if imp_total is not None else "",
                            "CuitEmisor": cuit_emisor,
                            "DocTipoRec": str(doc_tipo_rec) if doc_tipo_rec else "",
                            "DocNroRec": doc_nro_rec or "",
                            "AFIP": "OK" if afip_ok else "NO_CONSTA",
                            "Detalle AFIP": f"WSCDC Resultado={resultado}",
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
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "CbteFch": cbte_fch_yyyymmdd,
                            "ImpTotal": f"{imp_total:.2f}" if imp_total is not None else "",
                            "CuitEmisor": cuit_emisor,
                            "DocTipoRec": str(doc_tipo_rec) if doc_tipo_rec else "",
                            "DocNroRec": doc_nro_rec or "",
                            "AFIP": "OK_HTTP",
                            "Detalle AFIP": "WSCDC respondió 200. No se detectó campo 'Resultado' (revisar parse).",
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
                        "CbteTipo": cbte_tipo,
                        "PtoVta": pto_vta,
                        "CbteNro": cbte_nro,
                        "CbteFch": cbte_fch_yyyymmdd,
                        "ImpTotal": f"{imp_total:.2f}" if imp_total is not None else (total_raw or ""),
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
                    "Archivo": f.filename,
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
