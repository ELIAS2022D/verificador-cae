import os
import io
import re
import base64
import subprocess
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Tuple
import xml.etree.ElementTree as ET
import tempfile

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

# "A COD. 01" / "COD. 01"
CBTETIPO_PATTERNS = [
    re.compile(r"\bCOD\.?\s*(\d{1,3})\b", re.IGNORECASE),
    re.compile(r"\bC[oó]digo\s*(\d{1,3})\b", re.IGNORECASE),
]

# "Punto de Venta: 00001"
PTOVTA_PATTERNS = [
    re.compile(r"\bPunto\s+de\s+Venta:?\s*(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\bPto\.?\s*Vta\.?:?\s*(\d{1,5})\b", re.IGNORECASE),
    # fallback: 00001-00000061
    re.compile(r"\b(\d{4,5})\s*[-/]\s*(\d{6,10})\b"),
]

# "Comp. Nro: 00000061"
CBTENRO_PATTERNS = [
    re.compile(r"\bComp\.?\s*Nro:?\s*(\d{1,12})\b", re.IGNORECASE),
    re.compile(r"\bComprobante\s*N[º°o]?:?\s*(\d{1,12})\b", re.IGNORECASE),
    # fallback: 00001-00000061
    re.compile(r"\b(\d{4,5})\s*[-/]\s*(\d{6,10})\b"),
]

# "Fecha de Emisión: 21/01/2026"
CBTEFCH_PATTERNS = [
    re.compile(r"\bFecha\s+de\s+Emisi[oó]n:?\s*(\d{2}[/-]\d{2}[/-]\d{4})\b", re.IGNORECASE),
    re.compile(r"\bFecha\s+de\s+Emisi[oó]n:?\s*(\d{4}[/-]\d{2}[/-]\d{2})\b", re.IGNORECASE),
]

# TOTAL / IMPORTE TOTAL (necesario para WSCDC en muchos casos)
TOTAL_PATTERNS = [
    re.compile(
        r"\b(?:IMPORTE\s+TOTAL|TOTAL\s+A\s+PAGAR|IMP\.?\s*TOTAL|IMPORTE\s+FINAL|TOTAL)\b\D{0,40}(\d{1,3}(?:[.\s]\d{3})*(?:,\d{2})|\d+(?:,\d{2})|\d+(?:\.\d{2}))",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:IMPORTE\s+TOTAL|TOTAL\s+A\s+PAGAR|IMP\.?\s*TOTAL|TOTAL)\b\D{0,40}\$\s*(\d{1,3}(?:[.\s]\d{3})*(?:,\d{2})|\d+(?:,\d{2})|\d+(?:\.\d{2}))",
        re.IGNORECASE,
    ),
]

# Factura A/B/C (por texto típico en PDF)
FACTURA_TIPO_PATTERNS = [
    re.compile(r"\bA\s+FACTURA\b", re.IGNORECASE),
    re.compile(r"\bB\s+FACTURA\b", re.IGNORECASE),
    re.compile(r"\bC\s+FACTURA\b", re.IGNORECASE),
]

# CUITs: en PDFs AFIP suelen aparecer como "CUIT:" y el número puede estar en la misma línea o la siguiente
CUIT_AFTER_LABEL_RE = re.compile(r"\bCUIT:\s*([0-9]{11})\b", re.IGNORECASE)
CUIT_ANY_11_RE = re.compile(r"\b([0-9]{11})\b")

# DNI (si aparece; opcional)
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
            if m.lastindex == 2:  # 00001-00000061
                return m.group(1)
            return m.group(1)
    return None


def find_cbtenro(text: str) -> Optional[str]:
    for pat in CBTENRO_PATTERNS:
        m = pat.search(text)
        if m:
            if m.lastindex == 2:  # 00001-00000061
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
    Convierte strings tipo '1.234,56' o '1234,56' o '1234.56' a float.
    - Si hay coma, se asume decimal ',' y miles con '.' o espacios.
    - Si no hay coma, se intenta decimal '.' si corresponde.
    """
    if not s:
        return None
    x = s.strip()
    x = x.replace(" ", "")
    if "," in x:
        x = x.replace(".", "")
        x = x.replace(",", ".")
    try:
        return float(x)
    except ValueError:
        return None


def detect_factura_letra(text: str) -> Optional[str]:
    """
    Devuelve 'A' / 'B' / 'C' si lo detecta por texto tipo 'A FACTURA'.
    """
    for pat in FACTURA_TIPO_PATTERNS:
        m = pat.search(text)
        if m:
            # el patrón es "A FACTURA", etc.
            return m.group(0).strip()[0].upper()
    return None


def extract_all_cuits(text: str) -> List[str]:
    """
    Extrae CUITs de 11 dígitos. Priorizamos los que aparecen explícitamente como 'CUIT:'.
    Si no alcanza, caemos a cualquier número de 11 dígitos.
    """
    cuits = []
    for m in CUIT_AFTER_LABEL_RE.finditer(text):
        cuits.append(m.group(1))

    # Fallback: si por alguna razón no aparecen como 'CUIT:', tomamos cualquier 11 dígitos
    if not cuits:
        for m in CUIT_ANY_11_RE.finditer(text):
            cuits.append(m.group(1))

    # unique preservando orden
    seen = set()
    out = []
    for c in cuits:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def decide_receptor_doc(text: str, cuit_emisor: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Devuelve (DocTipoReceptor, DocNroReceptor).
    - Si encuentra un CUIT distinto al emisor: DocTipo=80 y DocNro = ese CUIT.
    - Si no, intenta DNI: DocTipo=96 y DocNro = DNI.
    - Si no hay nada: None, None.
    """
    cuit_emisor = (cuit_emisor or "").strip()
    cuits = extract_all_cuits(text)

    # Elegimos el primer CUIT que NO sea el emisor; en muchos PDFs el emisor aparece primero.
    for c in cuits:
        if cuit_emisor and c == cuit_emisor:
            continue
        # Heurística extra: evitar “basura” (igual, ya son 11 dígitos)
        return 80, c

    # DNI fallback
    dni = find_first([DNI_RE], text)
    if dni:
        return 96, dni

    return None, None


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

WSCDC_URLS = {
    "prod": "https://servicios1.afip.gov.ar/WSCDC/service.asmx",
    "homo": "https://wswhomo.afip.gob.ar/WSCDC/service.asmx",
}

WSAA_SOAP_ACTION = os.getenv("WSAA_SOAP_ACTION", "loginCms").strip()

# IMPORTANT: WSCDC requiere SOAPAction válido (si no, fault "valid action parameter").
WSCDC_SOAP_ACTION = os.getenv(
    "WSCDC_SOAP_ACTION",
    "http://servicios1.afip.gob.ar/wscdc/ComprobanteConstatar",
).strip()

# Namespace real del servicio WSCDC (según endpoint de AFIP)
WSCDC_NS = os.getenv(
    "WSCDC_NS",
    "http://servicios1.afip.gob.ar/wscdc/",
).strip()


def require_afip_env():
    if AFIP_ENV not in ("prod", "homo"):
        raise HTTPException(status_code=500, detail="AFIP_ENV debe ser 'prod' o 'homo'")
    if not AFIP_CUIT:
        raise HTTPException(status_code=500, detail="Falta AFIP_CUIT en variables de entorno")
    if not AFIP_CERT_B64 or not AFIP_KEY_B64:
        raise HTTPException(status_code=500, detail="Faltan AFIP_CERT_B64 y/o AFIP_KEY_B64 en variables de entorno")


def b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


# ============================================================
# TLS FIX: bajar SECLEVEL solo para AFIP (DH_KEY_TOO_SMALL)
# ============================================================
class AfipTLSAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.create_default_context()
        # Clave: permite parámetros DH más chicos (solo para AFIP via este adapter)
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        pool_kwargs["ssl_context"] = ctx
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)


AFIP_SESSION = requests.Session()
AFIP_SESSION.mount("https://wsaa.afip.gov.ar", AfipTLSAdapter())
AFIP_SESSION.mount("https://wsaahomo.afip.gov.ar", AfipTLSAdapter())
AFIP_SESSION.mount("https://servicios1.afip.gov.ar", AfipTLSAdapter())
AFIP_SESSION.mount("https://wswhomo.afip.gob.ar", AfipTLSAdapter())


# ============================================================
# WSAA cache (token+sign)
# ============================================================
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
    key_is_pem = b"BEGIN" in key_bytes  # RSA PRIVATE KEY / PRIVATE KEY, etc.

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

    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "loginCms",
    }

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
    """
    WSCDC: ComprobanteConstatar
    - SOAPAction correcto (si no, fault "valid action parameter")
    - Namespace real
    - Incluye ImpTotal y CuitEmisor (muy comúnmente requeridos)
    - Incluye DocTipoReceptor/DocNroReceptor si están disponibles (en Factura A suele ser clave)
    """
    ta = wsaa_login_get_ta(service="wscdc")

    url = WSCDC_URLS[AFIP_ENV]
    cuit_consulta = AFIP_CUIT  # CUIT del contribuyente que consulta

    # Armado dinámico de nodos del receptor (para A suele ser necesario; para B/C se envía si se detecta)
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
        <ImpTotal>{imp_total:.2f}</ImpTotal>
        <CodAutorizacion>{str(cae).strip()}</CodAutorizacion>
      </CmpReq>
    </ComprobanteConstatar>
  </soap:Body>
</soap:Envelope>"""

    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        # Comillas para SOAP 1.1 en .asmx
        "SOAPAction": f"\"{WSCDC_SOAP_ACTION}\"",
    }

    r = AFIP_SESSION.post(url, data=soap.encode("utf-8"), headers=headers, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"WSCDC HTTP {r.status_code}: {r.text[:2000]}")

    # Parse básico
    root = ET.fromstring(r.text)

    resultado = None
    for el in root.iter():
        if el.tag.lower().endswith("resultado") and el.text:
            resultado = el.text.strip()
            break

    # Extras útiles (errores/observaciones si vienen)
    errors = []
    obs = []

    for el in root.iter():
        tag = el.tag.lower()
        if tag.endswith("err") or tag.endswith("errors"):
            pass

    # Heurística: capturar nodos <Err> / <Obs> aunque estén en distintos namespaces
    for el in root.iter():
        tag = el.tag.lower()
        if tag.endswith("err"):
            code = el.findtext("./*[(local-name()='Code') or (local-name()='code')]")
            msg = el.findtext("./*[(local-name()='Msg') or (local-name()='msg')]")
            if code or msg:
                errors.append({"code": code, "msg": msg})
        if tag.endswith("obs"):
            code = el.findtext("./*[(local-name()='Code') or (local-name()='code')]")
            msg = el.findtext("./*[(local-name()='Msg') or (local-name()='msg')]")
            if code or msg:
                obs.append({"code": code, "msg": msg})

    return {"resultado": resultado, "errors": errors, "obs": obs, "raw": r.text}


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

    today = datetime.now().date()
    out_rows: List[Dict[str, Any]] = []

    for f in files:
        try:
            pdf_bytes = await f.read()
            text = extract_text_pdf(pdf_bytes, max_pages=5)

            # Detectores base
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

            # Emisor: por defecto el CUIT que consulta (tu env).
            # Si estás validando comprobantes de terceros, cambiá esta lógica por extracción del CUIT emisor del PDF.
            cuit_emisor = AFIP_CUIT

            # Receptor: auto-detección
            doc_tipo_rec, doc_nro_rec = decide_receptor_doc(text, cuit_emisor=cuit_emisor)

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

            # ========================================================
            # Reglas automáticas A/B/C (mínimo necesario para WSCDC)
            # ========================================================
            # - ImpTotal: requerido en la práctica para validar consistentemente.
            # - Factura A: normalmente exige datos del receptor (DocTipo/Nro).
            # - Factura B/C: se envía receptor si se detecta; si no, no bloquea.
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
                missing.append("CuitEmisor")

            if require_receptor:
                if not doc_tipo_rec:
                    missing.append("DocTipoReceptor")
                if not doc_nro_rec:
                    missing.append("DocNroReceptor")

            if missing:
                out_rows.append({
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
                })
                continue

            # Llamada WSCDC
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
                    # Convención práctica
                    afip_ok = resultado.upper() in ("A", "OK", "APROBADO")
                    # Detalle enriquecido si hay errors/obs
                    detail_bits = [f"WSCDC Resultado={resultado}"]
                    if res.get("errors"):
                        detail_bits.append(f"Errors={res['errors']}")
                    if res.get("obs"):
                        detail_bits.append(f"Obs={res['obs']}")
                    out_rows.append({
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
                        "Detalle AFIP": " | ".join(detail_bits),
                    })
                else:
                    out_rows.append({
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
                    })

            except Exception as e:
                out_rows.append({
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
                })

        except Exception as e:
            out_rows.append({
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
            })

    return {"rows": out_rows}
