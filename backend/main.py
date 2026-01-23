import os
import io
import re
import base64
import subprocess
import tempfile
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
import xml.etree.ElementTree as ET

import pdfplumber
import requests
from fastapi import FastAPI, Header, HTTPException, UploadFile, File
from pydantic import BaseModel

# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("verificador-cae")

# ============================================================
# FASTAPI
# ============================================================
app = FastAPI(title="Verificador CAE Backend", version="1.0.1")

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
        re.IGNORECASE
    ),
    re.compile(
        r"(?:Fecha\s+de\s+)?(?:Vto\.?\s*de\s*CAE|Vto\.?\s*CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{4}[/-]\d{2}[/-]\d{2})",
        re.IGNORECASE
    ),
]

# Para tus PDFs reales (como el que pasaste): “COD. 01”
CBTETIPO_PATTERNS = [
    re.compile(r"\bCOD\.?\s*(\d{1,3})\b", re.IGNORECASE),
    re.compile(r"\bC[oó]digo\s*(\d{1,3})\b", re.IGNORECASE),
]

PTOVTA_PATTERNS = [
    re.compile(r"\bPunto\s+de\s+Venta:\s*(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\bPto\.?\s*Vta\.?:?\s*(\d{1,5})\b", re.IGNORECASE),
    # fallback: 00001-00000061
    re.compile(r"\b(\d{4,5})\s*[-/]\s*(\d{6,10})\b"),
]

CBTENRO_PATTERNS = [
    re.compile(r"\bComp\.?\s*Nro:?\s*(\d{1,12})\b", re.IGNORECASE),
    re.compile(r"\bComprobante\s*N[º°o]?:?\s*(\d{1,12})\b", re.IGNORECASE),
    # fallback: 00001-00000061
    re.compile(r"\b(\d{4,5})\s*[-/]\s*(\d{6,10})\b"),
]

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

# ============================================================
# AFIP CONFIG (WSAA + WSFE)
# ============================================================
AFIP_ENV = os.getenv("AFIP_ENV", "prod").strip().lower()  # prod | homo
AFIP_CUIT = os.getenv("AFIP_CUIT", "").strip()

AFIP_CERT_B64 = os.getenv("AFIP_CERT_B64", "")
AFIP_KEY_B64 = os.getenv("AFIP_KEY_B64", "")

WSAA_URLS = {
    "prod": "https://wsaa.afip.gov.ar/ws/services/LoginCms",
    "homo": "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
}

WSFE_URLS = {
    "prod": "https://servicios1.afip.gov.ar/wsfev1/service.asmx",
    "homo": "https://wswhomo.afip.gov.ar/wsfev1/service.asmx",
}

def require_afip_env():
    if AFIP_ENV not in ("prod", "homo"):
        raise HTTPException(status_code=500, detail="AFIP_ENV debe ser 'prod' o 'homo'")
    if not AFIP_CUIT:
        raise HTTPException(status_code=500, detail="Falta AFIP_CUIT en variables de entorno")
    if not AFIP_CERT_B64 or not AFIP_KEY_B64:
        raise HTTPException(status_code=500, detail="Faltan AFIP_CERT_B64 y/o AFIP_KEY_B64 en variables de entorno")

def maybe_b64_to_bytes(value: str) -> bytes:
    """
    Acepta:
      - base64 de un archivo PEM/CRT/KEY
      - PEM directo pegado (-----BEGIN ...)
    """
    v = (value or "").strip()
    if not v:
        return b""

    # Si es PEM directo, devolvemos bytes tal cual
    if "BEGIN CERTIFICATE" in v or "BEGIN PRIVATE KEY" in v or "BEGIN RSA PRIVATE KEY" in v:
        return v.encode("utf-8")

    # Si parece base64, decodificamos
    try:
        return base64.b64decode(v.encode("utf-8"))
    except Exception:
        # fallback: devolver como texto
        return v.encode("utf-8")

def fail_wsaa(prefix: str, http_status: int, body_text: str) -> str:
    """
    Intenta parsear SOAP Fault para mostrar faultstring útil.
    """
    snippet = (body_text or "")[:1200]
    try:
        root = ET.fromstring(body_text)
        fault = None
        for el in root.iter():
            if el.tag.endswith("Fault"):
                fault = el
                break
        if fault is not None:
            faultcode = fault.findtext("faultcode") or fault.findtext(".//faultcode")
            faultstring = fault.findtext("faultstring") or fault.findtext(".//faultstring")
            if faultstring:
                return f"{prefix} HTTP {http_status}: {faultstring.strip()}"
            if faultcode:
                return f"{prefix} HTTP {http_status}: Fault {faultcode.strip()}"
    except Exception:
        pass

    return f"{prefix} HTTP {http_status}: {snippet}"

# Cache simple del TA (token+sign) en memoria del proceso
_TA_CACHE: Dict[str, Any] = {"token": None, "sign": None, "exp_utc": None}

def build_tra(service: str) -> str:
    # UTC, sin microsegundos, con Z (WSAA suele ser sensible)
    now = datetime.now(timezone.utc)
    gen = now - timedelta(minutes=5)
    exp = now + timedelta(hours=8)

    def fmt(dt: datetime) -> str:
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    tra = f"""<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>{int(now.timestamp())}</uniqueId>
    <generationTime>{fmt(gen)}</generationTime>
    <expirationTime>{fmt(exp)}</expirationTime>
  </header>
  <service>{service}</service>
</loginTicketRequest>"""
    return tra

def sign_tra_with_openssl(tra_xml: str, cert_pem: bytes, key_pem: bytes) -> bytes:
    """
    Firma CMS (PKCS#7) DER usando openssl.
    Requiere cert y key en PEM.
    """
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

        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except FileNotFoundError:
            raise RuntimeError("No se encontró 'openssl' en el entorno del servidor.")
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode("utf-8", "ignore")
            raise RuntimeError(f"OpenSSL error: {stderr[:800]}")

        with open(out_path, "rb") as f:
            cms = f.read()

        if not cms or len(cms) < 50:
            raise RuntimeError("OpenSSL generó un CMS vacío o inválido.")
        return cms

def wsaa_login_get_ta(service: str = "wsfe") -> Dict[str, str]:
    """
    Devuelve token+sign, usando cache si no expiró.
    """
    now = datetime.now(timezone.utc)
    if _TA_CACHE["token"] and _TA_CACHE["sign"] and _TA_CACHE["exp_utc"]:
        if now + timedelta(minutes=2) < _TA_CACHE["exp_utc"]:
            return {"token": _TA_CACHE["token"], "sign": _TA_CACHE["sign"]}

    cert_bytes = maybe_b64_to_bytes(AFIP_CERT_B64)
    key_bytes = maybe_b64_to_bytes(AFIP_KEY_B64)

    if b"BEGIN" not in cert_bytes:
        # A veces te queda DER: en ese caso, hay que convertir a PEM antes.
        # Para no romper, lo marcamos explícito.
        raise RuntimeError("AFIP_CERT_B64 no parece PEM (falta BEGIN CERTIFICATE). Convertí el CRT a PEM o guardá el PEM.")
    if b"BEGIN" not in key_bytes:
        raise RuntimeError("AFIP_KEY_B64 no parece PEM (falta BEGIN PRIVATE KEY/RSA PRIVATE KEY). Guardá la key en PEM.")

    tra_xml = build_tra(service=service)
    cms_der = sign_tra_with_openssl(tra_xml, cert_bytes, key_bytes)
    cms_b64 = base64.b64encode(cms_der).decode("utf-8")

    wsaa_url = WSAA_URLS[AFIP_ENV]

    # Namespace correcto + SOAPAction (mejora compatibilidad)
    soap = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <loginCms xmlns="http://wsaa.view.sua.dvadac.desein.afip.gov/">
      <in0>{cms_b64}</in0>
    </loginCms>
  </soapenv:Body>
</soapenv:Envelope>"""

    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "loginCms",
    }

    r = requests.post(wsaa_url, data=soap.encode("utf-8"), headers=headers, timeout=40)

    if r.status_code != 200:
        raise RuntimeError(fail_wsaa("WSAA", r.status_code, r.text))

    # Parse: loginCmsReturn contiene XML TA
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

    # expirationTime suele venir ISO con offset/Z
    exp_utc = datetime.fromisoformat(exp_s.replace("Z", "+00:00")).astimezone(timezone.utc)

    _TA_CACHE["token"] = token
    _TA_CACHE["sign"] = sign
    _TA_CACHE["exp_utc"] = exp_utc

    return {"token": token, "sign": sign}

def wsfe_comp_consultar(cbte_tipo: int, pto_vta: int, cbte_nro: int) -> Dict[str, Any]:
    """
    Llama WSFEv1 FECompConsultar y devuelve CAE y vto reales (si existe).
    """
    ta = wsaa_login_get_ta(service="wsfe")

    wsfe_url = WSFE_URLS[AFIP_ENV]
    cuit = AFIP_CUIT

    soap = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Header/>
  <soapenv:Body>
    <ar:FECompConsultar>
      <ar:Auth>
        <ar:Token>{ta["token"]}</ar:Token>
        <ar:Sign>{ta["sign"]}</ar:Sign>
        <ar:Cuit>{cuit}</ar:Cuit>
      </ar:Auth>
      <ar:FeCompConsReq>
        <ar:CbteTipo>{cbte_tipo}</ar:CbteTipo>
        <ar:PtoVta>{pto_vta}</ar:PtoVta>
        <ar:CbteNro>{cbte_nro}</ar:CbteNro>
      </ar:FeCompConsReq>
    </ar:FECompConsultar>
  </soapenv:Body>
</soapenv:Envelope>"""

    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "http://ar.gov.afip.dif.FEV1/FECompConsultar",
    }

    r = requests.post(wsfe_url, data=soap.encode("utf-8"), headers=headers, timeout=50)
    if r.status_code != 200:
        # también puede venir SOAP Fault
        raise RuntimeError(fail_wsaa("WSFE", r.status_code, r.text))

    root = ET.fromstring(r.text)

    cae = None
    cae_vto = None

    for el in root.iter():
        if el.tag.endswith("CAE") and el.text and el.text.strip():
            cae = el.text.strip()
        if el.tag.endswith("CAEFchVto") and el.text and el.text.strip():
            cae_vto = el.text.strip()

    # Parse de Errors estándar
    errors = []
    for err in root.findall(".//*[local-name()='Errors']/*[local-name()='Err']"):
        code = err.findtext(".//*[local-name()='Code']")
        msg = err.findtext(".//*[local-name()='Msg']")
        if code or msg:
            errors.append({"code": (code or "").strip(), "msg": (msg or "").strip()})

    return {"cae": cae, "cae_vto": cae_vto, "errors": errors, "raw": r.text[:1200]}

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

            cae_pdf = find_first(CAE_PATTERNS, text)
            vto_raw = find_first(VTO_PATTERNS, text)
            vto_pdf = parse_date(vto_raw)

            cbte_tipo_raw = find_first(CBTETIPO_PATTERNS, text)
            pto_vta_raw = find_ptovta(text)
            cbte_nro_raw = find_cbtenro(text)

            cbte_tipo = int(cbte_tipo_raw) if cbte_tipo_raw else None
            pto_vta = int(pto_vta_raw) if pto_vta_raw else None
            cbte_nro = int(cbte_nro_raw) if cbte_nro_raw else None

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

            if not (cbte_tipo and pto_vta is not None and cbte_nro is not None):
                out_rows.append({
                    "Archivo": f.filename,
                    "CAE": cae_pdf or "",
                    "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                    "Estado": " | ".join(status),
                    "CbteTipo": cbte_tipo_raw or "",
                    "PtoVta": pto_vta_raw or "",
                    "CbteNro": cbte_nro_raw or "",
                    "AFIP": "DATOS_INSUFICIENTES",
                    "Detalle AFIP": "Faltan CbteTipo / PtoVta / CbteNro para consultar en WSFE.",
                })
                continue

            try:
                res = wsfe_comp_consultar(cbte_tipo=cbte_tipo, pto_vta=pto_vta, cbte_nro=cbte_nro)
                cae_afip = res.get("cae")
                vto_afip = res.get("cae_vto")  # yyyymmdd

                if not cae_afip:
                    errs = res.get("errors") or []
                    if errs:
                        out_rows.append({
                            "Archivo": f.filename,
                            "CAE": cae_pdf or "",
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "AFIP": "ERROR_AFIP",
                            "Detalle AFIP": f"WSFE Errors: {errs[:2]}",
                        })
                    else:
                        out_rows.append({
                            "Archivo": f.filename,
                            "CAE": cae_pdf or "",
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "AFIP": "NO_CONSTA",
                            "Detalle AFIP": "AFIP no devolvió CAE para ese comprobante (no existe o no accesible).",
                        })
                else:
                    if cae_pdf and cae_pdf.strip() == cae_afip.strip():
                        out_rows.append({
                            "Archivo": f.filename,
                            "CAE": cae_pdf,
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "AFIP": "OK",
                            "Detalle AFIP": f"AFIP OK. CAE coincide. Vto AFIP: {vto_afip or ''}",
                        })
                    else:
                        out_rows.append({
                            "Archivo": f.filename,
                            "CAE": cae_pdf or "",
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "AFIP": "NO_COINCIDE",
                            "Detalle AFIP": f"AFIP devolvió CAE={cae_afip} (no coincide con PDF). Vto AFIP: {vto_afip or ''}",
                        })

            except Exception as e:
                out_rows.append({
                    "Archivo": f.filename,
                    "CAE": cae_pdf or "",
                    "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                    "Estado": " | ".join(status),
                    "CbteTipo": cbte_tipo,
                    "PtoVta": pto_vta,
                    "CbteNro": cbte_nro,
                    "AFIP": "ERROR_AFIP",
                    "Detalle AFIP": str(e)[:600],
                })

        except Exception as e:
            out_rows.append({
                "Archivo": f.filename,
                "CAE": "",
                "Vto CAE": "",
                "Estado": f"Error procesando PDF: {e}",
                "CbteTipo": "",
                "PtoVta": "",
                "CbteNro": "",
                "AFIP": "ERROR",
                "Detalle AFIP": str(e)[:600],
            })

    return {"rows": out_rows}
