import os
import io
import re
import base64
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone, date
from typing import List, Optional, Dict, Any, Tuple
import xml.etree.ElementTree as ET

import pdfplumber
import requests
from fastapi import FastAPI, Header, HTTPException, UploadFile, File
from pydantic import BaseModel

# ============================================================
# FASTAPI
# ============================================================
app = FastAPI(title="Verificador CAE Backend", version="2.0.0")

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
# PDF EXTRACTION
# ============================================================
CAE_PATTERNS = [
    re.compile(r"\bCAE\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bC\.?A\.?E\.?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bCAE\s*N[º°o]?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bCAE\s*NRO\.?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
]

VTOCAE_PATTERNS = [
    re.compile(
        r"(?:Vto\.?\s*de\s*CAE|Vto\.?\s*CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{2}[/-]\d{2}[/-]\d{4})",
        re.IGNORECASE
    ),
    re.compile(
        r"(?:Vto\.?\s*de\s*CAE|Vto\.?\s*CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{4}[/-]\d{2}[/-]\d{2})",
        re.IGNORECASE
    ),
]

# Tipos: para tus PDFs “COD. 01”
CBTETIPO_PATTERNS = [
    re.compile(r"\bCOD\.?\s*(\d{1,3})\b", re.IGNORECASE),
    re.compile(r"\bC[oó]digo\s*(\d{1,3})\b", re.IGNORECASE),
    re.compile(r"\bTipo\s+Comprobante\D{0,10}(\d{1,3})\b", re.IGNORECASE),
]

# PtoVta y Nro: fallback “00001-00000061”
PTOVTA_PATTERNS = [
    re.compile(r"\bPunto\s+de\s+Venta\D{0,20}(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\bPto\.?\s*Vta\.?\D{0,10}(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\b(\d{4,5})\s*[-/]\s*(\d{6,10})\b"),
]

CBTENRO_PATTERNS = [
    re.compile(r"\bComp\.?\s*Nro\D{0,10}(\d{1,12})\b", re.IGNORECASE),
    re.compile(r"\bComprobante\s*N[º°o]?\D{0,10}(\d{1,12})\b", re.IGNORECASE),
    re.compile(r"\b(\d{4,5})\s*[-/]\s*(\d{6,10})\b"),
]

# Fecha comprobante (varios formatos)
CBTEFCH_PATTERNS = [
    re.compile(r"\bFecha\D{0,10}(\d{2}[/-]\d{2}[/-]\d{4})\b", re.IGNORECASE),
    re.compile(r"\bFecha\D{0,10}(\d{4}[/-]\d{2}[/-]\d{2})\b", re.IGNORECASE),
]

# Total (buscamos algo tipo “Total: 12.345,67” o “Importe Total 12345.67”)
TOTAL_PATTERNS = [
    re.compile(r"\bImporte\s*Total\D{0,10}([$]?\s*[\d\.\,]+)\b", re.IGNORECASE),
    re.compile(r"\bTotal\D{0,10}([$]?\s*[\d\.\,]+)\b", re.IGNORECASE),
]

def extract_text_pdf(file_bytes: bytes, max_pages: int = 5) -> str:
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        parts = []
        for page in pdf.pages[:max_pages]:
            parts.append(page.extract_text() or "")
        return "\n".join(parts)

def parse_date_any(s: Optional[str]) -> Optional[date]:
    if not s:
        return None
    s = s.strip()
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            pass
    return None

def basic_format_ok_cae(cae: Optional[str]) -> bool:
    return bool(cae and re.fullmatch(r"\d{14}", cae))

def find_first_group(patterns: List[re.Pattern], text: str) -> Optional[str]:
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
                return m.group(1)  # 00001
            return m.group(1)
    return None

def find_cbtenro(text: str) -> Optional[str]:
    for pat in CBTENRO_PATTERNS:
        m = pat.search(text)
        if m:
            if m.lastindex == 2:
                return m.group(2)  # 00000061
            return m.group(1)
    return None

def normalize_money_to_float(raw: Optional[str]) -> Optional[float]:
    if not raw:
        return None
    s = raw.strip().replace("$", "").strip()
    # Heurística AR: miles ".", decimales ","
    # Si hay "," asumimos decimal ","
    if "," in s:
        s = s.replace(".", "").replace(",", ".")
    return float(re.sub(r"[^\d\.]", "", s)) if re.search(r"\d", s) else None

def extract_fields_from_pdf_text(text: str) -> Dict[str, Any]:
    cae = find_first_group(CAE_PATTERNS, text)

    vto_raw = find_first_group(VTOCAE_PATTERNS, text)
    vto_cae = parse_date_any(vto_raw)

    cbte_tipo_raw = find_first_group(CBTETIPO_PATTERNS, text)
    pto_vta_raw = find_ptovta(text)
    cbte_nro_raw = find_cbtenro(text)

    cbte_fch_raw = find_first_group(CBTEFCH_PATTERNS, text)
    cbte_fch = parse_date_any(cbte_fch_raw)

    total_raw = find_first_group(TOTAL_PATTERNS, text)
    imp_total = normalize_money_to_float(total_raw)

    # ints
    cbte_tipo = int(cbte_tipo_raw) if cbte_tipo_raw and cbte_tipo_raw.isdigit() else None
    pto_vta = int(pto_vta_raw) if pto_vta_raw and pto_vta_raw.isdigit() else None
    cbte_nro = int(cbte_nro_raw) if cbte_nro_raw and cbte_nro_raw.isdigit() else None

    return {
        "CAE": cae,
        "VtoCAE": vto_cae,
        "CbteTipo": cbte_tipo,
        "PtoVta": pto_vta,
        "CbteNro": cbte_nro,
        "CbteFch": cbte_fch,
        "ImpTotal": imp_total,
        "debug": {
            "vto_raw": vto_raw,
            "cbte_tipo_raw": cbte_tipo_raw,
            "pto_vta_raw": pto_vta_raw,
            "cbte_nro_raw": cbte_nro_raw,
            "cbte_fch_raw": cbte_fch_raw,
            "total_raw": total_raw,
        }
    }

# ============================================================
# AFIP CONFIG (WSAA + WSCDC)
# ============================================================
AFIP_ENV = os.getenv("AFIP_ENV", "prod").strip().lower()  # prod | homo
AFIP_CUIT = os.getenv("AFIP_CUIT", "").strip()

AFIP_CERT_B64 = os.getenv("AFIP_CERT_B64", "")
AFIP_KEY_B64 = os.getenv("AFIP_KEY_B64", "")

FAIL_WSAA = os.getenv("FAIL_WSAA", "0").strip() == "1"
OPENSSL_BIN = os.getenv("OPENSSL_BIN", "openssl").strip()

WSAA_URLS = {
    "prod": "https://wsaa.afip.gov.ar/ws/services/LoginCms",
    "homo": "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
}

# WSCDC (Constatación de Comprobantes)
# Nota: si tu AFIP te dio endpoints distintos, actualizalos acá.
WSCDC_URLS = {
    "prod": "https://servicios1.afip.gov.ar/wsdc/service.asmx",
    "homo": "https://wswhomo.afip.gov.ar/wsdc/service.asmx",
}

def require_afip_env():
    if AFIP_ENV not in ("prod", "homo"):
        raise HTTPException(status_code=500, detail="AFIP_ENV debe ser 'prod' o 'homo'")
    if not AFIP_CUIT:
        raise HTTPException(status_code=500, detail="Falta AFIP_CUIT en variables de entorno")
    if not AFIP_CERT_B64 or not AFIP_KEY_B64:
        raise HTTPException(status_code=500, detail="Faltan AFIP_CERT_B64 y/o AFIP_KEY_B64 en variables de entorno")

def b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

# Cache simple del TA (token+sign)
_TA_CACHE: Dict[str, Any] = {"token": None, "sign": None, "exp_utc": None, "service": None}

def build_tra(service: str) -> str:
    # WSAA es sensible al reloj: usamos margen.
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

def sign_tra_with_openssl(tra_xml: str, cert_bytes: bytes, key_bytes: bytes) -> bytes:
    """
    Firma CMS (PKCS#7) usando openssl smime -sign, salida DER.
    """
    with tempfile.TemporaryDirectory() as tmp:
        cert_path = os.path.join(tmp, "cert.crt")
        key_path = os.path.join(tmp, "private.key")
        tra_path = os.path.join(tmp, "tra.xml")
        out_path = os.path.join(tmp, "tra.cms")

        with open(cert_path, "wb") as f:
            f.write(cert_bytes)
        with open(key_path, "wb") as f:
            f.write(key_bytes)
        with open(tra_path, "wb") as f:
            f.write(tra_xml.encode("utf-8"))

        cmd = [
            OPENSSL_BIN, "smime", "-sign",
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
            raise RuntimeError(f"No se encontró OpenSSL ('{OPENSSL_BIN}'). Configurá OPENSSL_BIN o instalalo.")
        except subprocess.CalledProcessError as e:
            err = (e.stderr or b"").decode("utf-8", "ignore")[:800]
            raise RuntimeError(f"OpenSSL error: {err}")

        with open(out_path, "rb") as f:
            return f.read()

def wsaa_login_get_ta(service: str) -> Dict[str, str]:
    """
    WSAA LoginCms -> Token/Sign.
    IMPORTANTE: para WSCDC el service debe ser 'wscdc'.
    """
    now = datetime.now(timezone.utc)

    if (
        _TA_CACHE["token"]
        and _TA_CACHE["sign"]
        and _TA_CACHE["exp_utc"]
        and _TA_CACHE["service"] == service
    ):
        if now + timedelta(minutes=2) < _TA_CACHE["exp_utc"]:
            return {"token": _TA_CACHE["token"], "sign": _TA_CACHE["sign"]}

    cert_bytes = b64_to_bytes(AFIP_CERT_B64)
    key_bytes = b64_to_bytes(AFIP_KEY_B64)

    tra_xml = build_tra(service=service)
    cms_der = sign_tra_with_openssl(tra_xml, cert_bytes, key_bytes)
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

    r = requests.post(
        wsaa_url,
        data=soap.encode("utf-8"),
        headers={"Content-Type": "text/xml; charset=utf-8"},
        timeout=40,
    )

    if r.status_code != 200:
        # WSAA manda SOAP Fault con 500 cuando el computador no está autorizado, etc.
        raise RuntimeError(f"WSAA HTTP {r.status_code}: {r.text[:900]}")

    root = ET.fromstring(r.text)
    ta_xml = None
    for el in root.iter():
        if el.tag.endswith("loginCmsReturn"):
            ta_xml = el.text
            break
    if not ta_xml:
        raise RuntimeError("WSAA: no se encontró loginCmsReturn.")

    ta_root = ET.fromstring(ta_xml)
    token = ta_root.findtext(".//token")
    sign = ta_root.findtext(".//sign")
    exp_s = ta_root.findtext(".//expirationTime")
    if not token or not sign or not exp_s:
        raise RuntimeError("WSAA: TA incompleto (token/sign/expirationTime).")

    exp_utc = datetime.fromisoformat(exp_s.replace("Z", "+00:00")).astimezone(timezone.utc)

    _TA_CACHE.update({"token": token, "sign": sign, "exp_utc": exp_utc, "service": service})
    return {"token": token, "sign": sign}

def _xml_text(root: ET.Element, endswith_tag: str) -> Optional[str]:
    for el in root.iter():
        if el.tag.endswith(endswith_tag) and el.text:
            t = el.text.strip()
            if t:
                return t
    return None

def wscdc_comprobante_constatar(
    cuit_emisor: int,
    cbte_tipo: int,
    pto_vta: int,
    cbte_nro: int,
    cbte_fch: str,
    imp_total: float,
    cod_autorizacion: str,
) -> Dict[str, Any]:
    """
    WSCDC: ComprobanteConstatar
    """
    # Token/Sign para el servicio correcto:
    ta = wsaa_login_get_ta(service="wscdc")

    ws_url = WSCDC_URLS[AFIP_ENV]
    cuit = int(AFIP_CUIT)

    # Muchos servicios AFIP aceptan fecha como yyyymmdd:
    # (si te viene dd/mm/yyyy lo convertimos antes)
    fch = cbte_fch

    # Namespace típico WSCDC (si tu WSDL indica otro, lo cambiás acá)
    ns = "http://ar.gov.afip.dif.wscdc/"
    soap_action = f"{ns}ComprobanteConstatar"

    soap = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:ar="{ns}">
  <soapenv:Header/>
  <soapenv:Body>
    <ar:ComprobanteConstatar>
      <ar:AuthRequest>
        <ar:token>{ta["token"]}</ar:token>
        <ar:sign>{ta["sign"]}</ar:sign>
        <ar:cuit>{cuit}</ar:cuit>
      </ar:AuthRequest>
      <ar:CmpReq>
        <ar:CuitEmisor>{cuit_emisor}</ar:CuitEmisor>
        <ar:CbteTipo>{cbte_tipo}</ar:CbteTipo>
        <ar:PtoVta>{pto_vta}</ar:PtoVta>
        <ar:CbteNro>{cbte_nro}</ar:CbteNro>
        <ar:CbteFch>{fch}</ar:CbteFch>
        <ar:ImpTotal>{imp_total:.2f}</ar:ImpTotal>
        <ar:CodAutorizacion>{cod_autorizacion}</ar:CodAutorizacion>
      </ar:CmpReq>
    </ar:ComprobanteConstatar>
  </soapenv:Body>
</soapenv:Envelope>"""

    r = requests.post(
        ws_url,
        data=soap.encode("utf-8"),
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": soap_action,
        },
        timeout=60,
    )

    if r.status_code != 200:
        raise RuntimeError(f"WSCDC HTTP {r.status_code}: {r.text[:900]}")

    root = ET.fromstring(r.text)

    # En respuestas AFIP suele venir:
    # - Resultado (A/R)
    # - Observaciones / Errores
    resultado = _xml_text(root, "Resultado") or _xml_text(root, "resultado")
    detalle = _xml_text(root, "Msg") or _xml_text(root, "msg") or ""

    # Captura de errores si aparecen
    errors = []
    for el in root.iter():
        if el.tag.endswith("Err"):
            code = el.findtext(".//*[local-name()='Code']") or el.findtext(".//*[local-name()='code']")
            msg = el.findtext(".//*[local-name()='Msg']") or el.findtext(".//*[local-name()='msg']")
            if code or msg:
                errors.append({"code": code, "msg": msg})

    return {
        "resultado": resultado,
        "detalle": detalle,
        "errors": errors,
        "raw": r.text,
    }

def to_yyyymmdd(d: date) -> str:
    return d.strftime("%Y%m%d")

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

            fields = extract_fields_from_pdf_text(text)

            cae_pdf = fields["CAE"]
            vto_pdf = fields["VtoCAE"]
            cbte_tipo = fields["CbteTipo"]
            pto_vta = fields["PtoVta"]
            cbte_nro = fields["CbteNro"]
            cbte_fch = fields["CbteFch"]
            imp_total = fields["ImpTotal"]

            # Estado local
            status = []
            status.append("CAE encontrado" if cae_pdf else "CAE NO encontrado")
            if basic_format_ok_cae(cae_pdf):
                status.append("Formato OK")
            elif cae_pdf:
                status.append("Formato dudoso")
            if vto_pdf:
                status.append("Vigente" if vto_pdf >= today else "Vencido")
            else:
                status.append("Vto no detectado")

            # Validación AFIP: si FAIL_WSAA activo, devolvemos pendiente sin romper prod
            if FAIL_WSAA:
                out_rows.append({
                    "Archivo": f.filename,
                    "CAE": cae_pdf or "",
                    "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                    "Estado": " | ".join(status),
                    "CbteTipo": cbte_tipo or "",
                    "PtoVta": pto_vta or "",
                    "CbteNro": cbte_nro or "",
                    "CbteFch": cbte_fch.strftime("%d/%m/%Y") if cbte_fch else "",
                    "ImpTotal": f"{imp_total:.2f}" if isinstance(imp_total, float) else "",
                    "AFIP": "PENDIENTE",
                    "Detalle AFIP": f"AFIP: Integración pendiente (WSAA/WSCDC). Emisor={AFIP_CUIT}. ENV={AFIP_ENV}",
                })
                continue

            # Requisitos mínimos WSCDC
            missing = []
            if not cae_pdf: missing.append("CAE")
            if cbte_tipo is None: missing.append("CbteTipo")
            if pto_vta is None: missing.append("PtoVta")
            if cbte_nro is None: missing.append("CbteNro")
            if cbte_fch is None: missing.append("CbteFch")
            if imp_total is None: missing.append("ImpTotal")

            if missing:
                out_rows.append({
                    "Archivo": f.filename,
                    "CAE": cae_pdf or "",
                    "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                    "Estado": " | ".join(status),
                    "CbteTipo": cbte_tipo or "",
                    "PtoVta": pto_vta or "",
                    "CbteNro": cbte_nro or "",
                    "CbteFch": cbte_fch.strftime("%d/%m/%Y") if cbte_fch else "",
                    "ImpTotal": f"{imp_total:.2f}" if isinstance(imp_total, float) else "",
                    "AFIP": "DATOS_INSUFICIENTES",
                    "Detalle AFIP": f"Faltan campos para WSCDC: {', '.join(missing)}. Mejorar extracción del PDF.",
                })
                continue

            # WSCDC real
            try:
                resp = wscdc_comprobante_constatar(
                    cuit_emisor=int(AFIP_CUIT),   # Emisor (tu CUIT dueño del cert)
                    cbte_tipo=int(cbte_tipo),
                    pto_vta=int(pto_vta),
                    cbte_nro=int(cbte_nro),
                    cbte_fch=to_yyyymmdd(cbte_fch),
                    imp_total=float(imp_total),
                    cod_autorizacion=str(cae_pdf),
                )

                resultado = (resp.get("resultado") or "").strip().upper()
                errors = resp.get("errors") or []

                if errors:
                    out_rows.append({
                        "Archivo": f.filename,
                        "CAE": cae_pdf or "",
                        "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                        "Estado": " | ".join(status),
                        "CbteTipo": cbte_tipo,
                        "PtoVta": pto_vta,
                        "CbteNro": cbte_nro,
                        "CbteFch": cbte_fch.strftime("%d/%m/%Y") if cbte_fch else "",
                        "ImpTotal": f"{imp_total:.2f}",
                        "AFIP": "ERROR_AFIP",
                        "Detalle AFIP": f"WSCDC Errors: {errors[:2]}",
                    })
                else:
                    if resultado in ("A", "APROBADO", "OK"):
                        out_rows.append({
                            "Archivo": f.filename,
                            "CAE": cae_pdf or "",
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "CbteFch": cbte_fch.strftime("%d/%m/%Y") if cbte_fch else "",
                            "ImpTotal": f"{imp_total:.2f}",
                            "AFIP": "OK",
                            "Detalle AFIP": "AFIP OK (WSCDC): el comprobante consta y coincide con los datos enviados.",
                        })
                    elif resultado:
                        out_rows.append({
                            "Archivo": f.filename,
                            "CAE": cae_pdf or "",
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "CbteFch": cbte_fch.strftime("%d/%m/%Y") if cbte_fch else "",
                            "ImpTotal": f"{imp_total:.2f}",
                            "AFIP": "NO_OK",
                            "Detalle AFIP": f"WSCDC respondió Resultado={resultado}. Detalle={resp.get('detalle','')[:200]}",
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
                            "CbteFch": cbte_fch.strftime("%d/%m/%Y") if cbte_fch else "",
                            "ImpTotal": f"{imp_total:.2f}",
                            "AFIP": "RESPUESTA_INESPERADA",
                            "Detalle AFIP": "WSCDC no devolvió Resultado. Revisar namespaces / endpoint / SOAPAction.",
                        })

            except Exception as e:
                out_rows.append({
                    "Archivo": f.filename,
                    "CAE": cae_pdf or "",
                    "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                    "Estado": " | ".join(status),
                    "CbteTipo": cbte_tipo or "",
                    "PtoVta": pto_vta or "",
                    "CbteNro": cbte_nro or "",
                    "CbteFch": cbte_fch.strftime("%d/%m/%Y") if cbte_fch else "",
                    "ImpTotal": f"{imp_total:.2f}" if isinstance(imp_total, float) else "",
                    "AFIP": "ERROR_AFIP",
                    "Detalle AFIP": str(e)[:300],
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
                "CbteFch": "",
                "ImpTotal": "",
                "AFIP": "ERROR",
                "Detalle AFIP": str(e)[:300],
            })

    return {"rows": out_rows}
