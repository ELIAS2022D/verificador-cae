import os
import io
import re
import base64
import subprocess
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
import xml.etree.ElementTree as ET

import pdfplumber
import requests
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
        re.IGNORECASE
    ),
    re.compile(
        r"(?:Fecha\s+de\s+)?(?:Vto\.?\s*de\s*CAE|Vto\.?\s*CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{4}[/-]\d{2}[/-]\d{2})",
        re.IGNORECASE
    ),
]

# “COD. 01” => tipo comprobante
CBTETIPO_PATTERNS = [
    re.compile(r"\bCOD\.?\s*(\d{1,3})\b", re.IGNORECASE),
    re.compile(r"\bC[oó]digo\s*(\d{1,3})\b", re.IGNORECASE),
]

# Punto de venta / Comprobante nro
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

# Fecha de emisión (CbteFch para WSCDC)
CBTEFCH_PATTERNS = [
    re.compile(r"\bFecha\s+de\s+Emisi[oó]n:\s*(\d{2}[/-]\d{2}[/-]\d{4})\b", re.IGNORECASE),
    re.compile(r"\bFec\.?\s*Emisi[oó]n:\s*(\d{2}[/-]\d{2}[/-]\d{4})\b", re.IGNORECASE),
]

# Total (ImpTotal)
IMPTOTAL_PATTERNS = [
    re.compile(r"\bImporte\s+Total:?\s*\$?\s*([0-9\.\,]+)\b", re.IGNORECASE),
    re.compile(r"\bTOTAL:?\s*\$?\s*([0-9\.\,]+)\b", re.IGNORECASE),
]

# CUITs (emisor / receptor)
CUIT_PATTERNS = [
    re.compile(r"\bCUIT\b\D{0,10}(\d{2}-?\d{8}-?\d)\b", re.IGNORECASE),
    re.compile(r"\bCUIT\b\D{0,10}(\d{11})\b", re.IGNORECASE),
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
            if m.lastindex == 2:  # caso 00001-00000061
                return m.group(1)
            return m.group(1)
    return None

def find_cbtenro(text: str) -> Optional[str]:
    for pat in CBTENRO_PATTERNS:
        m = pat.search(text)
        if m:
            if m.lastindex == 2:  # caso 00001-00000061
                return m.group(2)
            return m.group(1)
    return None

def parse_date_any(date_str: Optional[str]):
    if not date_str:
        return None
    s = date_str.strip()
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            pass
    return None

def to_yyyymmdd(d) -> Optional[str]:
    if not d:
        return None
    return d.strftime("%Y%m%d")

def basic_format_ok(cae: Optional[str]) -> bool:
    return bool(cae and re.fullmatch(r"\d{14}", cae))

def parse_money_to_float(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    s = s.strip()
    # Ej AR: 1.234,56  -> 1234.56
    s = s.replace(".", "").replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return None

def normalize_cuit(s: str) -> str:
    return re.sub(r"\D", "", s or "")

def extract_cuits(text: str) -> List[str]:
    found = []
    for pat in CUIT_PATTERNS:
        for m in pat.finditer(text):
            c = normalize_cuit(m.group(1))
            if len(c) == 11 and c not in found:
                found.append(c)
    return found

def guess_doc_tipo_y_nro(doc: str) -> (Optional[int], Optional[int]):
    """
    Regla simple:
    - 11 dígitos => CUIT => DocTipo 80
    - 8 dígitos => DNI  => DocTipo 96
    """
    if not doc:
        return None, None
    docn = re.sub(r"\D", "", doc)
    if len(docn) == 11:
        return 80, int(docn)
    if len(docn) == 8:
        return 96, int(docn)
    return None, None

# ============================================================
# AFIP CONFIG (WSAA + WSCDC)
# ============================================================
AFIP_ENV = os.getenv("AFIP_ENV", "prod").strip().lower()  # prod | homo
AFIP_CUIT = os.getenv("AFIP_CUIT", "").strip()            # CUIT autenticado (tu CUIT)
AFIP_CERT_B64 = os.getenv("AFIP_CERT_B64", "")
AFIP_KEY_B64 = os.getenv("AFIP_KEY_B64", "")

# Si querés “no romper” en prod cuando AFIP está caído o todavía no autorizaste todo:
FAIL_WSAA = os.getenv("FAIL_WSAA", "0").strip() == "1"

# OpenSSL (por si en Render no es "openssl" directo)
OPENSSL_BIN = os.getenv("OPENSSL_BIN", "openssl").strip()

WSAA_URLS = {
    "prod": "https://wsaa.afip.gov.ar/ws/services/LoginCms",
    "homo": "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
}

# WSCDC (v2) — ARCA/AFIP (prod/homo)
# Si necesitás, podés override por env: WSCDC_URL
WSCDC_URLS = {
    "prod": "https://serviciosjava2.afip.gob.ar/wscdc/service.asmx",
    "homo": "https://wswhomo.afip.gov.ar/wscdc/service.asmx",
}
WSCDC_URL_OVERRIDE = os.getenv("WSCDC_URL", "").strip()

def require_afip_env():
    if AFIP_ENV not in ("prod", "homo"):
        raise HTTPException(status_code=500, detail="AFIP_ENV debe ser 'prod' o 'homo'")
    if not AFIP_CUIT:
        raise HTTPException(status_code=500, detail="Falta AFIP_CUIT en variables de entorno")
    if not AFIP_CERT_B64 or not AFIP_KEY_B64:
        raise HTTPException(status_code=500, detail="Faltan AFIP_CERT_B64 y/o AFIP_KEY_B64 en variables de entorno")

def b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

# Cache simple del TA (token+sign) en memoria del proceso
_TA_CACHE: Dict[str, Any] = {"token": None, "sign": None, "exp_utc": None, "service": None}

def build_tra(service: str) -> str:
    now = datetime.now(timezone.utc)
    gen = now - timedelta(minutes=5)
    exp = now + timedelta(hours=8)

    tra = f"""<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>{int(now.timestamp())}</uniqueId>
    <generationTime>{gen.isoformat()}</generationTime>
    <expirationTime>{exp.isoformat()}</expirationTime>
  </header>
  <service>{service}</service>
</loginTicketRequest>"""
    return tra

def sign_tra_with_openssl(tra_xml: str, cert_pem: bytes, key_pem: bytes) -> bytes:
    """
    Firma CMS (PKCS#7) usando openssl (smime -sign).
    """
    import tempfile

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
            OPENSSL_BIN, "smime", "-sign",
            "-signer", cert_path,
            "-inkey", key_path,
            "-in", tra_path,
            "-out", out_path,
            "-outform", "DER",
            "-nodetach",
            "-binary"
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except FileNotFoundError:
            raise RuntimeError(f"No se encontró OpenSSL ({OPENSSL_BIN}). Seteá OPENSSL_BIN o instalalo en el runtime.")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"OpenSSL error: {e.stderr.decode('utf-8', 'ignore')}")

        with open(out_path, "rb") as f:
            return f.read()

def wsaa_login_get_ta(service: str) -> Dict[str, str]:
    """
    Devuelve token+sign para el service pedido, usando cache si no expiró.
    """
    now = datetime.now(timezone.utc)
    if (
        _TA_CACHE["token"] and _TA_CACHE["sign"] and _TA_CACHE["exp_utc"] and _TA_CACHE["service"] == service
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
        timeout=40
    )
    if r.status_code != 200:
        raise RuntimeError(f"WSAA HTTP {r.status_code}: {r.text[:800]}")

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

    exp_utc = datetime.fromisoformat(exp_s.replace("Z", "+00:00")).astimezone(timezone.utc)

    _TA_CACHE["token"] = token
    _TA_CACHE["sign"] = sign
    _TA_CACHE["exp_utc"] = exp_utc
    _TA_CACHE["service"] = service

    return {"token": token, "sign": sign}

def wscdc_constatar(req: Dict[str, Any]) -> Dict[str, Any]:
    """
    WSCDC: ComprobanteConstatar
    Devuelve dict con:
      - resultado (S/N)
      - observaciones/errores
      - raw xml
    """
    # Service name para WSAA (WSCDC) suele ser "wscdc"
    # (si tu autorización está hecha sobre ese servicio)
    ta = wsaa_login_get_ta(service="wscdc")

    url = WSCDC_URL_OVERRIDE or WSCDC_URLS[AFIP_ENV]

    # Request fields (WSCDC)
    # CbteModo: "CAE"
    # CuitEmisor: CUIT del emisor del comprobante (del PDF)
    # PtoVta, CbteTipo, CbteNro, CbteFch (YYYYMMDD), ImpTotal, CodAutorizacion (CAE)
    # DocTipoReceptor y DocNroReceptor: si no los tenemos, mandamos 0/0 (seguro no siempre).
    # Preferimos exigirlos si faltan (para evitar consultas inválidas).
    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <ComprobanteConstatar xmlns="http://ar.gov.afip.dif.wscdc/">
      <AuthRequest>
        <Token>{ta["token"]}</Token>
        <Sign>{ta["sign"]}</Sign>
        <Cuit>{AFIP_CUIT}</Cuit>
      </AuthRequest>
      <CmpReq>
        <CbteModo>{req["CbteModo"]}</CbteModo>
        <CuitEmisor>{req["CuitEmisor"]}</CuitEmisor>
        <PtoVta>{req["PtoVta"]}</PtoVta>
        <CbteTipo>{req["CbteTipo"]}</CbteTipo>
        <CbteNro>{req["CbteNro"]}</CbteNro>
        <CbteFch>{req["CbteFch"]}</CbteFch>
        <ImpTotal>{req["ImpTotal"]}</ImpTotal>
        <CodAutorizacion>{req["CodAutorizacion"]}</CodAutorizacion>
        <DocTipoReceptor>{req["DocTipoReceptor"]}</DocTipoReceptor>
        <DocNroReceptor>{req["DocNroReceptor"]}</DocNroReceptor>
      </CmpReq>
    </ComprobanteConstatar>
  </soapenv:Body>
</soapenv:Envelope>"""

    r = requests.post(
        url,
        data=soap.encode("utf-8"),
        headers={"Content-Type": "text/xml; charset=utf-8"},
        timeout=60
    )
    if r.status_code != 200:
        raise RuntimeError(f"WSCDC HTTP {r.status_code}: {r.text[:900]}")

    # Parse básico: buscamos Resultado y/o errores/observaciones
    root = ET.fromstring(r.text)

    # Ej tags: Resultado, Obs/Observaciones, Err/Errores (depende respuesta)
    resultado = None
    for el in root.iter():
        if el.tag.lower().endswith("resultado"):
            if el.text and el.text.strip():
                resultado = el.text.strip()
                break

    errors = []
    for el in root.iter():
        if el.tag.lower().endswith("err"):
            code = el.findtext(".//*[local-name()='Code']")
            msg = el.findtext(".//*[local-name()='Msg']")
            if code or msg:
                errors.append({"code": code, "msg": msg})

    obs = []
    for el in root.iter():
        if el.tag.lower().endswith("obs"):
            code = el.findtext(".//*[local-name()='Code']")
            msg = el.findtext(".//*[local-name()='Msg']")
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

            cae_pdf = find_first(CAE_PATTERNS, text)
            vto_raw = find_first(VTO_PATTERNS, text)
            vto_pdf = parse_date_any(vto_raw)

            cbte_tipo_raw = find_first(CBTETIPO_PATTERNS, text)
            pto_vta_raw = find_ptovta(text)
            cbte_nro_raw = find_cbtenro(text)

            cbte_fch_raw = find_first(CBTEFCH_PATTERNS, text)  # dd/mm/yyyy
            cbte_fch_date = parse_date_any(cbte_fch_raw)
            cbte_fch = to_yyyymmdd(cbte_fch_date)

            imp_total_raw = find_first(IMPTOTAL_PATTERNS, text)
            imp_total = parse_money_to_float(imp_total_raw)

            cuits = extract_cuits(text)
            cuit_emisor = cuits[0] if len(cuits) >= 1 else None
            cuit_receptor = cuits[1] if len(cuits) >= 2 else None  # heurística simple

            doc_tipo_receptor, doc_nro_receptor = guess_doc_tipo_y_nro(cuit_receptor or "")

            # Normalizaciones numéricas
            cbte_tipo = int(cbte_tipo_raw) if cbte_tipo_raw else None
            pto_vta = int(pto_vta_raw) if pto_vta_raw else None
            cbte_nro = int(cbte_nro_raw) if cbte_nro_raw else None

            # Estado local
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

            # ===== Validación AFIP real (WSCDC) =====
            # WSCDC necesita: CbteTipo / PtoVta / CbteNro / CbteFch / ImpTotal / CodAutorizacion / CuitEmisor / DocTipo+DocNro receptor
            missing = []
            if not cbte_tipo:
                missing.append("CbteTipo")
            if pto_vta is None:
                missing.append("PtoVta")
            if cbte_nro is None:
                missing.append("CbteNro")
            if not cbte_fch:
                missing.append("CbteFch")
            if imp_total is None:
                missing.append("ImpTotal")
            if not cae_pdf:
                missing.append("CodAutorizacion(CAE)")
            if not cuit_emisor:
                missing.append("CuitEmisor")
            if not (doc_tipo_receptor and doc_nro_receptor is not None):
                missing.append("DocTipoReceptor/DocNroReceptor")

            if missing:
                out_rows.append({
                    "Archivo": f.filename,
                    "CAE": cae_pdf or "",
                    "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                    "Estado": " | ".join(status),
                    "CbteTipo": cbte_tipo_raw or "",
                    "PtoVta": pto_vta_raw or "",
                    "CbteNro": cbte_nro_raw or "",
                    "CbteFch": cbte_fch_raw or "",
                    "ImpTotal": imp_total_raw or "",
                    "CuitEmisor": cuit_emisor or "",
                    "DocTipoReceptor": str(doc_tipo_receptor or ""),
                    "DocNroReceptor": str(doc_nro_receptor or ""),
                    "AFIP": "DATOS_INSUFICIENTES",
                    "Detalle AFIP": f"Faltan campos para WSCDC: {', '.join(missing)}. Mejorar extracción del PDF.",
                })
                continue

            if FAIL_WSAA:
                out_rows.append({
                    "Archivo": f.filename,
                    "CAE": cae_pdf or "",
                    "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                    "Estado": " | ".join(status),
                    "CbteTipo": cbte_tipo,
                    "PtoVta": pto_vta,
                    "CbteNro": cbte_nro,
                    "CbteFch": cbte_fch,
                    "ImpTotal": imp_total,
                    "CuitEmisor": cuit_emisor,
                    "DocTipoReceptor": doc_tipo_receptor,
                    "DocNroReceptor": doc_nro_receptor,
                    "AFIP": "PENDIENTE",
                    "Detalle AFIP": f"FAIL_WSAA=1. WSCDC deshabilitado. Emisor={cuit_emisor}. ENV={AFIP_ENV}",
                })
                continue

            req = {
                "CbteModo": "CAE",
                "CuitEmisor": cuit_emisor,
                "PtoVta": pto_vta,
                "CbteTipo": cbte_tipo,
                "CbteNro": cbte_nro,
                "CbteFch": cbte_fch,                  # YYYYMMDD
                "ImpTotal": f"{imp_total:.2f}",        # string numérica
                "CodAutorizacion": cae_pdf,            # CAE
                "DocTipoReceptor": doc_tipo_receptor,
                "DocNroReceptor": doc_nro_receptor,
            }

            try:
                res = wscdc_constatar(req=req)
                resultado = res.get("resultado")
                errs = res.get("errors") or []
                obs = res.get("obs") or []

                if errs:
                    out_rows.append({
                        "Archivo": f.filename,
                        "CAE": cae_pdf,
                        "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                        "Estado": " | ".join(status),
                        "CbteTipo": cbte_tipo,
                        "PtoVta": pto_vta,
                        "CbteNro": cbte_nro,
                        "CbteFch": cbte_fch,
                        "ImpTotal": imp_total,
                        "CuitEmisor": cuit_emisor,
                        "DocTipoReceptor": doc_tipo_receptor,
                        "DocNroReceptor": doc_nro_receptor,
                        "AFIP": "ERROR_AFIP",
                        "Detalle AFIP": f"WSCDC Errors: {errs[:2]}",
                    })
                else:
                    if (resultado or "").upper() == "S":
                        out_rows.append({
                            "Archivo": f.filename,
                            "CAE": cae_pdf,
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "CbteFch": cbte_fch,
                            "ImpTotal": imp_total,
                            "CuitEmisor": cuit_emisor,
                            "DocTipoReceptor": doc_tipo_receptor,
                            "DocNroReceptor": doc_nro_receptor,
                            "AFIP": "OK",
                            "Detalle AFIP": f"WSCDC OK (Resultado=S). Obs: {obs[:1] if obs else '—'}",
                        })
                    else:
                        out_rows.append({
                            "Archivo": f.filename,
                            "CAE": cae_pdf,
                            "Vto CAE": vto_pdf.strftime("%d/%m/%Y") if vto_pdf else "",
                            "Estado": " | ".join(status),
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "CbteFch": cbte_fch,
                            "ImpTotal": imp_total,
                            "CuitEmisor": cuit_emisor,
                            "DocTipoReceptor": doc_tipo_receptor,
                            "DocNroReceptor": doc_nro_receptor,
                            "AFIP": "NO_CONSTA",
                            "Detalle AFIP": f"WSCDC Resultado != S. Obs: {obs[:2] if obs else '—'}",
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
                    "CbteFch": cbte_fch or "",
                    "ImpTotal": imp_total if imp_total is not None else "",
                    "CuitEmisor": cuit_emisor or "",
                    "DocTipoReceptor": str(doc_tipo_receptor or ""),
                    "DocNroReceptor": str(doc_nro_receptor or ""),
                    "AFIP": "ERROR_AFIP",
                    "Detalle AFIP": str(e)[:350],
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
                "CuitEmisor": "",
                "DocTipoReceptor": "",
                "DocNroReceptor": "",
                "AFIP": "ERROR",
                "Detalle AFIP": str(e)[:350],
            })

    return {"rows": out_rows}
