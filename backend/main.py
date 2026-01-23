import os
import io
import re
import base64
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
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
# AUTH (LOGIN DE TU SISTEMA) - sólo para usuarios de tu app
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
# PDF EXTRACTION (mejorada)
# ============================================================
CAE_PATTERNS = [
    re.compile(r"\bCAE\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bC\.?A\.?E\.?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bCAE\s*N[º°o]?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bCAE\s*NRO\.?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
]

VTO_PATTERNS = [
    re.compile(r"(?:Vto\.?\s*(?:de\s*)?CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{2}[/-]\d{2}[/-]\d{4})", re.IGNORECASE),
    re.compile(r"(?:Vto\.?\s*(?:de\s*)?CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{4}[/-]\d{2}[/-]\d{2})", re.IGNORECASE),
]

# Tipo comprobante: en tus PDFs aparece "COD. 01"
CBTETIPO_PATTERNS = [
    re.compile(r"\bCOD\.?\s*(\d{1,3})\b", re.IGNORECASE),
    re.compile(r"\bC[oó]digo\s*(\d{1,3})\b", re.IGNORECASE),
]

# Punto de venta / Nro: "Punto de Venta: 00001" "Comp. Nro: 00000061"
PTOVTA_PATTERNS = [
    re.compile(r"\bPunto\s+de\s+Venta:\s*(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\bPto\.?\s*Vta\.?:?\s*(\d{1,5})\b", re.IGNORECASE),
    # fallback 00001-00000061
    re.compile(r"\b(\d{4,5})\s*[-/]\s*(\d{6,10})\b"),
]
CBTENRO_PATTERNS = [
    re.compile(r"\bComp\.?\s*Nro:?\s*(\d{1,12})\b", re.IGNORECASE),
    re.compile(r"\bComprobante\s*N[º°o]?:?\s*(\d{1,12})\b", re.IGNORECASE),
    # fallback 00001-00000061
    re.compile(r"\b(\d{4,5})\s*[-/]\s*(\d{6,10})\b"),
]

# Fecha de emisión
CBTEFCH_PATTERNS = [
    re.compile(r"\bFecha\s+de\s+Emisi[oó]n:\s*(\d{2}[/-]\d{2}[/-]\d{4})\b", re.IGNORECASE),
    re.compile(r"\bEmisi[oó]n:\s*(\d{2}[/-]\d{2}[/-]\d{4})\b", re.IGNORECASE),
]

# Total (muy variable según formato). Ajustalo si tu PDF usa otra etiqueta.
IMPTOTAL_PATTERNS = [
    re.compile(r"\bImporte\s+Total:?\s*\$?\s*([0-9\.\,]+)\b", re.IGNORECASE),
    re.compile(r"\bTotal:?\s*\$?\s*([0-9\.\,]+)\b", re.IGNORECASE),
    re.compile(r"\bIMPORTE\s+TOTAL:?\s*\$?\s*([0-9\.\,]+)\b", re.IGNORECASE),
]

# CUITs: se usa para intentar sacar DocNroReceptor (si aparece en el PDF)
CUIT_ANY = re.compile(r"\b(\d{2}-?\d{7,8}-?\d)\b")

def extract_text_pdf(file_bytes: bytes, max_pages: int = 5) -> str:
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        texts = []
        for page in pdf.pages[:max_pages]:
            texts.append(page.extract_text() or "")
        return "\n".join(texts)

def parse_date_any(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str:
        return None
    s = date_str.strip()
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None

def date_to_yyyymmdd(dt: datetime) -> str:
    return dt.strftime("%Y%m%d")

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

def parse_money_to_float(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    # 1.234,56 -> 1234.56
    s = s.strip().replace(".", "").replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return None

def find_doc_receptor_cuit(text: str, cuit_emisor: str) -> Optional[str]:
    # capturamos CUITs y elegimos uno distinto al emisor (si aparece)
    found = CUIT_ANY.findall(text)
    norm_found = []
    for x in found:
        x2 = x.replace("-", "").strip()
        if len(x2) >= 10:
            norm_found.append(x2)
    norm_found = list(dict.fromkeys(norm_found))  # unique preserving order

    em = cuit_emisor.replace("-", "").strip()
    for c in norm_found:
        if c != em:
            return c
    return None

# ============================================================
# AFIP CONFIG (WSAA + WSCDC)
# ============================================================
AFIP_ENV = os.getenv("AFIP_ENV", "prod").strip().lower()  # prod | homo
AFIP_CUIT = os.getenv("AFIP_CUIT", "").strip()  # tu CUIT (emisor / firmante)

AFIP_CERT_B64 = os.getenv("AFIP_CERT_B64", "")
AFIP_KEY_B64 = os.getenv("AFIP_KEY_B64", "")

WSAA_URLS = {
    "prod": "https://wsaa.afip.gov.ar/ws/services/LoginCms",
    "homo": "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
}

WSCDC_URLS = {
    "prod": "https://servicios1.afip.gov.ar/WSCDC/service.asmx",
    "homo": "https://wswhomo.afip.gov.ar/WSCDC/service.asmx",
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

# Cache simple del TA en memoria del proceso
_TA_CACHE: Dict[str, Any] = {"token": None, "sign": None, "exp_utc": None}

def build_tra(service: str) -> str:
    # Margen por clock skew
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

def _ensure_cert_pem(tmpdir: str, cert_bytes: bytes) -> str:
    """
    Acepta cert en PEM o DER.
    Si es DER, lo convierte a PEM con openssl x509.
    """
    cert_in = os.path.join(tmpdir, "cert_in.crt")
    cert_pem = os.path.join(tmpdir, "cert.pem")
    with open(cert_in, "wb") as f:
        f.write(cert_bytes)

    if b"BEGIN CERTIFICATE" in cert_bytes:
        # ya es PEM
        with open(cert_pem, "wb") as f:
            f.write(cert_bytes)
        return cert_pem

    # DER -> PEM
    cmd = ["openssl", "x509", "-inform", "DER", "-in", cert_in, "-out", cert_pem, "-outform", "PEM"]
    subprocess.run(cmd, check=True, capture_output=True)
    return cert_pem

def sign_tra_with_openssl(tra_xml: str, cert_bytes: bytes, key_bytes: bytes) -> bytes:
    """
    Firma CMS (PKCS#7) con openssl smime.
    """
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "private.key")
        tra_path = os.path.join(tmp, "tra.xml")
        out_path = os.path.join(tmp, "tra.cms")

        # key (PEM)
        with open(key_path, "wb") as f:
            f.write(key_bytes)

        # cert PEM (si viene DER lo convertimos)
        cert_path = _ensure_cert_pem(tmp, cert_bytes)

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
        subprocess.run(cmd, check=True, capture_output=True)

        with open(out_path, "rb") as f:
            return f.read()

def wsaa_login_get_ta(service: str) -> Dict[str, str]:
    """
    Devuelve token+sign para el service solicitado (wscdc), usando cache.
    """
    now = datetime.now(timezone.utc)
    if _TA_CACHE["token"] and _TA_CACHE["sign"] and _TA_CACHE["exp_utc"]:
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

    # CLAVE: mandar SOAPAction para evitar Client.NoSOAPAction
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "loginCms",
    }

    r = requests.post(wsaa_url, data=soap.encode("utf-8"), headers=headers, timeout=40)
    if r.status_code != 200:
        raise RuntimeError(f"WSAA HTTP {r.status_code}: {r.text[:600]}")

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

def wsaa_safe_get_ta(service: str) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """
    No revienta el flujo: si falla WSAA devuelve error string.
    """
    try:
        return wsaa_login_get_ta(service=service), None
    except Exception as e:
        return None, str(e)[:400]

def wscdc_constatar(
    cuit_emisor: int,
    pto_vta: int,
    cbte_tipo: int,
    cbte_nro: int,
    cbte_fch_yyyymmdd: str,
    imp_total: float,
    cae: str,
    doc_tipo_receptor: str = "80",
    doc_nro_receptor: Optional[str] = None,
) -> Dict[str, Any]:
    """
    WSCDC ComprobanteConstatar (AFIP).
    SOAPAction y namespace según documentación del .asmx. :contentReference[oaicite:2]{index=2}
    """
    ta, err = wsaa_safe_get_ta(service="wscdc")
    if err or not ta:
        raise RuntimeError(f"FAIL_WSAA: {err}")

    url = WSCDC_URLS[AFIP_ENV]
    auth_cuit = int(AFIP_CUIT.replace("-", ""))

    # Si no encontramos doc receptor, mandamos vacío (algunos comprobantes no lo requieren estrictamente
    # dependiendo modo). Igual, si AFIP lo exige, lo verás en Errors.
    doc_nro = (doc_nro_receptor or "").strip()

    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ComprobanteConstatar xmlns="http://servicios1.afip.gob.ar/wscdc/">
      <Auth>
        <Token>{ta["token"]}</Token>
        <Sign>{ta["sign"]}</Sign>
        <Cuit>{auth_cuit}</Cuit>
      </Auth>
      <CmpReq>
        <CbteModo>CAE</CbteModo>
        <CuitEmisor>{cuit_emisor}</CuitEmisor>
        <PtoVta>{pto_vta}</PtoVta>
        <CbteTipo>{cbte_tipo}</CbteTipo>
        <CbteNro>{cbte_nro}</CbteNro>
        <CbteFch>{cbte_fch_yyyymmdd}</CbteFch>
        <ImpTotal>{imp_total}</ImpTotal>
        <CodAutorizacion>{cae}</CodAutorizacion>
        <DocTipoReceptor>{doc_tipo_receptor}</DocTipoReceptor>
        <DocNroReceptor>{doc_nro}</DocNroReceptor>
      </CmpReq>
    </ComprobanteConstatar>
  </soap:Body>
</soap:Envelope>"""

    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "http://servicios1.afip.gob.ar/wscdc/ComprobanteConstatar",
    }

    r = requests.post(url, data=soap.encode("utf-8"), headers=headers, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"WSCDC HTTP {r.status_code}: {r.text[:600]}")

    root = ET.fromstring(r.text)

    # Resultado/Observaciones/Errors (parsing tolerante)
    resultado = None
    for el in root.iter():
        if el.tag.endswith("Resultado") and el.text:
            resultado = el.text.strip()
            break

    errors = []
    for err_el in root.iter():
        if err_el.tag.endswith("Err"):
            code = None
            msg = None
            for c in err_el.iter():
                if c.tag.endswith("Code") and c.text:
                    code = c.text.strip()
                if c.tag.endswith("Msg") and c.text:
                    msg = c.text.strip()
            if code or msg:
                errors.append({"code": code, "msg": msg})

    obs = []
    for obs_el in root.iter():
        if obs_el.tag.endswith("Obs"):
            code = None
            msg = None
            for c in obs_el.iter():
                if c.tag.endswith("Code") and c.text:
                    code = c.text.strip()
                if c.tag.endswith("Msg") and c.text:
                    msg = c.text.strip()
            if code or msg:
                obs.append({"code": code, "msg": msg})

    return {
        "resultado": resultado,
        "errors": errors,
        "observaciones": obs,
        "raw": r.text,
    }

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

    cuit_emisor = int(AFIP_CUIT.replace("-", ""))

    for f in files:
        try:
            pdf_bytes = await f.read()
            text = extract_text_pdf(pdf_bytes, max_pages=5)

            # PDF fields
            cae_pdf = find_first(CAE_PATTERNS, text)

            vto_raw = find_first(VTO_PATTERNS, text)
            vto_dt = parse_date_any(vto_raw)
            vto_date = vto_dt.date() if vto_dt else None

            cbte_tipo_raw = find_first(CBTETIPO_PATTERNS, text)
            pto_vta_raw = find_ptovta(text)
            cbte_nro_raw = find_cbtenro(text)

            fch_raw = find_first(CBTEFCH_PATTERNS, text)
            fch_dt = parse_date_any(fch_raw) if fch_raw else None
            cbte_fch = date_to_yyyymmdd(fch_dt) if fch_dt else None

            imp_raw = find_first(IMPTOTAL_PATTERNS, text)
            imp_total = parse_money_to_float(imp_raw)

            doc_receptor = find_doc_receptor_cuit(text, cuit_emisor=str(cuit_emisor))

            # Normalizaciones
            cbte_tipo = int(cbte_tipo_raw) if cbte_tipo_raw else None
            pto_vta = int(pto_vta_raw) if pto_vta_raw else None
            cbte_nro = int(cbte_nro_raw) if cbte_nro_raw else None

            # Estado local
            status = []
            status.append("CAE encontrado" if cae_pdf else "CAE NO encontrado")
            if cae_pdf and re.fullmatch(r"\d{14}", cae_pdf):
                status.append("Formato OK")
            elif cae_pdf:
                status.append("Formato dudoso")
            if vto_date:
                status.append("Vigente" if vto_date >= today else "Vencido")
            else:
                status.append("Vto no detectado")

            # Validación AFIP (WSCDC requiere CbteFch + ImpTotal + CAE + ids)
            missing = []
            if not cae_pdf:
                missing.append("CAE")
            if cbte_tipo is None:
                missing.append("CbteTipo")
            if pto_vta is None:
                missing.append("PtoVta")
            if cbte_nro is None:
                missing.append("CbteNro")
            if not cbte_fch:
                missing.append("CbteFch")
            if imp_total is None:
                missing.append("ImpTotal")

            if missing:
                out_rows.append({
                    "Archivo": f.filename,
                    "CAE": cae_pdf or "",
                    "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                    "Estado": " | ".join(status),
                    "CbteTipo": cbte_tipo_raw or "",
                    "PtoVta": pto_vta_raw or "",
                    "CbteNro": cbte_nro_raw or "",
                    "CbteFch": fch_raw or "",
                    "ImpTotal": imp_raw or "",
                    "AFIP": "DATOS_INSUFICIENTES",
                    "Detalle AFIP": f"Faltan campos para WSCDC: {', '.join(missing)}. Mejorar extracción del PDF.",
                })
                continue

            # Llamada real WSCDC
            try:
                res = wscdc_constatar(
                    cuit_emisor=cuit_emisor,
                    pto_vta=pto_vta,
                    cbte_tipo=cbte_tipo,
                    cbte_nro=cbte_nro,
                    cbte_fch_yyyymmdd=cbte_fch,
                    imp_total=imp_total,
                    cae=cae_pdf,
                    doc_tipo_receptor="80",
                    doc_nro_receptor=doc_receptor,
                )

                resultado = (res.get("resultado") or "").upper()
                errs = res.get("errors") or []
                obs = res.get("observaciones") or []

                if errs:
                    out_rows.append({
                        "Archivo": f.filename,
                        "CAE": cae_pdf,
                        "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                        "Estado": " | ".join(status),
                        "CbteTipo": cbte_tipo,
                        "PtoVta": pto_vta,
                        "CbteNro": cbte_nro,
                        "CbteFch": cbte_fch,
                        "ImpTotal": imp_total,
                        "AFIP": "ERROR_AFIP",
                        "Detalle AFIP": f"WSCDC Errors: {errs[:2]}",
                    })
                else:
                    # Resultado típico: "A" (aceptado) / "R" (rechazado) (depende servicio)
                    if resultado in ("A", "APROBADO", "OK"):
                        out_rows.append({
                            "Archivo": f.filename,
                            "CAE": cae_pdf,
                            "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                            "Estado": " | ".join(status),
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "CbteFch": cbte_fch,
                            "ImpTotal": imp_total,
                            "AFIP": "OK",
                            "Detalle AFIP": f"WSCDC OK. Resultado={resultado}. Obs={obs[:2]}",
                        })
                    else:
                        out_rows.append({
                            "Archivo": f.filename,
                            "CAE": cae_pdf,
                            "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                            "Estado": " | ".join(status),
                            "CbteTipo": cbte_tipo,
                            "PtoVta": pto_vta,
                            "CbteNro": cbte_nro,
                            "CbteFch": cbte_fch,
                            "ImpTotal": imp_total,
                            "AFIP": "NO_CONSTA",
                            "Detalle AFIP": f"WSCDC Resultado={resultado or 'N/D'}. Obs={obs[:2]}",
                        })

            except Exception as e:
                out_rows.append({
                    "Archivo": f.filename,
                    "CAE": cae_pdf or "",
                    "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                    "Estado": " | ".join(status),
                    "CbteTipo": cbte_tipo or "",
                    "PtoVta": pto_vta or "",
                    "CbteNro": cbte_nro or "",
                    "CbteFch": cbte_fch or "",
                    "ImpTotal": imp_total if imp_total is not None else "",
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
