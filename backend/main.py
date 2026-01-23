import os
import io
import re
import base64
from datetime import datetime
from typing import List, Optional, Dict, Any

import pdfplumber
import requests
from fastapi import FastAPI, Header, HTTPException, UploadFile, File
from pydantic import BaseModel

# ============================================================
# FASTAPI
# ============================================================
app = FastAPI(title="Verificador CAE Backend", version="1.0.0")

# ============================================================
# AUTH (LOGIN DE TU SISTEMA, NO AFIP)
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
    """
    Para producción real, reemplazar por JWT con expiración.
    Para esta demo/prod-mvp: token fijo por env.
    """
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

# Intentos para datos típicos de factura:
PTOVTA_PATTERNS = [
    re.compile(r"\bP(?:unto)?\s*de\s*V(?:enta)?\b\D{0,15}(\d{1,5})", re.IGNORECASE),
    re.compile(r"\bPto\.?\s*Vta\.?\b\D{0,15}(\d{1,5})", re.IGNORECASE),
    re.compile(r"\bPtoVta\b\D{0,15}(\d{1,5})", re.IGNORECASE),
]

CBTE_NRO_PATTERNS = [
    re.compile(r"\bN[º°o]\s*Comprobante\b\D{0,20}(\d{1,12})", re.IGNORECASE),
    re.compile(r"\bComp\.?\s*N[º°o]?\b\D{0,20}(\d{1,12})", re.IGNORECASE),
    re.compile(r"\bN[º°o]\b\D{0,10}(\d{1,12})", re.IGNORECASE),
]

FECHA_CBTE_PATTERNS = [
    re.compile(r"\bFecha\b\D{0,20}(\d{2}[/-]\d{2}[/-]\d{4})", re.IGNORECASE),
    re.compile(r"\bFecha\b\D{0,20}(\d{4}[/-]\d{2}[/-]\d{2})", re.IGNORECASE),
]

CUIT_PATTERNS = [
    re.compile(r"\bCUIT\b\D{0,20}(\d{2}-?\d{8}-?\d{1})\b", re.IGNORECASE),
]

IMPORTE_PATTERNS = [
    re.compile(r"\bImporte\s*Total\b\D{0,20}\$?\s*([\d\.\,]+)", re.IGNORECASE),
    re.compile(r"\bTotal\b\D{0,20}\$?\s*([\d\.\,]+)", re.IGNORECASE),
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

def normalize_cuit(raw: str) -> str:
    if not raw:
        return ""
    return re.sub(r"\D", "", raw)

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

def parse_amount(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    # típico AR: 1.234,56
    t = s.strip().replace(".", "").replace(",", ".")
    try:
        return float(t)
    except ValueError:
        return None

def basic_format_ok(cae: Optional[str]) -> bool:
    return bool(cae and re.fullmatch(r"\d{14}", cae))

# ============================================================
# AFIP (WSAA + WSCDC) - CONFIG
# ============================================================
AFIP_ENV = os.getenv("AFIP_ENV", "prod").strip().lower()  # "prod" | "homo"
AFIP_CUIT = os.getenv("AFIP_CUIT", "").strip()            # tu CUIT (emisor)
AFIP_CERT_B64 = os.getenv("AFIP_CERT_B64", "")
AFIP_KEY_B64 = os.getenv("AFIP_KEY_B64", "")

# WSAA endpoints (suelen ser estables)
WSAA_URLS = {
    "prod": "https://wsaa.afip.gov.ar/ws/services/LoginCms",
    "homo": "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
}

# WSCDC endpoints (Constatación de Comprobantes)
WSCDC_URLS = {
    "prod": "https://servicios1.afip.gov.ar/WSCDC/service.asmx",
    "homo": "https://wswhomo.afip.gov.ar/WSCDC/service.asmx",
}

def require_afip_env():
    if AFIP_ENV not in ("prod", "homo"):
        raise HTTPException(status_code=500, detail="AFIP_ENV debe ser 'prod' o 'homo'")
    if not AFIP_CUIT:
        raise HTTPException(status_code=500, detail="Falta AFIP_CUIT en variables de entorno del backend")
    if not AFIP_CERT_B64 or not AFIP_KEY_B64:
        raise HTTPException(status_code=500, detail="Faltan AFIP_CERT_B64 y/o AFIP_KEY_B64 en variables de entorno del backend")

# ============================================================
# /verify - PRODUCCIÓN (cert/key en env, cuit en env)
# ============================================================
@app.post("/verify")
async def verify(
    files: List[UploadFile] = File(...),      # PDFs
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
):
    """
    Producción:
    - El front NO manda CUIT/CRT/KEY.
    - El backend toma AFIP_CUIT + AFIP_CERT_B64 + AFIP_KEY_B64 desde Render env.
    - Extrae datos del PDF y (si hay datos suficientes) deja listo para WSAA+WSCDC real.
    """
    check_api_key(x_api_key)
    check_bearer(authorization)

    require_afip_env()

    today = datetime.now().date()
    out_rows: List[Dict[str, Any]] = []

    for f in files:
        try:
            pdf_bytes = await f.read()
            text = extract_text_pdf(pdf_bytes, max_pages=5)

            cae = find_first(CAE_PATTERNS, text)
            vto_raw = find_first(VTO_PATTERNS, text)
            vto_date = parse_date(vto_raw)

            pto_vta = find_first(PTOVTA_PATTERNS, text)
            cbte_nro = find_first(CBTE_NRO_PATTERNS, text)
            fecha_cbte_raw = find_first(FECHA_CBTE_PATTERNS, text)
            fecha_cbte = parse_date(fecha_cbte_raw)

            cuit_en_pdf_raw = find_first(CUIT_PATTERNS, text)
            cuit_en_pdf = normalize_cuit(cuit_en_pdf_raw)

            imp_total_raw = find_first(IMPORTE_PATTERNS, text)
            imp_total = parse_amount(imp_total_raw)

            fmt_ok = basic_format_ok(cae)
            vig_ok = (vto_date is not None and vto_date >= today)

            estado = []
            estado.append("CAE encontrado" if cae else "CAE NO encontrado")
            if fmt_ok:
                estado.append("Formato OK")
            elif cae:
                estado.append("Formato dudoso")
            if vto_date:
                estado.append("Vigente" if vig_ok else "Vencido")
            else:
                estado.append("Vto no detectado")

            # ===============================
            # Validación AFIP REAL (WSAA+WSCDC)
            # ===============================
            # Para constatar real, WSCDC requiere más campos.
            # Si faltan, devolvemos DATOS_INSUFICIENTES y listo.
            needed_ok = all([
                cae,
                pto_vta,
                cbte_nro,
                fecha_cbte,
                imp_total is not None,
            ])

            if not needed_ok:
                afip_status = "DATOS_INSUFICIENTES"
                afip_detail = "Para validar contra AFIP faltan datos del comprobante (pto vta / nro / fecha / total). Mejorar extracción."
            else:
                # Aquí es donde va tu integración real:
                # token, sign = wsaa_login(service="wscdc")
                # ok, detail = wscdc_constatar(token, sign, AFIP_CUIT, datos...)
                #
                # Por ahora, dejamos el plumbing listo y devolvemos PENDIENTE.
                afip_status = "PENDIENTE"
                afip_detail = "Integración WSAA+WSCDC lista para conectar (faltan llamadas SOAP)."

            out_rows.append({
                "Archivo": f.filename,
                "CAE": cae or "",
                "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                "Estado": " | ".join(estado),

                # Campos extra (útiles para WSCDC)
                "PtoVta": pto_vta or "",
                "CbteNro": cbte_nro or "",
                "FechaCbte": fecha_cbte.strftime("%d/%m/%Y") if fecha_cbte else "",
                "CUIT_en_PDF": cuit_en_pdf or "",
                "ImpTotal": imp_total if imp_total is not None else "",

                "AFIP": afip_status,
                "Detalle AFIP": afip_detail,
            })

        except Exception as e:
            out_rows.append({
                "Archivo": getattr(f, "filename", "archivo"),
                "CAE": "",
                "Vto CAE": "",
                "Estado": f"Error procesando PDF: {e}",
                "PtoVta": "",
                "CbteNro": "",
                "FechaCbte": "",
                "CUIT_en_PDF": "",
                "ImpTotal": "",
                "AFIP": "ERROR",
                "Detalle AFIP": str(e),
            })

    return {"rows": out_rows}
